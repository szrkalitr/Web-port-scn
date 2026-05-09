#!/usr/bin/env python3
"""
NmapGUI Pro - Gerçek Nmap Tabanlı Web Arayüzü
Hiçbir simülasyon yok - tüm veriler gerçek nmap çıktısından gelir.
Eğitim ve yetkili testler içindir.

Kurulum:
    pip install flask flask-cors python-libnmap
    Termux: pkg install nmap && pip install flask flask-cors python-libnmap
    Linux:  sudo apt install nmap && pip install flask flask-cors python-libnmap
    macOS:  brew install nmap && pip install flask flask-cors python-libnmap
"""

import subprocess
import threading
import json
import time
import shutil
import os
import socket
import platform
import re
import tempfile
from datetime import datetime
from queue import Queue, Empty

try:
    from flask import Flask, jsonify, request, Response, stream_with_context
    from flask_cors import CORS
except ImportError:
    print("[!] pip install flask flask-cors")
    exit(1)

app = Flask(__name__)
CORS(app)

# ── Nmap varlık kontrolü ───────────────────────────────────────────────────
NMAP_PATH = shutil.which("nmap")

def check_nmap():
    if not NMAP_PATH:
        return False, "nmap bulunamadı. Kurun: pkg install nmap (Termux) / apt install nmap (Linux)"
    try:
        r = subprocess.run([NMAP_PATH, "--version"], capture_output=True, text=True, timeout=5)
        ver = r.stdout.strip().split("\n")[0] if r.stdout else "?"
        return True, ver
    except Exception as e:
        return False, str(e)

NMAP_OK, NMAP_VER = check_nmap()

# ── Aktif işler ────────────────────────────────────────────────────────────
jobs: dict = {}   # job_id -> job_dict

# ── Profiller ──────────────────────────────────────────────────────────────
PROFILES = {
    "quick":       {"label": "Hızlı Tarama",        "args": ["-T4", "-F"]},
    "standard":    {"label": "Standart",             "args": ["-T4", "-sV", "-sC", "--open"]},
    "intense":     {"label": "Yoğun",                "args": ["-T4", "-A", "-v"]},
    "intense_udp": {"label": "Yoğun + UDP",          "args": ["-sS", "-sU", "-T4", "-A", "-v"]},
    "ping":        {"label": "Ping Tarama",          "args": ["-sn"]},
    "vuln":        {"label": "Zafiyet Tarama",       "args": ["-T4", "--script=vuln"]},
    "os":          {"label": "OS Tespiti",           "args": ["-O", "-T4"]},
    "version":     {"label": "Versiyon Tespiti",     "args": ["-sV", "-T4"]},
    "aggressive":  {"label": "Agresif (root gerek)", "args": ["-T4", "-A", "-sS", "-v"]},
    "stealth":     {"label": "Gizli SYN (root)",     "args": ["-sS", "-T2", "-f"]},
    "full":        {"label": "Tüm Portlar",          "args": ["-p-", "-T4", "-sV"]},
    "scripts":     {"label": "NSE Script Paketi",    "args": ["-T4", "--script=default,safe"]},
    "manual":      {"label": "Manuel Komut",         "args": []},  # kullanıcı girer
}

# ── Yardımcılar ────────────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except:
        return "127.0.0.1"

def parse_nmap_xml(xml_path: str) -> dict:
    """nmap -oX çıktısını parse et - python-libnmap ile."""
    result = {"hosts": [], "stats": {}}
    try:
        from libnmap.parser import NmapParser
        report = NmapParser.parse_fromfile(xml_path)
        result["stats"] = {
            "start": report.started,
            "elapsed": report.elapsed,
            "hosts_total": report.hosts_total,
            "hosts_up": report.hosts_up,
            "hosts_down": report.hosts_down,
            "command": report.commandline,
            "version": report.version,
            "summary": report.summary,
        }
        for host in report.hosts:
            h = {
                "ip": host.address,
                "hostname": host.hostnames[0] if host.hostnames else "",
                "status": host.status,
                "os_matches": [],
                "ports": [],
                "scripts": {},
                "traceroute": [],
                "uptime": "",
                "mac": "",
                "vendor": "",
            }
            # OS
            if host.os_match_probabilities():
                for om in host.os_match_probabilities()[:3]:
                    h["os_matches"].append({
                        "name": om.name,
                        "accuracy": om.accuracy,
                    })
            # MAC
            try:
                if hasattr(host, '_extras') and host._extras:
                    h["mac"] = host._extras.get("mac", "")
                    h["vendor"] = host._extras.get("vendor", "")
            except:
                pass
            # Yalnızca "up" olan hostları ekle — down hostlar gereksiz karmaşa yaratır
            if host.status != "up":
                continue
            # Portlar
            for svc in host.services:
                p = {
                    "port": svc.port,
                    "proto": svc.protocol,
                    "state": svc.state,
                    "service": svc.service,
                    "product": svc.product,
                    "version": svc.version,
                    "extrainfo": svc.extrainfo,
                    "cpe": svc.cpelist if hasattr(svc,'cpelist') else [],
                    "scripts": {},
                    "reason": svc.reason if hasattr(svc,'reason') else "",
                }
                # Script çıktıları
                try:
                    if svc.scripts_results:
                        for sc in svc.scripts_results:
                            p["scripts"][sc["id"]] = sc["output"]
                except:
                    pass
                h["ports"].append(p)
            # Host scriptleri
            try:
                if host.scripts_results:
                    for sc in host.scripts_results:
                        h["scripts"][sc["id"]] = sc["output"]
            except:
                pass
            # Traceroute
            try:
                if hasattr(host, '_extras'):
                    tr = host._extras.get("traceroute", [])
                    h["traceroute"] = tr
            except:
                pass
            result["hosts"].append(h)
    except ImportError:
        # libnmap yoksa regex ile basit parse
        result = _parse_nmap_xml_regex(xml_path)
    except Exception as e:
        result["parse_error"] = str(e)
    return result

def _parse_nmap_xml_regex(xml_path: str) -> dict:
    """libnmap yoksa basit XML regex parse."""
    result = {"hosts": [], "stats": {}, "note": "libnmap yok, basit parse kullanıldı"}
    try:
        with open(xml_path, "r", errors="replace") as f:
            content = f.read()
        # hosts
        host_blocks = re.findall(r'<host[\s\S]*?</host>', content)
        for block in host_blocks:
            ip_m = re.search(r'<address addr="([^"]+)" addrtype="ipv4"', block)
            stat_m = re.search(r'<status state="([^"]+)"', block)
            if not ip_m: continue
            status = stat_m.group(1) if stat_m else "up"
            # Down hostları atla
            if status != "up":
                continue
            h = {
                "ip": ip_m.group(1),
                "hostname": "",
                "status": status,
                "os_matches": [], "ports": [], "scripts": {},
                "traceroute": [], "uptime": "", "mac": "", "vendor": "",
            }
            hn_m = re.search(r'<hostname name="([^"]+)"', block)
            if hn_m: h["hostname"] = hn_m.group(1)
            mac_m = re.search(r'<address addr="([^"]+)" addrtype="mac"', block)
            if mac_m: h["mac"] = mac_m.group(1)
            vendor_m = re.search(r'addrtype="mac"[^/]* vendor="([^"]+)"', block)
            if vendor_m: h["vendor"] = vendor_m.group(1)
            # Ports
            port_blocks = re.findall(r'<port[\s\S]*?</port>', block)
            for pb in port_blocks:
                pm = re.search(r'<port protocol="([^"]+)" portid="([^"]+)"', pb)
                sm = re.search(r'<state state="([^"]+)"', pb)
                svm = re.search(r'<service name="([^"]*)"[^>]*product="([^"]*)"[^>]*version="([^"]*)"', pb)
                if pm:
                    port_d = {
                        "port": int(pm.group(2)),
                        "proto": pm.group(1),
                        "state": sm.group(1) if sm else "?",
                        "service": svm.group(1) if svm else "",
                        "product": svm.group(2) if svm else "",
                        "version": svm.group(3) if svm else "",
                        "extrainfo": "", "cpe": [], "scripts": {}, "reason": "",
                    }
                    sc_blocks = re.findall(r'<script id="([^"]+)" output="([^"]*)"', pb)
                    for sc_id, sc_out in sc_blocks:
                        port_d["scripts"][sc_id] = sc_out
                    h["ports"].append(port_d)
            # OS
            os_ms = re.findall(r'<osmatch name="([^"]+)" accuracy="([^"]+)"', block)
            for om_name, om_acc in os_ms[:3]:
                h["os_matches"].append({"name": om_name, "accuracy": int(om_acc)})
            result["hosts"].append(h)
        # Stats
        sum_m = re.search(r'<runstats>[\s\S]*?<finished[^>]*elapsed="([^"]+)"[\s\S]*?summary="([^"]+)"', content)
        if sum_m:
            result["stats"]["elapsed"] = sum_m.group(1)
            result["stats"]["summary"] = sum_m.group(2)
        cmd_m = re.search(r'args="([^"]+)"', content)
        if cmd_m: result["stats"]["command"] = cmd_m.group(1)
    except Exception as e:
        result["parse_error"] = str(e)
    return result

# ── Tarama çalıştırıcı ─────────────────────────────────────────────────────
def run_nmap_job(job_id: str, cmd: list, xml_path: str):
    job = jobs[job_id]
    job["status"] = "running"
    job["start_time"] = datetime.now().isoformat()
    job["cmd_str"] = " ".join(cmd)
    job["output_lines"] = []
    job["result"] = None
    job["error"] = None
    job["returncode"] = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        job["pid"] = proc.pid

        for line in proc.stdout:
            line = line.rstrip()
            job["output_lines"].append(line)
            # İlerleme bilgisi çıkar
            if "%" in line:
                m = re.search(r'(\d+\.\d+)%', line)
                if m:
                    job["progress"] = float(m.group(1))

        proc.wait()
        job["returncode"] = proc.returncode

        # XML parse
        if os.path.exists(xml_path):
            job["result"] = parse_nmap_xml(xml_path)
            try: os.remove(xml_path)
            except: pass

        job["status"] = "done" if proc.returncode == 0 else "error"
        if proc.returncode != 0:
            job["error"] = f"nmap çıkış kodu: {proc.returncode}"

    except FileNotFoundError:
        job["status"] = "error"
        job["error"] = "nmap bulunamadı. Lütfen kurun."
    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
    finally:
        job["end_time"] = datetime.now().isoformat()

# ── API ────────────────────────────────────────────────────────────────────
@app.route("/api/info")
def api_info():
    return jsonify({
        "nmap_ok": NMAP_OK,
        "nmap_version": NMAP_VER,
        "nmap_path": NMAP_PATH,
        "local_ip": get_local_ip(),
        "hostname": socket.gethostname(),
        "platform": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
        "profiles": {k: v["label"] for k,v in PROFILES.items()},
    })

@app.route("/api/scan/start", methods=["POST"])
def api_start():
    if not NMAP_OK:
        return jsonify({"error": "nmap kurulu değil: " + NMAP_VER}), 503

    data = request.json or {}
    target   = data.get("target", "").strip()
    profile  = data.get("profile", "standard")
    manual   = data.get("manual_args", "").strip()   # manuel mod
    extra    = data.get("extra_args", "").strip()     # ek argümanlar

    if not target:
        return jsonify({"error": "target gerekli"}), 400

    job_id   = f"job_{int(time.time()*1000)}"
    xml_dir  = tempfile.gettempdir()                          # Termux dahil her ortamda doğru tmp dizini
    xml_path = os.path.join(xml_dir, f"nmap_{job_id}.xml")

    # Komut oluştur
    if profile == "manual" and manual:
        # Kullanıcının tam komutu — nmap + hedef + xml
        # Güvenlik: sadece nmap komutuna izin ver, shell injection engelle
        parts = manual.split()
        # nmap kelimesini başa koy/zorla
        if parts[0].lower() == "nmap":
            parts = parts[1:]
        cmd = [NMAP_PATH] + parts + [target, "-oX", xml_path, "-v"]
    else:
        profile_args = PROFILES.get(profile, PROFILES["standard"])["args"]
        extra_parts = extra.split() if extra else []
        cmd = [NMAP_PATH] + profile_args + extra_parts + [target, "-oX", xml_path, "-v"]

    jobs[job_id] = {
        "id": job_id,
        "target": target,
        "profile": profile,
        "status": "init",
        "progress": 0.0,
        "output_lines": [],
        "result": None,
        "error": None,
        "pid": None,
        "cmd_str": "",
        "start_time": None,
        "end_time": None,
        "returncode": None,
    }

    t = threading.Thread(target=run_nmap_job, args=(job_id, cmd, xml_path), daemon=True)
    t.start()
    return jsonify({"job_id": job_id})

@app.route("/api/scan/<job_id>")
def api_job(job_id):
    if job_id not in jobs:
        return jsonify({"error": "job bulunamadı"}), 404
    return jsonify(jobs[job_id])

@app.route("/api/scan/<job_id>/output")
def api_output(job_id):
    """SSE stream — gerçek zamanlı nmap çıktısı."""
    if job_id not in jobs:
        return jsonify({"error": "job bulunamadı"}), 404

    def generate():
        seen = 0
        while True:
            job = jobs.get(job_id)
            if not job: break
            lines = job.get("output_lines", [])
            for line in lines[seen:]:
                yield f"data: {json.dumps({'line': line})}\n\n"
                seen = len(lines)
            if job["status"] in ("done","error"):
                yield f"data: {json.dumps({'done': True, 'status': job['status']})}\n\n"
                break
            time.sleep(0.2)

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/scan/<job_id>/stop", methods=["POST"])
def api_stop(job_id):
    if job_id not in jobs:
        return jsonify({"error": "job bulunamadı"}), 404
    import signal as sig
    pid = jobs[job_id].get("pid")
    if pid:
        try:
            os.kill(pid, sig.SIGTERM)
            jobs[job_id]["status"] = "stopped"
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})

@app.route("/api/jobs")
def api_jobs():
    return jsonify([{
        "id": j["id"], "target": j["target"],
        "profile": j["profile"], "status": j["status"],
        "start_time": j.get("start_time",""),
        "open_ports": len([p for h in (j.get("result") or {}).get("hosts",[])
                           for p in h.get("ports",[]) if p["state"]=="open"]),
    } for j in jobs.values()])

@app.route("/api/nmap/scripts")
def api_scripts():
    """Mevcut NSE scriptleri listele."""
    scripts = []
    script_dirs = [
        "/usr/share/nmap/scripts",
        "/usr/local/share/nmap/scripts",
        "/data/data/com.termux/files/usr/share/nmap/scripts",
    ]
    for d in script_dirs:
        if os.path.isdir(d):
            scripts = [f[:-4] for f in os.listdir(d) if f.endswith(".nse")]
            break
    return jsonify({"scripts": sorted(scripts), "count": len(scripts)})

@app.route("/api/resolve", methods=["POST"])
def api_resolve():
    host = (request.json or {}).get("host","")
    try:
        ip = socket.gethostbyname(host)
        try: rdns = socket.gethostbyaddr(ip)[0]
        except: rdns = ""
        return jsonify({"ip": ip, "rdns": rdns})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/")
def index():
    gui = os.path.join(os.path.dirname(__file__), "nmap_gui.html")
    if os.path.exists(gui):
        with open(gui, "r", encoding="utf-8") as f:
            return f.read()
    return "<h2>nmap_gui.html bulunamadı. İki dosyayı aynı klasöre koyun.</h2>", 404

if __name__ == "__main__":
    print("=" * 60)
    print("  NmapGUI Pro — Gerçek Nmap Web Arayüzü")
    print("  Eğitim ve Yetkili Testler İçindir")
    print("=" * 60)
    nmap_ok, nmap_ver = check_nmap()
    if nmap_ok:
        print(f"  ✓ {nmap_ver}")
    else:
        print(f"  ✗ NMAP BULUNAMADI: {nmap_ver}")
        print("    Termux: pkg install nmap")
        print("    Linux:  sudo apt install nmap")
    print(f"\n  Web arayüzü: http://localhost:5000")
    print(f"  Ağdan:       http://{get_local_ip()}:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
