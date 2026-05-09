# Web-port-scn

Modern, hafif ve web tabanlı bir ağ keşif ve port tarama arayüzü.

Web-port-scn; klasik masaüstü ağ araçlarının karmaşıklığını azaltmayı, daha temiz bir kullanıcı deneyimi sunmayı ve ağ keşif süreçlerini modern bir web paneli üzerinden yönetilebilir hale getirmeyi amaçlayan bir projedir.

Bu proje bir “exploit framework” veya saldırı odaklı pentest aracı değildir.  

---

# ✨ Proje Amacı

Günümüzde birçok ağ aracı:

- eski arayüzlere sahip,
- masaüstüne bağımlı,
- gereksiz derecede ağır,
- yeni başlayanlar için karmaşık,
- mobil kullanım açısından yetersiz.

Web-port-scn ise daha sade ve modern bir yaklaşım benimser.

Amaç:
- hızlı çalışmak,
- anlaşılır olmak,
- modern görünmek,
- düşük kaynak tüketmek,

Bu proje özellikle:
- Linux kullanıcıları,
- Termux ,nethunter kullananlar,
- networking öğrenenler,
- kendi lokal ağını analiz etmek isteyenler,
- web tabanlı araç geliştirmeyi sevenler

için uygun bir yapı sunar.

---

# 🌐 Özellikler

## Mevcut Özellikler

- Web tabanlı kullanım
- Basit ve anlaşılır arayüz
- Port tarama sistemi
- Hedef IP girişi
- Hafif frontend yapısı
- Lokal kullanım desteği
- Gerçek zaman hissi veren çıktı sistemi
- Mobil uyumlu kullanım yaklaşımı
- Geliştirilebilir mimari

---

# 🚀 Planlanan Özellikler

## Ağ Keşfi
- subnet tarama
- ağ cihazı keşfi
- ping sweep sistemi
- TTL analizi
- gecikme ölçümü
- MAC vendor tespiti

## Port Tarama
- TCP connect scan
- asenkron tarama sistemi
- özel port aralıkları
- timeout kontrolü
- tarama profilleri
- hızlı/yavaş tarama modları

## Servis Analizi
- banner grabbing
- HTTP başlık analizi
- servis tahmini
- SSL sertifika kontrolü
- temel fingerprint sistemi

## Web Paneli
- canlı tarama çıktısı
- websocket desteği
- host kart sistemi
- responsive dashboard
- scan geçmişi
- istatistik ekranı

## Dışa Aktarma
- JSON export
- CSV export
- rapor sistemi
- scan geçmişi kaydı

---

# 🧠 Neden Web Tabanlı?

Birçok port tarama aracı doğrudan terminal odaklıdır.

Terminal araçları güçlü olsa da:
- yeni başlayanlar için karmaşık olabilir,
- mobil cihazlarda zor kullanılabilir,
- görsel açıdan yetersiz kalabilir.

Web-port-scn bu noktada daha erişilebilir bir deneyim sunmayı hedefler.

Tarayıcı tabanlı yapı sayesinde:
- telefon üzerinden kullanım mümkündür,
- kurulum daha basittir,
- arayüz geliştirilebilir,
- görselleştirme kolaylaşır.

---

# ⚙️ Teknik Yaklaşım

Proje mümkün olduğunca:
- sade,
- okunabilir,
- modüler,
- genişletilebilir

şekilde tasarlanmaktadır.

Amaç gereksiz bağımlılıklardan kaçınarak:
- hızlı açılan,
- düşük RAM kullanan,
- düşük işlemci tüketen,
- hafif bir sistem oluşturmaktır.

---

# 🖥️ Kullanım Senaryoları

## Lokal Ağ Analizi
Ev ağındaki cihazları ve açık servisleri gözlemlemek için kullanılabilir.

## Networking Öğrenme
TCP bağlantıları, port mantığı ve servis davranışlarını anlamak için faydalıdır.

## Self-hosted Sistemler
Kendi sunucularını veya lokal servislerini hızlıca kontrol etmek isteyen kullanıcılar için uygundur.

## Eğitim Amaçlı Deneyler
Ağ davranışlarını anlamak ve tarama mantığını öğrenmek için güvenli bir ortam sağlar.

---

# 🧩 Kullanılan Teknolojiler

## Frontend
- HTML
- CSS
- JavaScript

## Backend
Backend yapısı geliştirilebilir şekilde tasarlanmıştır.

Kullanılabilecek seçenekler:
- Python
- Node.js
- Go
- Rust

---

# 🏗️ Mimari Felsefesi

Bu proje tek bir temel mantık üzerine kuruludur:

> “Basit ama işlevsel.”

Web-port-scn;
karmaşık saldırı araçları yerine:
- görünürlük,
- hız,
- kullanım kolaylığı,
- modern arayüz,
- öğrenilebilirlik

üzerine odaklanır.

Kod yapısında:
- okunabilirlik,
- düzen,
- modülerlik

ön planda tutulur.

---

# 📈 Performans Hedefleri

Proje hedef olarak:
- düşük kaynak tüketimi,
- hızlı yanıt süresi,
- düşük bağımlılık,
- mobil uyumluluk,
- Linux/Termux desteği

üzerine yoğunlaşmaktadır.

Özellikle düşük donanımlı cihazlarda çalışabilecek hafiflik korunmaya çalışılır.

---

# 📦 Kurulum

## Repoyu Klonla

```bash
git clone https://github.com/szrkalitr/Web-port-scn.git
cd Web-port-scn
python nmap_backend.py
