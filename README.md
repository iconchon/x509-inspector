# X.509 Inspector

Aplikasi desktop minimalis untuk memeriksa file-file terkait sertifikat X.509 di Windows, macOS, dan Linux.
Ditulis dengan **Go + Wails**. Hasilnya satu binary ±10 MB yang memakai webview bawaan OS, tanpa Electron dan tanpa runtime tambahan.

Prinsip utamanya: **semua pemeriksaan bersifat non-blocking.** File yang rusak, format aneh, atau algoritma yang tidak
didukung tidak menghentikan analisis. Setiap masalah dicatat sebagai temuan (Error / Peringatan / Info / OK), lalu
aplikasi tetap menampilkan apa pun yang masih bisa dibaca, termasuk pohon ASN.1 mentah.

## Format yang didukung

| Jenis | Format |
|---|---|
| Sertifikat | PEM, DER (`.cer/.crt/.der`), bundle berisi banyak sertifikat, `TRUSTED CERTIFICATE`, Base64 tanpa header, teks hex |
| CRL | PEM / DER |
| CSR (PKCS#10) | PEM / DER |
| Kunci | PKCS#8, PKCS#1, SEC1 (EC), kunci publik SPKI/PKCS#1. Material kunci privat **tidak pernah ditampilkan** |
| PKCS#7 / CMS | `.p7b/.p7c/.p7s`, termasuk BER (panjang indefinite) |
| PKCS#12 | `.p12/.pfx`, dengan isian password di UI |
| ICAO 9303 | CSCA Master List (`.ml`), EF.SOD (`0x77`), Deviation List |

## Pemeriksaan yang dilakukan

- **Format & encoding:** PEM rusak, data sisa, BER vs DER, BOM, label PEM yang tidak sesuai isinya.
- **Struktur (RFC 5280):** versi, serial (positif, ≤20 oktet, encoding minimal), kecocokan algoritma TBS dan
  algoritma luar, unique ID.
- **Nama:** tipe string (PrintableString/UTF8/IA5), countryName 2 huruf, atribut kosong, batas panjang,
  pencocokan issuer↔subject (byte-exact dan caseless).
- **Waktu:** belum berlaku, kedaluwarsa, akan kedaluwarsa, format UTCTime/GeneralizedTime, aturan tahun 2050,
  privateKeyUsagePeriod, dan peringatan "baru berlaku < 24 jam" (masalah jam perangkat).
- **Kunci:** ukuran RSA, eksponen, modulus, validitas titik EC di kurva, kurva eksplisit vs bernama, DSA usang.
- **Tanda tangan:** verifikasi kriptografis RSA PKCS#1 v1.5, RSA-PSS, ECDSA (P-224…P-521, secp256k1,
  **Brainpool**, dan **parameter eksplisit ICAO**), Ed25519, dan DSA. Algoritma lemah (MD5/SHA-1) ditandai.
- **Ekstensi:** duplikat, critical yang tidak dikenal, kombinasi KU/EKU/basicConstraints, SKI/AKI, SAN,
  CRLDP, AIA, policies, nameConstraints, documentTypeList ICAO.
- **Rantai:** dibangun otomatis dari semua file yang dimuat. Mencakup verifikasi tanda tangan tiap mata rantai,
  CA flag, keyCertSign, pathLenConstraint, masa berlaku CA, dan deteksi loop.
- **Revokasi:** CRL lokal (tanda tangan CRL ikut diverifikasi). Lewat **Cek online** juga mengunduh CRL dari
  CRLDP, menanyakan **OCSP**, dan mengambil issuer yang hilang dari **AIA caIssuers**.
- **Trust store OS:** apakah sertifikat dipercaya Windows, macOS, atau Linux (dibatasi waktu).
- **Hostname:** pencocokan SAN DNS/IP dengan aturan wildcard.
- **Profil ICAO 9303-12:** peran CSCA / link / Document Signer / Master List Signer, keyUsage per peran,
  countryName, documentTypeList, CRLDP, issuerAltName, serta verifikasi tanda tangan CMS Master List dan SOD.
- **Profil TLS:** SAN wajib, masa berlaku ≤ 398 hari, wildcard.
- **Kompatibilitas:** memberi tahu jika parser ketat (Go `crypto/x509`, yang juga mewakili perilaku banyak
  library lain) menolak sertifikat, misalnya sertifikat dengan parameter EC eksplisit.
- **Pencocokan kunci:** kunci privat ↔ sertifikat / CSR.

Jaringan **tidak pernah** dipakai kecuali Anda menekan tombol **Cek online** atau memakai `-online` di CLI.

## Instalasi

Unduh dari halaman Release (dibuat otomatis oleh GitHub Actions):

- **Windows:** `x509-inspector-windows-amd64-setup.exe` (installer), atau versi portable `.zip`.
  Membutuhkan WebView2, yang sudah ada di Windows 10/11.
- **macOS:** `x509-inspector-macos-universal.zip` (Intel + Apple Silicon). Aplikasinya belum di-notarize, jadi
  saat pertama kali dibuka, klik kanan → *Open*.
- **Linux:** `x509-inspector-linux-amd64.tar.gz`, lalu jalankan `./install.sh` (tanpa root).
  Membutuhkan WebKitGTK 4.1 (`sudo apt install libwebkit2gtk-4.1-0`).

## Mode baris perintah

Binary yang sama juga bisa dipakai dari terminal atau CI:

```
x509-inspector check sertifikat.pem
x509-inspector check -host www.contoh.go.id -online fullchain.pem
x509-inspector check -json -fail-on error *.crt
x509-inspector check -at "2027-02-20 10:00" -profile icao ds.pem csca.pem
```

## Build dari source

Butuh Go 1.22+.

```
go test ./engine
go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1
wails build                      # Windows / macOS
wails build -tags webkit2_41     # Linux (Ubuntu 24.04+, butuh libgtk-3-dev libwebkit2gtk-4.1-dev)
```

Di Windows, build tanpa Wails CLI juga bisa:

```
go build -tags desktop,production -ldflags "-H windowsgui -s -w" -o x509-inspector.exe .
```

## Struktur

```
engine/      parser & validator (murni Go, tanpa UI) — bisa dipakai ulang
app.go       binding desktop (Wails)
cli.go       mode baris perintah
frontend/    UI HTML/CSS/JS statis (tanpa npm)
```
