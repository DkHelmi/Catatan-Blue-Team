# Deobfuscation JavaScript Berbahaya: Membongkar Kode yang Disembunyikan

## Kenapa Ini Penting

JavaScript adalah salah satu kendaraan serangan paling umum yang dihadapi analis, dari payload phishing, skimmer di halaman pembayaran, sampai dropper yang mengunduh malware tahap berikutnya. Dan hampir selalu, kode jahat itu di-obfuscate: sengaja dibuat tidak terbaca agar lolos dari deteksi dan menyembunyikan niatnya. Sebuah skrip yang isinya hanya deretan `_0x` dan string base64 panjang dirancang persis untuk membuat analis menyerah.

Kabar baiknya, obfuscation bukan enkripsi. Kode itu harus tetap bisa dijalankan browser, jadi pada akhirnya ia selalu bisa dibongkar kembali. Tulisan ini membahas teknik obfuscation yang umum dan cara mendeobfuscate-nya secara bertahap, sehingga sebuah skrip yang tampak mustahil dibaca bisa diurai sampai niat aslinya terlihat jelas.

---

## Kenapa JavaScript Sering Di-obfuscate

JavaScript punya sifat yang membuatnya istimewa dibanding bahasa server-side seperti PHP atau Python: ia berjalan di sisi klien dan dikirim ke browser dalam bentuk teks. Artinya, siapa pun bisa melihat kodenya cukup dengan membuka source halaman. Inilah yang mendorong obfuscation, dengan beberapa motif:

- **Menyembunyikan fungsi** agar sulit ditiru atau di-reverse engineer.
- **Sebagai lapisan keamanan** (walau menaruh logika auth atau enkripsi di sisi klien justru praktik yang lemah).
- Yang paling relevan bagi analis: **menyembunyikan niat jahat** agar lolos dari IDS, filter, dan mata manusia.

Karena obfuscation harus tetap menghasilkan kode yang bisa dieksekusi, ia selalu reversibel. Tugas analis adalah membalikkan prosesnya.

---

## Langkah Awal: Selalu Baca Source

Sebelum menyentuh obfuscation apa pun, langkah paling dasar dan paling sering membuahkan hasil adalah membaca source halaman. Di browser ini dilakukan dengan melihat view-source, dan dari command line dengan mengambil HTML mentah lewat curl.

Yang dicari: tag `<script>` (inline maupun eksternal lewat atribut `src`), dan yang sering terlupakan, komentar HTML. Komentar sering menyimpan informasi sensitif yang ditinggalkan developer, dari kredensial sampai petunjuk endpoint. Membaca source dan komentar adalah kebiasaan murah yang berkali-kali menghemat waktu.

---

## Spektrum Obfuscation

Memahami tingkatan obfuscation membantu mengenali apa yang dihadapi dan memilih cara membongkarnya.

- **Minify.** Kode dipadatkan menjadi satu baris panjang tanpa spasi, biasanya berekstensi `.min.js`. Ini bukan obfuscation sejati, hanya membuat tidak nyaman dibaca. Mudah dibalik dengan beautify.
- **Packing.** Kode dibungkus packer dengan ciri khas berupa fungsi berargumen `p,a,c,k,e,d` yang diakhiri `eval`. Packer mengubah kata dan simbol menjadi kamus, lalu merekonstruksinya saat dijalankan. Kelemahannya bagi penyerang: string utama sering masih terlihat dalam array kamus, sehingga sebagian fungsi sudah bisa ditebak.
- **Obfuscation lanjutan.** Tool modern bisa meng-encode string menjadi base64 dan mengganti nama variabel menjadi pola tak bermakna, sehingga tidak ada string asli yang tersisa di permukaan. Ada juga teknik ekstrem seperti JSFuck yang menulis seluruh kode hanya dengan beberapa karakter simbol. Ini sengaja dibuat sangat lambat dan biasanya hanya dipakai untuk membypass filter tertentu.

---

## Membongkar Secara Bertahap

Proses deobfuscation berjalan dari yang ringan ke yang berat.

**Beautify dulu.** Kode minified diformat ulang agar terbaca, baik lewat fitur pretty print di developer tools browser maupun tool online. Untuk kode yang sekadar minified, langkah ini sudah cukup.

**Unpack jika di-pack.** Beautify saja tidak membongkar packing. Untuk kode dengan pola packer, tool unpacker khusus mengembalikannya ke bentuk asli. Ada juga trik manual yang elegan: mengganti `eval` di akhir packer dengan `console.log`, sehingga alih-alih menjalankan kode tersembunyi, browser justru mencetaknya untuk kita baca. Prinsip ini penting, jangan jalankan kode jahat untuk membongkarnya, buat ia mencetak dirinya.

**Decode encoding.** Setelah struktur terbuka, string yang ter-encode tinggal didekode. Mengenali jenis encoding dari karakteristiknya membantu: base64 memakai huruf, angka, plus karakter tertentu dan kadang padding; hex hanya 0 sampai f; base32 memakai huruf A sampai Z dan angka 2 sampai 7. Tool seperti CyberChef bisa mendeteksi dan mendekode otomatis, dan ada padanan command line untuk masing-masing. Ingat, encoding bukan enkripsi, tidak ada kunci, jadi selalu bisa dibalik.

**Reverse manual untuk yang berat.** Untuk obfuscation kustom yang membuat tool otomatis gagal, tidak ada jalan pintas selain membaca dan memahami logikanya langkah demi langkah.

---

## Membaca Niat: Analisis Kode

Setelah kode terbaca, langkah terakhir adalah memahami apa yang dilakukannya. Beberapa pola yang sering muncul di JavaScript jahat:

- Objek seperti `XMLHttpRequest` yang dipadukan dengan `open` dan `send` menandakan kode mengirim permintaan web. Endpoint relatif menunjukkan tujuan di domain yang sama, sementara URL eksternal mengarah ke server penyerang.
- Fungsi yang mengumpulkan data form atau cookie lalu mengirimnya ke domain asing adalah ciri skimmer atau pencuri sesi.
- Kode yang membangun lalu mengeksekusi string secara dinamis sering menyembunyikan tahap berikutnya dari sebuah serangan.

Dengan membaca kode yang sudah terdeobfuscate baris per baris, niat yang tadinya tersembunyi di balik kekacauan simbol menjadi jelas, dan dari sana kita bisa mengekstrak IOC seperti domain tujuan dan endpoint.

---

## Catatan Keamanan Saat Menganalisis

Karena yang dianalisis adalah kode jahat, ada disiplin yang perlu dijaga. Jangan menjalankan skrip yang dicurigai di browser atau mesin produksi. Untuk membongkar, gunakan teknik yang membuat kode mencetak dirinya (mengganti eval dengan console.log) alih-alih mengeksekusinya, atau lakukan di lingkungan terisolasi. Untuk mereplikasi permintaan web yang dilakukan skrip tanpa menjalankan skrip itu sendiri, tool seperti curl memungkinkan kita memanggil endpoint secara terkendali dan mengamati responsnya.

---

## Kesalahan Umum

**1. Menyerah melihat kode yang berantakan.** Obfuscation dirancang untuk membuat menyerah. Tapi ia selalu reversibel karena harus tetap bisa dijalankan.

**2. Menjalankan kode untuk membongkarnya.** Jangan eksekusi kode jahat. Buat ia mencetak dirinya dengan mengganti eval menjadi console.log, atau kerjakan di lingkungan terisolasi.

**3. Melewatkan source dan komentar HTML.** Petunjuk paling berharga sering ada di tempat paling sederhana.

**4. Mengira encoding sama dengan enkripsi.** Base64, hex, dan base32 tidak punya kunci dan selalu bisa dibalik. Jangan terintimidasi olehnya.

**5. Berhenti di kode terbaca, tidak sampai niat.** Tujuan akhirnya bukan membuat kode rapi, tapi memahami apa yang dilakukannya dan mengekstrak IOC.

---

## Kartu Referensi Cepat

| Tahap | Yang dilakukan | Cara |
|-------|----------------|------|
| Lihat source | Temukan script dan komentar | view-source, curl |
| Beautify | Rapikan minified | pretty print, beautifier online |
| Unpack | Bongkar packer (p,a,c,k,e,d + eval) | unpacker, ganti eval jadi console.log |
| Decode | Balikkan encoding | CyberChef, base64/xxd/base32 |
| Analisis | Pahami niat, ekstrak IOC | baca XMLHttpRequest, endpoint, domain |
| Replikasi aman | Panggil endpoint tanpa jalankan skrip | curl |

Pegangan akhir: obfuscation JavaScript dirancang untuk mengintimidasi, tapi ia bukan tembok. Bongkar bertahap dari beautify, unpack, lalu decode, selalu dengan membuat kode mencetak dirinya alih-alih dijalankan. Di ujungnya, niat yang disembunyikan selalu bisa dibaca, dan itulah yang menghasilkan IOC untuk melindungi pengguna.

---

## Referensi

- [MDN: XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest)
- [GCHQ: CyberChef](https://gchq.github.io/CyberChef/)
- [MITRE ATT&CK: Obfuscated Files or Information (T1027)](https://attack.mitre.org/techniques/T1027/)
- [MITRE ATT&CK: Command and Scripting Interpreter: JavaScript (T1059.007)](https://attack.mitre.org/techniques/T1059/007/)
- [OWASP: Testing for Client-side resource manipulation](https://owasp.org/www-project-web-security-testing-guide/)
