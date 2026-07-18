# Menulis dan Tuning Rule Snort/Suricata untuk Deteksi Intrusi

## Kenapa Ini Penting

IDS dan IPS seperti Snort dan Suricata sering dipasang lalu dibiarkan dengan ruleset bawaan, dan di situlah letak masalahnya. Ruleset default memang titik awal yang baik, tapi ia tidak tahu apa-apa tentang lingkunganmu. Hasilnya dua ekstrem yang sama-sama buruk: banjir alert yang tidak relevan sampai analis berhenti memperhatikan, atau kebutaan terhadap ancaman spesifik yang menargetkan organisasimu.

Kemampuan yang membedakan analis yang sekadar memakai IDS dari yang benar-benar menguasainya adalah menulis rule sendiri dari sampel trafik jahat, dan men-tuning rule yang ada agar presisi. Tulisan ini membahas anatomi sebuah rule, cara menyusun signature dari trafik yang ditangkap, dan disiplin tuning yang mencegah false positive menelan tim.

---

## IDS vs IPS, dan Dua Cara Mendeteksi

Sebelum menulis rule, perlu jelas dua hal dasar.

Perbedaan IDS dan IPS sederhana tapi penting. **IDS** memantau secara pasif dan hanya menghasilkan alert, ia tidak menghentikan apa pun. **IPS** duduk inline di jalur trafik dan bisa aktif mencegah, dengan men-drop paket atau mereset koneksi. Konsekuensinya, rule untuk IPS punya taruhan lebih tinggi: false positive di IDS berarti alert palsu, sedangkan di IPS berarti trafik sah yang ikut terblokir.

Ada juga dua filosofi deteksi yang saling melengkapi:

- **Signature-based** mengenali pola buruk yang sudah dikenal. Presisi tinggi untuk ancaman yang sudah diketahui, tapi buta terhadap yang baru.
- **Anomaly-based** membangun baseline perilaku normal lalu menandai penyimpangan. Bisa menangkap zero-day, tapi rawan false positive.

Sebagian besar rule yang kita tulis bersifat signature-based, tapi rule terbaik sering memadukan unsur perilaku, seperti ambang frekuensi, untuk menekan kebisingan.

---

## Anatomi Sebuah Rule

Rule Snort dan Suricata punya struktur yang sangat mirip. Bentuk dasarnya:

```
action protocol from_ip port -> to_ip port (msg:"..."; content:"..."; sid:N; rev:N;)
```

Bagian header (sebelum kurung) menentukan **kapan rule diperiksa**:

- **action**: `alert` (beri tahu), `drop` (blokir, untuk IPS), `reject` (kirim RST), atau `pass` (abaikan).
- **protocol**: tcp, udp, icmp, atau protokol aplikasi seperti http, tls, dns.
- **arah**: `->` untuk satu arah, `<>` untuk dua arah. Biasanya memakai variabel `$HOME_NET` dan `$EXTERNAL_NET` agar rule berlaku relatif terhadap jaringanmu, bukan IP yang dipaku.

Bagian options (dalam kurung) menentukan **apa yang dicari**. Beberapa yang paling sering dipakai:

| Keyword | Fungsi |
|---------|--------|
| `msg` | Deskripsi yang muncul di alert |
| `sid` / `rev` | ID unik rule dan nomor versinya |
| `content` | Pola byte yang dicari (hex ditulis di antara tanda pipe, misalnya untuk newline) |
| `nocase` | Cocokkan tanpa peduli huruf besar-kecil |
| `flow` | Batasi pada arah atau state koneksi, misalnya `established, to_server` |
| `offset` / `depth` | Mulai memeriksa dari byte ke berapa, dan sejauh berapa byte |
| `distance` / `within` | Jarak antar beberapa pola content |
| `pcre` | Regex untuk pola yang lebih fleksibel |
| `detection_filter` | Hanya alert bila terjadi N kali dalam T detik |

Konsep penting untuk efisiensi adalah **sticky buffer**, yang membatasi pencarian ke bagian tertentu dari trafik. Alih-alih memindai seluruh paket, kita bisa fokus ke `http.uri`, `http.user_agent`, `http.cookie`, dan sejenisnya. Ini membuat rule jauh lebih cepat sekaligus lebih presisi.

---

## Menulis Signature dari Trafik Jahat

Skenario nyata seorang analis: sebuah sampel malware tertangkap, dan kita perlu membuat rule agar varian yang sama terdeteksi ke depan. Prosesnya bukan menebak, melainkan membaca trafiknya dan mengekstrak pola yang unik sekaligus stabil.

Ambil contoh mendeteksi komunikasi command and control yang masih clear text. Saat menganalisis trafik sebuah framework C2, kita mungkin melihat pola yang konsisten: request HTTP GET ke URI berakhiran tertentu, disertai cookie dengan format khas dan User-Agent yang spesifik. Rule yang baik menggabungkan beberapa penanda ini sekaligus, karena satu penanda saja mudah memicu false positive. Misalnya, mencocokkan pola URI lewat sticky buffer `http.uri`, ditambah nilai cookie lewat `http.cookie`, ditambah User-Agent lewat `http.user_agent`, sehingga ketiganya harus muncul bersamaan baru alert berbunyi.

Untuk deteksi berbasis perilaku, `detection_filter` sangat berguna. Sebuah beacon C2 mungkin mengirim response berukuran konsisten secara berkala. Rule bisa dibuat hanya berbunyi bila pola itu muncul beberapa kali dalam jendela waktu tertentu, sehingga satu kemunculan kebetulan tidak memicu alarm.

Prinsip memilih pola yang baik: cari yang **unik bagi ancaman** tapi **tidak rapuh**. Mencocokkan satu string acak yang gampang diubah penyerang menghasilkan rule yang cepat usang. Mencocokkan karakteristik struktural yang sulit diubah tanpa merombak tool menghasilkan rule yang tahan lama. Inilah inti dari Pyramid of Pain: deteksi yang menyasar perilaku lebih menyakitkan untuk dihindari daripada yang menyasar indikator yang gampang diganti.

---

## Mendeteksi Trafik Terenkripsi

Pertanyaan yang sering muncul: bagaimana menulis rule untuk trafik TLS yang isinya terenkripsi. Jawabannya, walau payload tersembunyi, ada bagian yang tetap terbuka saat handshake.

Dua sumber yang berharga:

- **Field sertifikat TLS** yang dipertukarkan saat handshake. Issuer, subject, dan terutama Common Name sering mengandung anomali. Sebuah malware yang memakai sertifikat self-signed dengan Common Name yang janggal (misalnya nama organisasi generik yang tidak masuk akal) bisa dideteksi dari sana.
- **JA3 hash**, yaitu fingerprint dari cara klien memulai handshake TLS (versi, cipher suite, dan extension yang ditawarkan). Karena tiap tool punya cara khas memulai TLS, JA3 hash sering unik per keluarga malware, dan bisa dicocokkan lewat sticky buffer khusus walau isi trafiknya tidak bisa dibaca.

Ini contoh bagus bahwa enkripsi tidak membuat IDS tidak berguna. Ia hanya memindahkan titik deteksi dari isi ke metadata handshake.

---

## Tuning: Pekerjaan yang Tidak Pernah Selesai

Menulis rule baru hanya separuh pekerjaan. Separuh lainnya, yang lebih sering diabaikan, adalah tuning agar rule presisi di lingkungan nyata. Sebuah rule yang sempurna di laboratorium bisa membanjiri produksi dengan false positive karena lingkungan asli punya trafik sah yang kebetulan mirip.

Beberapa prinsip tuning yang penting:

- **Pakai variabel jaringan dengan benar.** `HOME_NET` dan `EXTERNAL_NET` membuat rule hanya berlaku pada arah yang relevan, mengurangi pemeriksaan yang tidak perlu.
- **Tambahkan ambang dengan `detection_filter`** untuk pola yang baru bermakna pada frekuensi tertentu, sehingga kejadian tunggal yang tidak berbahaya tidak memicu alarm.
- **Persempit dengan sticky buffer dan flow.** Membatasi rule ke bagian dan arah yang tepat mengurangi salah cocok sekaligus menghemat sumber daya.
- **Validasi sebelum deploy.** Suricata punya mode test konfigurasi, dan rule sebaiknya diuji terhadap pcap yang berisi trafik jahat (harus berbunyi) dan trafik bersih (tidak boleh berbunyi).
- **Perbarui ruleset secara rutin.** Sumber seperti Emerging Threats Open menyediakan rule yang terus diperbarui, dan tool pembaruan otomatis memudahkan menjaganya tetap mutakhir.

Disiplin tuning inilah yang menentukan apakah IDS jadi aset atau jadi sumber alert fatigue. Rule yang tidak di-tuning bukan keamanan, melainkan kebisingan.

---

## Kesalahan Umum

**1. Memakai ruleset default apa adanya.** Default tidak mengenal lingkunganmu. Tanpa penyesuaian, hasilnya banjir alert atau kebutaan.

**2. Mencocokkan pola yang rapuh.** String acak yang mudah diganti penyerang menghasilkan rule yang cepat usang. Sasar karakteristik yang sulit diubah.

**3. Mengandalkan satu penanda.** Satu content saja mudah memicu false positive. Gabungkan beberapa penanda agar harus muncul bersamaan.

**4. Lupa menguji terhadap trafik bersih.** Rule yang berbunyi pada sampel jahat tapi belum diuji pada trafik normal sering jadi mesin false positive di produksi.

**5. Menulis rule lalu meninggalkannya.** Lingkungan dan ancaman berubah. Tuning dan pembaruan adalah pekerjaan berkelanjutan, bukan sekali jadi.

---

## Kartu Referensi Cepat

| Elemen | Peran |
|--------|-------|
| action | alert / drop / reject / pass |
| protocol + arah | Kapan rule diperiksa (pakai HOME_NET / EXTERNAL_NET) |
| content | Pola byte yang dicari |
| sticky buffer | Batasi ke bagian trafik (http.uri, http.user_agent, dll.) |
| flow | Batasi ke arah/state koneksi |
| detection_filter | Ambang frekuensi (N kali dalam T detik) |
| pcre | Pola fleksibel via regex |
| sid / rev | Identitas dan versi rule |
| JA3 hash / cert subject | Deteksi pada trafik TLS terenkripsi |

Pegangan akhir: IDS dan IPS hanya sebaik rule yang menjalankannya. Menulis rule yang baik berarti mengekstrak pola yang unik tapi tahan banting dari trafik jahat, dan menjaganya tetap presisi lewat tuning yang tak pernah berhenti. Rule default adalah titik awal, bukan tujuan.

---

## Referensi

- [Suricata: Rules format dan keyword](https://docs.suricata.io/en/latest/rules/intro.html)
- [Snort 3: Rule Writing Guide](https://docs.snort.org/)
- [Emerging Threats Open Ruleset](https://rules.emergingthreats.net/)
- [Salesforce: JA3 TLS fingerprinting](https://github.com/salesforce/ja3)
- [SANS: Pyramid of Pain (David Bianco)](https://www.sans.org/tools/the-pyramid-of-pain/)
