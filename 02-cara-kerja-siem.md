# Cara Kerja SIEM: Dari Pengumpulan Log sampai Korelasi Alert

## Kenapa Ini Penting

Ada satu salah paham yang mahal soal SIEM, yaitu menganggapnya kotak ajaib. Manajemen membeli lisensi, log dialirkan masuk, dan diasumsikan ancaman akan otomatis tertangkap. Kenyataannya berbeda jauh. SIEM yang baru dipasang dan dibiarkan apa adanya justru memuntahkan ribuan alert per jam yang mayoritas tidak berguna, sampai analis berhenti mempercayainya. Nilai SIEM bukan terletak pada produk yang dibeli, melainkan pada seberapa baik log disiapkan, dinormalisasi, dan dikorelasikan menjadi sesuatu yang bisa ditindaklanjuti.

Tulisan ini membongkar cara kerja SIEM dari dalam: bagaimana log masuk, kenapa normalisasi menentukan segalanya, bagaimana correlation rule mengubah ribuan baris log menjadi satu alert, dan kenapa alert palsu (false positive) itu hampir tidak terhindarkan tanpa tuning. Tujuannya supaya kamu memperlakukan SIEM sebagai sistem yang harus dirawat, bukan layanan sekali pasang.

---

## Apa Sebenarnya SIEM Itu

SIEM adalah singkatan dari Security Information and Event Management. Istilahnya lahir dari analis Gartner pada 2005, dan secara konsep ia menggabungkan dua teknologi yang sebelumnya terpisah:

- **SIM (Security Information Management)** yang fokus pada pengumpulan, penyimpanan jangka panjang, dan pelaporan log.
- **SEM (Security Event Management)** yang fokus pada korelasi dan notifikasi event keamanan secara real-time.

Gabungan keduanya menghasilkan satu sistem yang bisa mengumpulkan log dari banyak sumber, menyimpannya, lalu menganalisis dan mengkorelasikannya untuk memunculkan ancaman. Memahami asal-usul ini penting karena menjelaskan kenapa SIEM punya dua kepribadian: di satu sisi gudang log untuk audit dan investigasi, di sisi lain mesin deteksi real-time.

Pertanyaan yang sering muncul: kalau firewall, IDS, dan EDR sudah punya log sendiri, kenapa butuh SIEM? Jawabannya ada pada **korelasi lintas sumber**. Satu IDS hanya melihat trafik jaringan, satu EDR hanya melihat satu endpoint. Tidak ada satu pun dari mereka yang bisa menghubungkan "login gagal berulang di Active Directory" dengan "koneksi keluar mencurigakan dari endpoint yang sama" dengan "akses ke file share sensitif lima menit kemudian". SIEM-lah yang menyatukan potongan-potongan itu. Inilah pembeda utamanya dari IDS atau IPS: bukan sekadar mendeteksi satu peristiwa, tapi menunjuk peristiwa berisiko tinggi dari korelasi banyak sumber. SIEM melengkapi perangkat keamanan lain, bukan menggantikannya.

---

## Tiga Tahap Aliran Data di Dalam SIEM

Apa pun produknya (Splunk, Elastic, Sentinel, QRadar, dan lainnya), aliran datanya selalu melewati tiga tahap yang sama. Memahami ketiganya adalah kunci untuk tahu di mana sesuatu bisa rusak.

### Tahap 1: Ingestion (Pengumpulan Log)

Di tahap ini SIEM menelan log dari sumbernya. Sumbernya bisa sangat beragam: Windows Event Log, Sysmon, firewall, web server, autentikasi VPN, log cloud, sampai aplikasi internal. Cara pengumpulannya umumnya lewat:

- **Agen ringan** yang dipasang di tiap host, sering disebut shipper. Di ekosistem Elastic ini namanya Beats (Winlogbeat untuk Windows Event Log, Filebeat untuk file log). Splunk punya Universal Forwarder, dan seterusnya.
- **Syslog** untuk perangkat jaringan dan appliance.
- **API atau konektor** untuk sumber cloud.

Di sinilah letak kebenaran yang sering diabaikan: **SIEM hanya sebaik log yang masuk ke dalamnya.** Kalau Command Line Logging di Windows tidak diaktifkan, kalau Sysmon tidak terpasang, atau kalau log autentikasi VPN tidak dikirim, maka seluruh kecanggihan correlation engine tidak ada gunanya untuk skenario itu. Kelengkapan dan kualitas sumber log adalah fondasi yang menentukan seluruh kemampuan deteksi.

### Tahap 2: Normalization & Aggregation (Penyeragaman)

Log mentah dari sumber berbeda punya format berbeda. Firewall menulis IP penyerang di field bernama `src_ip`, Windows menyebutnya `IpAddress`, web server menaruhnya di posisi tertentu pada baris teks. Kalau dibiarkan apa adanya, mustahil membuat satu query yang mencari "semua aktivitas dari IP X" lintas sumber.

**Normalisasi** menyelesaikan ini dengan memetakan semua field yang artinya sama ke satu nama field standar. Di Elastic, skema standar itu disebut **ECS (Elastic Common Schema)**, misalnya semua alamat IP sumber dipetakan ke `source.ip` tidak peduli dari perangkat mana asalnya. Inilah yang membuat korelasi lintas sumber menjadi mungkin.

Sebagai gambaran konkret betapa beragamnya penamaan field di satu sumber saja (Windows lewat Elastic), perhatikan bahwa kode event bisa muncul sebagai `event.code` (versi ECS) sekaligus `winlog.event_id` (versi Winlogbeat). Tanpa skema yang disepakati, analis akan menghabiskan waktu menebak nama field alih-alih berburu ancaman.

Proses ini biasanya dikerjakan oleh komponen pengolah seperti Logstash di Elastic, yang bekerja di tiga area: menerima input, mentransformasi dan memperkaya data (parsing, menambah konteks seperti geolokasi IP), lalu mengirim hasilnya ke penyimpanan. Parsing yang buruk di tahap ini adalah penyebab umum kenapa sebuah field "kosong" atau salah saat dipakai di rule, padahal datanya sebenarnya ada di log mentah.

### Tahap 3: Detection & Analysis (Korelasi dan Deteksi)

Ini tahap tempat data yang sudah rapi diubah menjadi nilai keamanan. Di sinilah tim SOC membuat detection rule, dashboard, visualisasi, dan alert. Inti dari tahap ini adalah **correlation rule**.

Konsepnya paling mudah dipahami lewat contoh. Misalkan ada user yang gagal login sepuluh kali berturut-turut dalam empat menit. Setiap kegagalan adalah satu event terpisah di log. Tanpa SIEM, sepuluh baris itu hanyalah noise. Correlation rule mengubahnya: ia menghitung kegagalan per user dalam jendela waktu tertentu, dan kalau melewati ambang (misalnya sepuluh dalam empat menit), kesepuluh event dikondensasi menjadi **satu alert** berlabel "kemungkinan brute force". Logikanya kira-kira seperti ini:

```
event 4625 (gagal login)
| kelompokkan berdasarkan user.name dan source.ip
| hitung dalam jendela 4 menit
| picu alert jika jumlah >= 10
```

Korelasi yang lebih canggih menggabungkan event dari sumber berbeda. Contohnya: brute force berhasil (banyak 4625 lalu satu 4624 dari IP yang sama), diikuti akses ke admin share, diikuti koneksi keluar ke IP yang reputasinya buruk. Masing-masing sendirian mungkin tidak menarik, tapi rangkaiannya menceritakan sebuah serangan.

---

## Kenapa Alert Bisa Salah (dan Kenapa Itu Wajar)

Inilah bagian yang membedakan SIEM yang berguna dari SIEM yang diabaikan. Sebuah correlation rule pada dasarnya adalah tebakan terstruktur, dan tebakan bisa meleset ke dua arah.

**False positive** adalah alert yang berbunyi padahal tidak ada serangan. Contoh klasik: rule brute force yang berbunyi setiap Senin pagi karena banyak karyawan salah ketik password setelah akhir pekan. Atau rule yang menandai sebuah binary sistem sebagai mencurigakan padahal seorang developer memang rutin memakainya. False positive yang dibiarkan menumpuk melahirkan **alert fatigue**, kondisi saat analis begitu sering melihat alarm palsu sampai mereka mulai mengabaikan semuanya, termasuk yang asli. Inilah cara sebuah insiden nyata lolos di lingkungan yang sebenarnya punya deteksi.

**False negative** kebalikannya: serangan terjadi tapi tidak ada alert. Penyebabnya bisa rule yang ambangnya terlalu tinggi, log sumber yang tidak masuk, atau teknik penyerang yang memang belum tercakup rule mana pun.

Cara menekan keduanya adalah dua hal yang harus dilakukan terus-menerus:

1. **Kontekstualisasi.** Alert mentah tanpa konteks hampir tidak berguna. Lima login gagal dari akun intern berbeda artinya dengan lima login gagal dari akun administrator domain. SIEM yang matang memperkaya alert dengan konteks: siapa aktornya, seberapa kritis aset yang terlibat, kapan terjadi, dan apakah polanya cocok dengan baseline normal. Kontekstualisasi inilah yang menentukan prioritas, bukan sekadar fakta bahwa sebuah rule terpicu.

2. **Tuning dan whitelisting.** Rule perlu dikalibrasi berdasarkan kondisi nyata lingkungan. Mengecualikan akun layanan yang memang sah, menyesuaikan ambang, dan menambah filter adalah pekerjaan rutin, bukan sekali jadi. Lingkungan berubah, jadi rule pun harus ikut dirawat.

Pegangannya sederhana: SIEM tanpa tuning bukan SIEM yang aman, melainkan SIEM yang berisik.

---

## Mengubah Ide Menjadi Deteksi: Use Case Development

Cara terstruktur untuk membangun deteksi disebut pengembangan use case. Use case adalah skenario konkret yang ingin dideteksi, dari yang sederhana (login gagal berkali-kali) sampai yang kompleks (pola penyebaran ransomware). Alur pengembangannya kira-kira:

1. **Requirements.** Tentukan apa yang mau dideteksi dan dalam kondisi apa alert harus berbunyi. Contoh: sepuluh kegagalan login dalam empat menit.
2. **Data Points.** Identifikasi semua tempat di jaringan yang relevan. Untuk deteksi login, itu berarti semua titik autentikasi: Windows, Linux, VPN, aplikasi web.
3. **Log Validation.** Pastikan log dari semua titik itu benar-benar masuk dan memuat detail penting (user, waktu, sumber, tujuan). Tahap ini sering terlewat dan jadi penyebab rule yang "tidak pernah berbunyi".
4. **Design & Implementation.** Definisikan rule lewat tiga parameter inti: **Condition** (kondisi pemicu), **Aggregation** (pengelompokan untuk menekan false positive), dan **Priority** (severity berdasarkan dampak).
5. **Documentation (SOP).** Buat prosedur baku penanganan alert, termasuk ke mana harus dieskalasi.
6. **Onboarding.** Uji rule di lingkungan development dulu, tutup celah false positive, baru naikkan ke produksi.
7. **Fine-tuning berkala.** Ambil umpan balik dari analis dan terus sesuaikan.

Untuk mengukur apakah deteksi benar-benar bekerja, dua metrik yang sering dipakai adalah **TTD (Time to Detection)**, berapa lama dari serangan terjadi sampai terdeteksi, dan **TTR (Time to Response)**, berapa lama dari terdeteksi sampai ditangani. Keduanya menilai efektivitas SIEM sekaligus performa tim.

---

## Contoh Nyata Pola Deteksi

Beberapa pola yang lazim dipakai analis, untuk memberi gambaran konkret seperti apa correlation rule di lapangan.

**Login gagal terhadap akun yang dinonaktifkan.** Di Windows, login dengan akun disabled tidak akan pernah berhasil. Saat kredensial yang benar dicoba pada akun disabled, Windows menambahkan kode SubStatus `0xC0000072` pada event 4625. Pola ini layak diselidiki karena artinya seseorang tahu kredensial dari akun yang sudah dimatikan, sebuah sinyal yang jauh lebih spesifik daripada sekadar "login gagal".

**Akun layanan dipakai untuk login interaktif jarak jauh.** Kredensial akun layanan (service account) hampir tidak pernah dipakai untuk RDP di lingkungan korporat, padahal akun ini sering punya privilege tinggi. Rule yang menandai login sukses (event 4624) dengan tipe logon RemoteInteractive pada akun yang berpola nama service account adalah deteksi bernilai tinggi dengan false positive rendah.

**Binary tepercaya dipakai untuk eksekusi mencurigakan (LOLBin).** Ambil contoh MSBuild, utilitas sah bawaan Windows. Kalau MSBuild dipicu oleh aplikasi Office atau browser, itu sangat janggal dan menandakan kemungkinan eksekusi payload. Teknik penyalahgunaan binary tepercaya ini dipetakan ke MITRE ATT&CK pada taktik Defense Evasion (TA0005), teknik Trusted Developer Utilities Proxy Execution (T1127), sub-teknik MSBuild (T1127.001). Severity-nya tinggi. Bandingkan dengan skenario MSBuild yang membuat koneksi keluar: karena MSBuild juga bisa terhubung ke alamat yang sah, false positive lebih mungkin, jadi severity-nya diturunkan ke menengah dan deteksinya bergantung kuat pada reputasi IP tujuan.

Perhatikan benang merahnya: deteksi terbaik bukan yang paling rumit, melainkan yang punya rasio sinyal terhadap noise paling tinggi. Memetakan tiap deteksi ke kerangka seperti MITRE ATT&CK juga membantu mengukur sejauh mana cakupan deteksi kita dan di mana lubangnya.

---

## Kesalahan Umum di Sekitar SIEM

**1. Menganggap SIEM siap pakai sejak hari pertama.** Tanpa onboarding log dan tuning rule, yang kamu dapat adalah generator noise. SIEM adalah proses, bukan produk.

**2. Mengabaikan validasi log.** Membuat rule untuk sumber yang lognya ternyata tidak masuk menghasilkan deteksi semu yang tidak pernah berbunyi. Selalu konfirmasi datanya benar-benar ada sebelum menulis rule.

**3. Membiarkan false positive menumpuk.** Setiap alert palsu yang tidak ditangani menurunkan kepercayaan analis dan mendekatkan tim ke alert fatigue. Tuning adalah pekerjaan rutin, bukan opsional.

**4. Membuat alert tanpa konteks dan prioritas.** Kalau semua hal memicu alert dengan bobot yang sama, tidak ada yang benar-benar diprioritaskan. Severity harus mencerminkan dampak nyata ke aset.

**5. Lupa bahwa lingkungan berubah.** Server baru, aplikasi baru, dan kebijakan baru membuat rule lama jadi usang. Tanpa fine-tuning berkala, cakupan deteksi perlahan keropos.

---

## Kartu Referensi Cepat

| Konsep | Inti singkat |
|--------|--------------|
| SIEM | Gabungan SIM (manajemen log) + SEM (korelasi event real-time) |
| Pembeda dari IDS/IPS | Korelasi lintas sumber untuk menunjuk event berisiko tinggi |
| Tahap 1: Ingestion | Kumpulkan log via agen/syslog/API. Sebaik log yang masuk |
| Tahap 2: Normalization | Seragamkan field ke skema standar (mis. ECS) agar bisa dikorelasi |
| Tahap 3: Detection | Correlation rule mengubah banyak event jadi satu alert bermakna |
| False positive | Alert berbunyi tanpa serangan. Penyebab alert fatigue |
| False negative | Serangan terjadi tanpa alert. Akibat rule/log yang kurang |
| Kontekstualisasi | Tambahkan siapa, aset apa, kapan, untuk menentukan prioritas |
| Tuning | Kalibrasi rule terus-menerus sesuai lingkungan |
| TTD / TTR | Metrik kecepatan deteksi dan respons |

Pegangan akhir: SIEM bukan kotak ajaib. Ia adalah amplifier. Diberi log yang lengkap, skema yang rapi, dan rule yang dirawat, ia melipatgandakan kemampuan tim kecil mengawasi lingkungan besar. Diberi data berantakan dan dibiarkan, ia hanya melipatgandakan kebisingan.

---

## Referensi

- [Elastic: Elastic Common Schema (ECS) Reference](https://www.elastic.co/guide/en/ecs/current/index.html)
- [Elastic: Elastic Stack overview (Elasticsearch, Logstash, Kibana, Beats)](https://www.elastic.co/elastic-stack)
- [MITRE ATT&CK: Trusted Developer Utilities Proxy Execution (T1127)](https://attack.mitre.org/techniques/T1127/)
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [Microsoft: Audit logon events dan Logon Type](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)
