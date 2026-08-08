# Threat Hunting Berbasis Hipotesis: Berburu Ancaman dengan Elastic Stack

## Kenapa Ini Penting

Ada satu angka yang menjelaskan kenapa threat hunting ada: dwell time, yaitu jarak waktu antara saat penyerang membobol jaringan dan saat mereka akhirnya terdeteksi. Angka ini sering terukur dalam minggu, kadang bulan. Artinya penyerang bisa berada di dalam jaringan begitu lama tanpa ketahuan, cukup waktu untuk memetakan, mencuri, dan menancap dalam.

Threat hunting lahir dari kesadaran bahwa menunggu alert berbunyi tidaklah cukup. Penyerang canggih sengaja beroperasi di bawah ambang deteksi. Hunting membalik posisi: alih-alih menunggu, analis secara aktif dan dipimpin hipotesis menyisir data untuk menemukan ancaman yang lolos dari pertahanan yang ada. Tujuannya menekan dwell time, menemukan musuh sedini mungkin. Tulisan ini membahas cara berpikir berbasis hipotesis dan bagaimana ia diterapkan dengan SIEM seperti Elastic Stack.

---

## Hunting Bukan Menunggu Alert

Perbedaan paling mendasar antara monitoring dan hunting ada pada arah inisiatif. Monitoring bersifat menunggu: sebuah aturan berbunyi, analis merespons. Hunting bersifat mencari: analis berangkat dari dugaan tentang apa yang mungkin sudah terjadi, lalu membuktikannya lewat data, tanpa perlu ada alert sama sekali.

Threat hunting adalah aktivitas yang aktif, dipimpin manusia, dan sering digerakkan hipotesis. Ia dipakai dalam dua mode yang saling melengkapi. Secara **proaktif**, hunting mengantisipasi ancaman berdasarkan intelligence dan TTP penyerang, sebelum ada insiden. Secara **reaktif**, hunting mencari artefak terkait insiden yang sudah terverifikasi di seluruh jaringan, untuk memahami cakupan penuh kompromi. Keduanya bisa berjalan bersamaan dengan incident response, bukan menggantikannya.

Yang dibutuhkan seorang hunter bukan sekadar tool, melainkan pemahaman mendalam tentang seperti apa aktivitas normal di lingkungannya, empati kognitif terhadap cara berpikir penyerang, dan data berkualitas untuk diselami.

---

## Inti dari Semuanya: Hipotesis yang Bisa Diuji

Jantung hunting berbasis hipotesis adalah hipotesisnya sendiri, dan ada satu syarat mutlak: hipotesis harus **spesifik dan bisa diuji**. Hipotesis yang tidak bisa diuji tidak berguna, karena ia tidak memberi tahu kita ke mana harus mencari dan apa yang harus dicari.

Hipotesis yang baik berasal dari sumber konkret: laporan threat intelligence terbaru, kerentanan baru pada aplikasi yang kita pakai, indikator terkait penyerang yang menyasar industri kita, atau anomali yang terpantau. Bentuknya bukan "apakah kita diserang", melainkan sesuatu yang mengarahkan, misalnya "penyerang memanfaatkan phishing berisi file OneNote untuk mendapatkan eksekusi awal". Hipotesis seperti ini langsung memberi tahu data apa yang harus diperiksa dan pola apa yang dicari.

Penting disadari, hipotesis yang berbeda menghasilkan jalur perburuan yang berbeda. Inilah kenapa merumuskannya dengan baik menentukan seluruh arah hunting.

---

## Siklus Perburuan

Hunting yang terstruktur mengikuti siklus, bukan sekali jalan:

1. **Menyiapkan panggung.** Tetapkan target berdasarkan aset kritis dan threat landscape, pastikan logging yang memadai aktif dan tool terkonfigurasi.
2. **Merumuskan hipotesis.** Buat dugaan yang spesifik dan bisa diuji.
3. **Merancang perburuan.** Tentukan sumber data, metode, dan pola yang dicari.
4. **Mengumpulkan dan memeriksa data.** Inilah perburuan aktif, sangat iteratif. Hipotesis bisa diperhalus seiring temuan baru.
5. **Mengevaluasi temuan.** Konfirmasi atau bantah hipotesis, pahami perilaku ancaman, identifikasi sistem terdampak.
6. **Memitigasi ancaman.** Bila terkonfirmasi, lakukan remediasi.
7. **Setelah perburuan.** Dokumentasikan, dan yang krusial, ubah temuan menjadi deteksi baru.
8. **Pembelajaran berkelanjutan.** Tiap siklus menyempurnakan siklus berikutnya.

Langkah ketujuh adalah yang membedakan hunting yang matang. Sebuah perburuan yang sukses tidak berakhir dengan menemukan satu penyerang, tapi dengan menghasilkan aturan deteksi baru sehingga ancaman serupa tertangkap otomatis ke depan. Hunting hari ini menjadi alert otomatis besok.

---

## Mengejar TTP, Bukan Sekadar IOC

Saat berburu, ada pilihan tentang apa yang dikejar, dan Pyramid of Pain memandunya. Indikator di bawah piramida (hash, IP, domain) mudah diubah penyerang, jadi deteksi berbasis itu cepat usang. Indikator di puncak (TTP, yaitu cara penyerang bekerja) jauh lebih menyakitkan untuk diubah, jadi jauh lebih bernilai.

Konsekuensinya untuk hunting: jangan berhenti pada mencocokkan satu IOC dari laporan. Mulai dari IOC bila ada, tapi lebar ke TTP. Misalnya, alih-alih hanya mencari satu hash, buru pola perilaku seperti PowerShell yang mengunduh dan menjalankan konten dari layanan paste publik, atau proses Office yang melahirkan command interpreter. Pola perilaku menangkap varian yang IOC spesifik akan melewatkannya.

---

## Menerapkannya dengan Elastic Stack

Mari lihat bagaimana ini bekerja dalam praktik, memakai sebuah skenario hunting reaktif berbasis laporan intelligence. Bayangkan laporan menyebut sebuah malware masuk lewat phishing berisi file OneNote, lalu menjalankan rantai eksekusi tertentu. Hipotesisnya jelas: phishing itu berhasil di lingkungan kita.

Dengan Elastic sebagai SIEM, perburuan berjalan dari satu petunjuk ke petunjuk berikutnya, menyusuri data Sysmon, log Windows, dan log jaringan Zeek lewat antarmuka pencarian:

- Mulai dari mencari unduhan file mencurigakan, memanfaatkan event Sysmon yang menandai file yang diunduh browser. Ini mengungkap mesin dan user yang terdampak beserta waktunya.
- Saat log jaringan endpoint sengaja tidak menangkap koneksi browser (praktik umum agar log tidak membludak), log Zeek mengisi celah, memperlihatkan resolusi DNS dan koneksi ke layanan hosting tempat file berasal.
- Telusuri rantai proses: file OneNote dibuka, melahirkan command interpreter, yang menjalankan sebuah batch file, yang lalu memanggil PowerShell untuk mengunduh tahap berikutnya. Tiap langkah dikonfirmasi lewat event pembuatan proses dengan memeriksa proses induk dan command line-nya.
- Ikuti aktivitas PowerShell berdasarkan process ID, temukan koneksi command and control (sering disamarkan lewat layanan tunneling sah), file yang di-drop untuk persistence, dan tool recon Active Directory yang diunggah.
- Akhirnya, cari hash file jahat di seluruh lingkungan untuk menemukan mesin lain yang terkompromi, dan periksa log logon untuk merekonstruksi bagaimana kredensial dibobol dan lateral movement terjadi.

Yang menarik dari alur ini: ia bermula dari satu hipotesis, lalu setiap temuan memunculkan pertanyaan berikutnya, sampai seluruh rangkaian serangan terekonstruksi. Inilah hunting reaktif yang baik, menyusuri benang dari satu petunjuk menjadi gambaran utuh.

---

## Threat Intelligence sebagai Bahan Bakar

Hunting tidak berjalan dalam kekosongan. Ia diberi bahan bakar oleh threat intelligence, yang sifatnya prediktif: mengantisipasi langkah penyerang. Intelligence yang baik memenuhi empat prinsip, yaitu relevan dengan organisasi kita, tepat waktu, bisa ditindaklanjuti, dan akurat. Profil penyerang dari tim intelligence memandu hunter dalam menyusun hipotesis, dan sebaliknya, temuan hunting memperkaya intelligence. Keduanya saling memperkuat.

Saat membaca laporan intelligence untuk memulai perburuan, langkahnya: pahami konteks dan relevansinya, klasifikasikan IOC (berbasis jaringan, host, atau email), pahami daur hidup serangan lewat pemetaan ke MITRE ATT&CK, validasi IOC agar tidak mengejar false positive, lalu lebar dari IOC ke TTP untuk menangkap varian.

---

## Kesalahan Umum

**1. Menunggu alert alih-alih berburu.** Hunting justru dimulai tanpa alert, dari hipotesis tentang apa yang mungkin terlewat.

**2. Hipotesis yang tidak bisa diuji.** "Apakah kita diserang" bukan hipotesis. Yang berguna adalah dugaan spesifik yang mengarahkan ke data dan pola tertentu.

**3. Berhenti di IOC.** Indikator gampang diganti penyerang. Lebar ke TTP untuk menangkap varian.

**4. Tidak mengubah temuan menjadi deteksi.** Perburuan yang berakhir tanpa aturan deteksi baru membuang sebagian besar nilainya.

**5. Mengabaikan baseline lingkungan.** Tanpa tahu apa yang normal, anomali tidak terlihat dan hunting jadi menebak.

---

## Kartu Referensi Cepat

| Konsep | Inti |
|--------|------|
| Dwell time | Jarak breach ke deteksi. Tujuan hunting: menekannya |
| Mode hunting | Proaktif (antisipasi) dan reaktif (pasca-insiden terverifikasi) |
| Hipotesis | Harus spesifik dan bisa diuji |
| Siklus | Setup, hipotesis, desain, kumpul data, evaluasi, mitigasi, dokumentasi, belajar |
| Pyramid of Pain | Kejar TTP (sulit diubah), bukan sekadar hash/IP |
| Hasil akhir | Ubah temuan jadi deteksi baru |
| Elastic dalam praktik | Susuri Sysmon, Windows log, Zeek dari satu petunjuk ke gambaran utuh |

Pegangan akhir: threat hunting adalah sikap, bukan tool. Ia berangkat dari hipotesis yang bisa diuji, mengejar cara kerja penyerang alih-alih sekadar jejaknya, dan selalu berakhir dengan deteksi baru. Setiap perburuan yang baik membuat lingkungan sedikit lebih sulit untuk disembunyikan.

---

## Referensi

- [SANS: The Who, What, Where, When, Why and How of Effective Threat Hunting](https://www.sans.org/white-papers/36785/)
- [MITRE ATT&CK: Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [SANS: Pyramid of Pain (David Bianco)](https://www.sans.org/tools/the-pyramid-of-pain/)
- [Elastic Security: Threat hunting documentation](https://www.elastic.co/guide/en/security/current/es-overview.html)
- [The Diamond Model of Intrusion Analysis](https://www.activeresponse.org/the-diamond-model/)
