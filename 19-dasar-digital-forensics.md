# Dasar Digital Forensics: Akuisisi Bukti dan Order of Volatility

## Kenapa Ini Penting

Ketika sebuah alert akhirnya dikonfirmasi sebagai insiden nyata, pekerjaan bergeser dari mendeteksi menjadi merekonstruksi: apa sebenarnya yang terjadi di mesin korban, sejauh mana, dan bagaimana. Di sinilah digital forensics berperan. Tapi ada satu kebenaran keras yang harus dipahami sebelum menyentuh tool apa pun: cara kita mengumpulkan bukti menentukan apakah bukti itu masih berharga atau sudah rusak.

Kesalahan paling umum dan paling fatal seorang responder pemula adalah bertindak dalam urutan yang salah, misalnya langsung mematikan mesin yang terinfeksi. Tindakan itu, yang terasa seperti respons cepat, justru menghapus separuh barang bukti dalam sekejap. Tulisan ini membahas prinsip-prinsip akuisisi bukti yang benar, terutama order of volatility dan chain of custody, yang menjadi fondasi seluruh forensik.

---

## Order of Volatility: Yang Cepat Hilang Diambil Dulu

Prinsip paling fundamental dalam akuisisi bukti adalah order of volatility. Idenya sederhana: data yang paling cepat menghilang harus dikumpulkan lebih dulu, sebelum data yang relatif bertahan.

Bukti pada sebuah host terbagi dua sifat:

- **Data volatile** menghilang saat mesin dimatikan atau user logoff. Ini mencakup isi RAM (proses yang berjalan, koneksi jaringan aktif, kunci enkripsi, malware fileless yang hanya hidup di memori), ARP cache, dan tabel koneksi. Begitu daya hilang, data ini menguap selamanya.
- **Data non-volatile** bertahan melewati shutdown. Ini mencakup registry, Windows Event Log, dan artefak sistem seperti Prefetch dan Amcache, serta data aplikasi seperti riwayat browser.

Implikasi praktisnya tegas: jika sebuah mesin masih menyala dan dicurigai terinfeksi, **jangan buru-buru matikan**. Ambil memory dump lebih dulu, baru lakukan triage atau imaging disk. Mematikan mesin sama dengan menghancurkan bukti yang mungkin paling berharga, karena banyak teknik serangan modern, terutama malware fileless, hanya meninggalkan jejak di memori.

---

## Prinsip Integritas: Jangan Pernah Ubah Aslinya

Prinsip kedua yang tidak bisa ditawar: jangan pernah mengubah data sumber. Seluruh metode akuisisi forensik dirancang agar sumber tetap utuh dan tidak tersentuh, karena begitu data asli berubah, kredibilitasnya runtuh, dan dalam konteks hukum, ia bisa ditolak sebagai bukti.

Ini diwujudkan dengan beberapa cara. Imaging dilakukan secara read-only terhadap sumber. Hasil image diverifikasi dengan hash kriptografis, sehingga bisa dibuktikan identik dengan aslinya. Saat me-mount image untuk dianalisis, mode read-only dipilih agar analisis tidak menulis apa pun ke bukti. Setiap langkah ini melayani satu tujuan: menjaga agar bukti tetap bisa dipertanggungjawabkan.

Terkait erat dengan ini adalah **chain of custody**, yaitu pencatatan utuh siapa memegang bukti, kapan, dan apa yang dilakukan terhadapnya, sejak dikumpulkan sampai dianalisis. Tanpa chain of custody yang rapi, bukti sekuat apa pun bisa dipertanyakan keabsahannya di pengadilan.

---

## Tiga Arah Akuisisi

Akuisisi bukti bergerak ke tiga arah, masing-masing dengan tool dan pertimbangannya.

### Memory acquisition

Karena order of volatility, ini sering didahulukan. Tujuannya menangkap isi RAM ke sebuah file untuk dianalisis. Pada mesin fisik, tool seperti FTK Imager, WinPmem, atau DumpIt menangkap memori Windows, sementara untuk Linux ada LiME yang berjalan sebagai modul kernel. Untuk mesin virtual, cara paling bersih adalah men-suspend VM lalu menyalin file memori-nya, karena itu tidak menyentuh sistem operasi yang berjalan.

### Forensic imaging (full disk)

Membuat salinan bit demi bit dari media penyimpanan, termasuk slack space dan area yang tampak "terhapus". FTK Imager adalah yang paling umum di Windows, dengan padanan command line dd dan dcfldd di dunia Unix. Untuk menganalisis image tanpa merusaknya, tool seperti Arsenal Image Mounter me-mount-nya sebagai drive read-only.

### Rapid triage

Imaging penuh bisa makan waktu berjam-jam, dan sering kali tidak praktis di tengah insiden yang berlangsung. Rapid triage adalah jalan tengahnya: mengumpulkan artefak bernilai tinggi secara cepat dan terarah, bukan seluruh disk. Tool seperti KAPE bekerja dengan konsep target (artefak apa yang dikumpulkan) dan module (parser apa yang dijalankan), dengan koleksi standar siap pakai untuk triage. Untuk koleksi dari banyak mesin secara jarak jauh, platform seperti Velociraptor melakukannya lewat mekanisme hunt dan collection.

---

## Setelah Dikumpulkan: Analisis

Begitu bukti diakuisisi dengan benar, analisis bisa berjalan tanpa merusak sumber.

**Memory forensics** membaca isi RAM untuk menemukan apa yang tak terlihat di disk: proses tersembunyi, kode yang disuntik, koneksi C2 aktif. Framework seperti Volatility melakukannya lewat plugin, mulai dari mendaftar proses, memeriksa DLL dan handle yang terbuka, menelusuri koneksi jaringan, sampai mendeteksi region memori mencurigakan yang menandakan injeksi kode. Pendekatan investigasinya: temukan proses mencurigakan, periksa apa yang ia buka, lalu telusuri koneksi dan injeksinya.

**Disk forensics** menggali image disk dengan tool seperti Autopsy, yang menyediakan timeline, pencarian kata kunci, dan rekonstruksi artefak web maupun email.

**Analisis artefak NTFS** sering menjadi kunci merekonstruksi urutan aksi penyerang. Beberapa artefak yang sangat berharga: jurnal perubahan NTFS yang merekam pembuatan, penggantian nama, dan penghapusan file, sehingga aksi yang berusaha disembunyikan tetap tercatat. Lalu ada Zone.Identifier, penanda bahwa file berasal dari internet, dengan sifat menarik bahwa ia tidak ikut terhapus saat file di-rename, sehingga bisa dipakai melacak nama lama sebuah file ke nama barunya.

---

## Kesalahan Umum

**1. Mematikan mesin yang terinfeksi.** Ini menghapus seluruh data volatile, termasuk jejak malware fileless dan koneksi aktif. Ambil memori dulu.

**2. Mengabaikan order of volatility.** Mengumpulkan disk sebelum memori berisiko kehilangan bukti yang paling cepat menguap.

**3. Menulis ke bukti asli.** Analisis langsung di sumber, atau mount tanpa read-only, merusak integritas. Selalu kerjakan salinan yang terverifikasi hash.

**4. Mengabaikan chain of custody.** Bukti tanpa catatan penanganan yang rapi bisa ditolak di proses hukum, betapapun kuatnya.

**5. Selalu memilih imaging penuh.** Di tengah insiden, rapid triage sering lebih tepat. Imaging penuh untuk analisis mendalam, bukan untuk semua kasus.

---

## Kartu Referensi Cepat

| Prinsip / Tahap | Inti |
|-----------------|------|
| Order of volatility | Ambil yang cepat hilang dulu: RAM sebelum disk |
| Data volatile | RAM, koneksi aktif, ARP cache (hilang saat power off) |
| Data non-volatile | Registry, event log, artefak sistem (bertahan) |
| Integritas | Read-only, verifikasi hash, jangan ubah sumber |
| Chain of custody | Catat siapa, kapan, apa, agar bukti admissible |
| Memory capture | FTK Imager, WinPmem, DumpIt; LiME (Linux); .vmem (VM) |
| Disk imaging | FTK Imager, dd/dcfldd; mount read-only |
| Rapid triage | KAPE (target + module), Velociraptor (remote) |
| Analisis | Volatility (memori), Autopsy (disk), artefak NTFS (USN Journal, Zone.Identifier) |

Pegangan akhir: forensik dimulai jauh sebelum analisis, yaitu pada cara bukti dikumpulkan. Hormati order of volatility dengan mengambil memori sebelum disk, jaga integritas dengan tidak pernah menyentuh sumber asli, dan rawat chain of custody. Analisis sehebat apa pun tidak bisa menyelamatkan bukti yang sudah rusak sejak diambil.

---

## Referensi

- [NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/publications/detail/sp/800-86/final)
- [IETF RFC 3227: Guidelines for Evidence Collection and Archiving (order of volatility)](https://www.rfc-editor.org/rfc/rfc3227)
- [Volatility Foundation: dokumentasi framework](https://volatility3.readthedocs.io/en/latest/)
- [Eric Zimmerman: KAPE documentation](https://ericzimmerman.github.io/KapeDocs/)
- [SANS: Digital Forensics and Incident Response posters](https://www.sans.org/posters/?focus-area=digital-forensics)
