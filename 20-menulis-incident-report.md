# Menulis Incident Report yang Benar-Benar Berguna untuk Tim Keamanan

## Kenapa Ini Penting

Investigasi sehebat apa pun menjadi sia-sia kalau temuannya tidak bisa dikomunikasikan dengan jelas ke orang yang tepat. Inilah keterampilan yang paling sering diremehkan dalam keamanan: menulis laporan insiden. Laporan adalah jembatan antara apa yang ditemukan analis dan tindakan yang diambil organisasi, sekaligus arsip pembelajaran agar insiden serupa tidak terulang.

Tantangan terbesarnya, satu dokumen yang sama dibaca oleh orang dengan kebutuhan yang sangat berbeda: eksekutif yang menilai risiko, CFO yang menghitung dampak finansial, tim legal yang mengurus kepatuhan, dan sesama analis yang akan berburu ancaman serupa. Laporan yang baik harus melayani semuanya tanpa mengorbankan kedalaman maupun keterbacaan. Tulisan ini membahas struktur laporan yang benar-benar dipakai di lapangan dan prinsip yang membuatnya berguna.

---

## Prinsip Utama: Seimbang antara Kedalaman dan Keterbacaan

Kunci laporan yang berguna adalah strukturnya yang berlapis. Karena audiensnya beragam, laporan tidak bisa seluruhnya teknis (eksekutif tersesat) maupun seluruhnya ringkasan (analis kekurangan detail). Solusinya menyusunnya bertingkat: ada ringkasan untuk yang non-teknis, ada analisis mendalam untuk yang teknis, dan ada lampiran bukti mentah untuk verifikasi independen. Setiap pembaca masuk ke lapisan yang relevan baginya.

Dua prinsip emas menyertai ini: setiap klaim harus didukung bukti, dan integritas bukti dijaga dengan hashing. Laporan yang menyatakan sesuatu terjadi tanpa bukti pendukung tidak punya kekuatan, apalagi bila perkara berlanjut ke ranah hukum.

---

## Sebelum Menulis: Identifikasi dan Logging

Laporan yang baik berakar pada pencatatan yang baik sejak awal insiden. Sebelum sebuah insiden bisa dilaporkan, ia harus diidentifikasi dan diklasifikasikan, berdasarkan tipe (malware, phishing, akses tak sah, kebocoran data, dan lainnya) dan tingkat severity, dari yang kritis dan menuntut intervensi segera sampai yang rutin. Klasifikasi ini bisa berubah seiring intelligence baru muncul, jadi pendekatannya terstruktur tapi fleksibel.

Yang krusial, sepanjang penanganan insiden, setiap aksi dan observasi harus dicatat teliti pada saat terjadi. Tahap pencatatan ini, sering didukung platform seperti JIRA atau TheHive, adalah sumber bahan baku laporan. Tanpa logging yang disiplin, merekonstruksi kronologi setelahnya menjadi tebak-tebakan. Catat siapa melakukan apa, kapan, dan apa hasilnya.

---

## Anatomi Laporan yang Lengkap

Struktur laporan bergerak dari ringkasan ke detail ke bukti.

### Executive Summary

Ini gerbang laporan, dan sering satu-satunya bagian yang dibaca banyak stakeholder, jadi harus sempurna. Ditujukan untuk audiens luas termasuk yang non-teknis, ia merangkum: identifier insiden, gambaran kejadian (tipe, waktu, sistem terdampak, status), temuan kunci (akar masalah, kerentanan yang dieksploitasi, data yang terkompromi), tindakan cepat yang sudah diambil, dan dampak ke para pemangku kepentingan. Bahasanya lugas, tanpa jargon teknis berlebihan.

### Technical Analysis

Bagian terbesar dan paling teknis, membedah insiden secara mendalam: sistem dan data yang terdampak, sumber bukti dan metodologi analisis (dengan integritas bukti dijaga lewat hash), indikator kompromi untuk hunting lebih luas, analisis akar masalah, dan yang menjadi tulang punggungnya, **technical timeline**.

Timeline ini menyusun event secara kronologis mengikuti alur serangan: reconnaissance, kompromi awal, komunikasi command and control, enumerasi, lateral movement, akses dan exfiltrasi data, aktivitas malware seperti injeksi dan persistence, lalu containment, eradication, dan recovery. Timeline yang disusun rapi berdasarkan timestamp inilah yang mengubah kumpulan temuan terpisah menjadi narasi serangan yang bisa dipahami.

### Response and Recovery Analysis

Mendokumentasikan apa yang dilakukan tim: respons cepat seperti pencabutan akses, strategi containment jangka pendek dan panjang, eradication (penghapusan malware dan patching), recovery (pemulihan data dan validasi sistem), serta aktivitas pasca-insiden termasuk monitoring yang diperketat dan lessons learned.

### Diagram dan Lampiran

Diagram seperti flowchart serangan dan peta sistem terdampak membantu memahami alur secara visual. Sementara lampiran adalah tulang punggung kredibilitas laporan: data mentah yang bisa diverifikasi independen, seperti file log, bukti forensik, catatan komunikasi, dan dokumen legal. Lampiran inilah yang membuat klaim di bagian atas bisa dibuktikan.

---

## Rekomendasi yang Actionable

Laporan yang baik tidak berhenti pada menceritakan apa yang terjadi, tapi mengarah ke perbaikan yang konkret. Inilah inti dari feedback loop, langkah terakhir proses pelaporan. Pertanyaan yang dijawab bukan sekadar "apa yang terjadi", melainkan "apa yang harus kita ubah agar ini tidak terulang".

Rekomendasi yang actionable bersifat spesifik dan bisa ditindaklanjuti: kontrol keamanan apa yang perlu ditambah, kebijakan apa yang perlu diperbaiki, deteksi apa yang perlu dibuat, training apa yang dibutuhkan. Idealnya deteksi baru yang dihasilkan berbasis perilaku, bukan sekadar memblokir satu indikator yang gampang diganti penyerang. Rekomendasi yang kabur seperti "tingkatkan keamanan" tidak berguna, yang berguna adalah yang bisa langsung diubah menjadi tugas.

---

## Komunikasi: Internal, Eksternal, dan Aman

Laporan tidak berdiri sendiri, ia bagian dari komunikasi insiden yang lebih luas, dan komunikasi ini punya dimensi yang sering terlewat.

Secara internal, ada notifikasi awal saat insiden diakui, pembaruan berkala, dan pertukaran temuan antar tim. Secara eksternal, ada komunikasi ke pihak terdampak, pernyataan publik untuk insiden besar, dan notifikasi ke regulator yang sering punya tenggat ketat.

Yang penting disadari, channel komunikasi insiden itu sendiri harus aman. Detail insiden idealnya dienkripsi end-to-end, diakses dengan autentikasi kuat, dan integritasnya dijaga. Ada ketegangan menarik di sini: keamanan mendorong komunikasi yang bisa dihapus otomatis untuk kerahasiaan, tapi regulasi sering mewajibkan penyimpanan catatan. Analis harus menavigasi keseimbangan itu. Dan untuk bukti yang mungkin dipakai di pengadilan, chain of custody harus terjaga agar admissible.

---

## Kesalahan Umum

**1. Menulis seluruhnya teknis atau seluruhnya ringkasan.** Audiens beragam butuh struktur berlapis: ringkasan, analisis, lampiran.

**2. Klaim tanpa bukti.** Setiap pernyataan harus didukung bukti, dengan integritas dijaga lewat hash. Tanpa itu, laporan lemah.

**3. Logging yang baru dikerjakan setelah insiden reda.** Catat pada saat kejadian. Merekonstruksi belakangan menghasilkan kronologi yang bolong.

**4. Rekomendasi yang kabur.** "Tingkatkan keamanan" tidak bisa ditindaklanjuti. Berikan perbaikan spesifik yang bisa jadi tugas.

**5. Mengabaikan keamanan channel komunikasi dan tenggat regulasi.** Diskusi insiden lewat channel tak aman atau telat memberi tahu regulator bisa memperburuk keadaan.

---

## Kartu Referensi Cepat

| Bagian laporan | Untuk siapa / isi |
|----------------|-------------------|
| Executive Summary | Non-teknis: gambaran, temuan kunci, dampak, tindakan |
| Technical Analysis | Teknis: sistem terdampak, IOC, akar masalah, timeline |
| Response & Recovery | Containment, eradication, recovery, lessons learned |
| Diagrams | Flowchart serangan, peta sistem terdampak |
| Appendices | Bukti mentah terverifikasi: log, forensik, komunikasi |
| Prinsip | Seimbangkan kedalaman dan keterbacaan; klaim didukung bukti |
| Timeline | Recon, kompromi, C2, lateral movement, exfil, containment, recovery |
| Penutup | Feedback loop: rekomendasi actionable, lessons learned |

Pegangan akhir: laporan insiden yang berguna bukan yang paling tebal, tapi yang membuat setiap pembacanya, dari eksekutif sampai analis, bisa bertindak. Susun berlapis, dukung tiap klaim dengan bukti, rekonstruksi kronologi dengan rapi, dan tutup dengan rekomendasi yang benar-benar bisa dikerjakan. Di situlah investigasi berubah menjadi perbaikan.

---

## Referensi

- [NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS: Incident Handler's Handbook](https://www.sans.org/white-papers/33901/)
- [TheHive Project: case management untuk incident response](https://thehive-project.org/)
- [MITRE ATT&CK: Enterprise Matrix (untuk pemetaan TTP di laporan)](https://attack.mitre.org/matrices/enterprise/)
- [ENISA: Good Practice Guide for Incident Management](https://www.enisa.europa.eu/publications/good-practice-guide-for-incident-management)
