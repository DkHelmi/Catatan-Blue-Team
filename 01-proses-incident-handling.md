# Proses Incident Handling: 6 Fase Penanganan Insiden Keamanan dari Persiapan sampai Pemulihan

## Kenapa Ini Penting

Saat sebuah alarm keamanan benar-benar berbunyi, hal yang membedakan tim yang tenang dari tim yang panik bukanlah tool yang mahal, melainkan proses yang sudah dilatih. Insiden keamanan selalu datang di waktu yang tidak nyaman, informasinya selalu setengah, dan tekanan dari manajemen selalu ada. Tanpa kerangka kerja yang jelas, orang cenderung melompat langsung ke tindakan yang terasa "produktif", misalnya buru-buru menghapus malware atau memformat ulang server, padahal tindakan itu sering justru menghancurkan bukti dan membiarkan penyerang tetap punya jalan masuk.

Incident handling adalah cara berpikir terstruktur untuk menjawab satu pertanyaan inti: apa yang terjadi, seberapa jauh penyebarannya, dan bagaimana menghentikannya tanpa membuat keadaan lebih buruk. Tulisan ini membahas enam fase penanganan insiden versi praktisi (model SANS, sering disingkat PICERL) dan, yang lebih penting, kapan harus melakukan apa serta kesalahan umum yang membuat respons gagal.

Sebelum masuk ke fase, perlu disamakan dulu satu hal yang sering tertukar. **Event** adalah aksi apa pun di sistem, netral, belum tentu jelek (user login, firewall mengizinkan koneksi). **Incident** adalah event yang membawa konsekuensi negatif (akses tidak sah ke data, sistem crash). Sebagian besar pekerjaan analis SOC adalah memilah mana event yang naik kelas jadi incident. Begitu sesuatu dinyatakan incident, enam fase di bawah ini mulai berjalan.

---

## Dua Kerangka, Satu Cara Berpikir

Ada dua referensi yang paling sering dipakai industri, dan keduanya menggambarkan hal yang sama dengan tingkat detail berbeda.

- **NIST SP 800-61** memecah proses jadi empat fase: Preparation, Detection & Analysis, Containment-Eradication-Recovery (digabung jadi satu), dan Post-Incident Activity.
- **SANS** memakai enam langkah yang lebih granular: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned.

Perbedaannya hanya soal pengelompokan. SANS memisahkan Containment, Eradication, dan Recovery menjadi tiga fase terpisah karena, dalam praktik, ketiganya butuh keputusan dan keahlian yang berbeda. Itulah kenapa untuk keperluan operasional sehari-hari, model enam fase lebih enak dijadikan peta. Satu hal yang berlaku di kedua kerangka dan sering dilupakan: prosesnya **siklus, bukan garis lurus**. Bukti baru di fase Eradication bisa melempar kita kembali ke Identification. Jangan memperlakukan fase sebagai checklist sekali jalan.

---

## Fase 1: Preparation (Persiapan)

Ini fase yang paling tidak terlihat tapi paling menentukan. Preparation terjadi jauh sebelum insiden, dan kualitasnya menentukan apakah lima fase berikutnya berjalan mulus atau berantakan. Ada dua sisi yang harus disiapkan.

**Sisi kapabilitas**, yaitu kemampuan tim untuk merespons. Yang termasuk di sini:

- Dokumentasi kontak yang selalu diperbarui: anggota tim, legal, compliance, manajemen, IT, hubungan media, dan tim IR eksternal kalau ada.
- Incident response policy, plan, dan playbook per tipe insiden.
- Baseline sistem dan jaringan dari golden image, diagram jaringan, serta database aset. Tanpa tahu kondisi "normal", mustahil mengenali yang "abnormal".
- Akun berprivilege tinggi yang disiapkan untuk dipakai on-demand, diaktifkan saat insiden terkonfirmasi dan dinonaktifkan plus reset password begitu selesai.
- Jalur pembelian darurat. Menunggu approval berminggu-minggu untuk tool seharga beberapa ratus dolar di tengah insiden adalah pemborosan waktu yang fatal.

Banyak tool fisik dan software ini dikumpulkan dalam satu **jump bag**, tas yang selalu siap diambil: forensic workstation, write blocker, hard drive untuk imaging, kabel, sampai form chain of custody. Idenya sederhana, saat insiden terjadi kita tidak punya waktu mengumpulkan alat satu per satu.

**Sisi proteksi**, yaitu mengurangi kemungkinan dan dampak insiden lewat hardening. Secara teknis ini sering bukan tugas langsung tim IR, tapi tim IR wajib tahu kontrol apa saja yang terpasang, karena di situlah artifact investigasi akan dicari. Beberapa kontrol berdampak tinggi: matikan LLMNR/NetBIOS, terapkan LAPS dan cabut hak admin dari user biasa, set PowerShell ke ConstrainedLanguage, blokir eksekusi dari folder yang bisa ditulis user (Downloads, Desktop, AppData), terapkan MFA untuk semua akses administratif, segmentasi jaringan, dan DMARC untuk menahan phishing yang menyamar sebagai domain sendiri.

Satu prinsip yang sering diabaikan: **sistem dokumentasi dan komunikasi insiden harus terpisah dari infrastruktur organisasi**. Asumsikan sejak awal bahwa penyerang sudah menguasai segalanya, termasuk membaca email internal. Membahas strategi containment lewat email yang sedang disadap penyerang adalah cara cepat membocorkan rencana sendiri.

---

## Fase 2: Identification (Deteksi & Analisis)

Di sinilah pertanyaan "apakah ini benar-benar insiden?" dijawab. Sumber deteksi bisa bermacam-macam: karyawan yang melihat perilaku janggal, alert dari EDR/IDS/SIEM, hasil threat hunting, atau bahkan notifikasi dari pihak ketiga yang menemukan tanda kita sudah terkompromi.

Kunci fase ini bukan langsung membunyikan alarm besar, melainkan **membangun konteks lewat investigasi awal**. Informasi mentah hampir selalu menyesatkan. Kalimat "akun admin konek ke IP X jam 03:00" tidak berarti apa-apa sampai kita tahu sistem apa di IP itu, zona waktu mana yang dipakai, dan apakah pola itu memang tidak biasa untuk akun tersebut. Sebelum mengeskalasi, kumpulkan: kapan dan bagaimana terdeteksi, apa tipe insidennya, sistem apa saja yang terdampak, siapa yang sudah menyentuh sistem itu, dan apakah aktivitas masih berlangsung atau sudah berhenti.

Hampir bersamaan, mulai bangun **timeline**. Selama investigasi, bukti tidak ditemukan dalam urutan kronologis. Justru dengan menatanya berdasarkan waktu kejadian, ceritanya muncul. Kolom minimal yang berguna: tanggal, waktu (sertakan zona waktu), hostname, deskripsi event, dan sumber data. Timeline juga membantu memutuskan apakah sebuah bukti baru bagian dari insiden ini, misalnya payload yang dikira awal serangan ternyata sudah ada di mesin lain dua minggu sebelumnya.

Inti analisis adalah siklus tiga langkah yang berulang: membuat dan memakai **IOC** (Indicator of Compromise seperti hash file, IP, nama file), menemukan **lead dan sistem terdampak baru** dari IOC itu, lalu **mengumpulkan dan menganalisis data** dari sistem tersebut. Format standar untuk mendokumentasikan dan berbagi IOC antara lain YARA dan STIX. Hindari godaan untuk terpaku pada satu temuan saja. Mempersempit investigasi ke satu malware yang sudah dikenal sering berujung pada kesimpulan prematur dan pemahaman dampak yang tidak utuh.

Ada satu jebakan teknis yang penting di fase ini, yaitu **credential caching**. Saat memeriksa sistem yang mungkin terkompromi, jangan sampai kredensial admin kita ikut tersimpan di mesin itu, karena bisa langsung dipanen penyerang. Pakai protokol yang tidak meng-cache kredensial di sistem remote, misalnya WinRM atau logon Windows tipe 3 (Network Logon). Contoh klasik "kenali tool-mu": PsExec dengan kredensial eksplisit meninggalkan cache di mesin remote, sedangkan dipakai tanpa kredensial lewat sesi yang sudah login tidak. Tool yang sama, jejak yang berbeda.

---

## Fase 3: Containment (Pembendungan)

Begitu yakin ada insiden dan paham gambaran kasarnya, tujuan berubah jadi menghentikan penyebaran tanpa merusak bukti. Containment biasanya dibagi dua tahap.

- **Short-term containment** adalah aksi cepat dengan jejak minimal: memindahkan host ke VLAN terisolasi, memutus koneksi jaringan, atau mengalihkan (sinkhole) domain C2 penyerang ke alamat yang kita kontrol. Karena perubahan ke sistem dijaga seminimal mungkin, ini juga momen ideal mengambil forensic image dan mengawetkan bukti.
- **Long-term containment** adalah perubahan yang lebih permanen: rotasi password, menambah firewall rule, memasang HIDS, atau menerapkan patch sambil menyiapkan eradication.

Ada dua keputusan sulit yang khas di fase ini.

**Pertama, soal timing.** Kapan harus containment lebih dulu, sebelum investigasi tuntas? Aturan praktisnya: kalau kerusakan sedang aktif berlangsung dan membesar (ransomware sedang mengenkripsi, data sedang dieksfiltrasi), bendung sekarang walau gambarannya belum lengkap. Tapi kalau penyerang sudah pasif dan hanya sesekali beacon, menahan diri sebentar untuk memetakan seluruh pijakan mereka sering lebih berharga. Containment terlalu dini pada penyerang yang masih senyap berisiko membuat mereka sadar terdeteksi lalu berganti taktik.

**Kedua, soal serentak.** Aksi containment harus dikoordinasikan dan dieksekusi serempak di semua sistem yang terdampak. Memutus lima dari sepuluh host yang terinfeksi, lalu menunggu, sama saja memberi sinyal ke penyerang bahwa permainan sudah ketahuan. Mereka akan memakai lima host sisanya untuk membangun jalan masuk baru sebelum kita sempat menutupnya.

---

## Fase 4: Eradication (Pemberantasan)

Setelah penyebaran terbendung, eradication menghapus akar masalah beserta semua sisa kehadiran penyerang: menghapus malware, mencabut mekanisme persistence (scheduled task, service jahat, autorun registry, akun bayangan yang dibuat penyerang), serta menutup celah masuk awal lewat patch atau perbaikan konfigurasi. Sebagian sistem cukup dibersihkan, sebagian lain lebih aman di-rebuild dari nol atau di-restore dari backup yang bersih.

Pertanyaan yang sering muncul: kenapa repot mencari tahu "bagaimana" insiden terjadi, kenapa tidak rebuild saja semua sistem yang kena? Jawabannya adalah esensi dari kenapa fase Identification tidak boleh dilewati. Kalau kita tidak tahu persis bagaimana penyerang masuk dan apa saja yang mereka sentuh, remediasi apa pun hanya menebak. Penyerang akan mengulang jalur yang sama dan masuk lagi seminggu kemudian. Eradication yang efektif hanya mungkin kalau scoping di fase sebelumnya benar-benar tuntas.

Ini juga membawa kita ke **kesalahan paling umum** dalam penanganan insiden: melompat langsung ke eradication tanpa scoping. Pola yang sering terlihat: satu mesin ketahuan terinfeksi, analis langsung membersihkannya dan menyatakan kasus selesai, padahal penyerang sudah punya pijakan di sembilan mesin lain dan satu akun Domain Admin baru. Eradication yang dilakukan sebelum cakupan penuh dipahami bukan hanya gagal, tapi memberi penyerang waktu untuk bersembunyi lebih dalam.

---

## Fase 5: Recovery (Pemulihan)

Recovery mengembalikan sistem ke operasi normal. Yang penting di sini, keputusan kapan sebuah sistem boleh kembali produksi sebaiknya melibatkan pemilik bisnis, bukan hanya tim keamanan. Bisnis perlu memverifikasi bahwa sistem berfungsi sebagaimana mestinya dan datanya utuh sebelum dibawa kembali online.

Yang membedakan recovery yang matang adalah **monitoring ketat pasca-pemulihan**. Sistem yang pernah terkompromi adalah target yang paling mungkin diserang ulang dalam waktu dekat, karena penyerang tahu persis kelemahannya. Maka setelah dipulihkan, sistem itu dipantau lebih intens dari biasanya untuk tanda-tanda seperti: logon yang tidak biasa (akun atau service yang belum pernah login di situ), proses yang janggal, atau perubahan registry di lokasi yang sering disalahgunakan malware. Munculnya kembali salah satu tanda ini adalah indikasi bahwa eradication belum tuntas.

Pada insiden besar, recovery bisa memakan waktu berbulan-bulan dan dilakukan bertahap. Fase awal fokus pada quick win untuk menaikkan keamanan dengan cepat, fase berikutnya pada perubahan permanen jangka panjang.

---

## Fase 6: Lessons Learned (Pasca-Insiden)

Fase terakhir adalah yang paling sering dipotong karena tim sudah lelah dan ingin pindah ke pekerjaan lain. Padahal di sinilah satu insiden diubah menjadi peningkatan kapabilitas yang permanen. Idealnya dibahas dalam pertemuan dengan semua pihak yang terlibat, beberapa hari setelah insiden mereda, saat laporan final sudah siap.

Laporan final yang berguna menjawab pertanyaan yang actionable, bukan sekadar kronologi: apa yang terjadi dan kapan, seberapa baik tim merespons dibanding playbook yang ada, apakah bisnis memberi informasi yang dibutuhkan dengan cepat, langkah preventif apa yang perlu dipasang agar kejadian serupa tidak terulang, dan tool atau visibilitas apa yang ternyata kurang. Output konkretnya bisa berupa playbook yang diperbarui, rule deteksi baru (idealnya berbasis TTP, bukan sekadar memblokir satu IP), atau kebutuhan training tertentu.

Di sinilah konsep **Pyramid of Pain** relevan untuk recall. Memblokir hash atau IP penyerang itu mudah bagi kita tapi juga mudah dihindari penyerang, mereka tinggal ganti. Deteksi berbasis perilaku dan TTP jauh lebih menyakitkan untuk mereka ubah. Lessons learned yang baik mendorong deteksi naik ke level itu, bukan berhenti di pemblokiran indikator yang gampang diganti.

---

## Kesalahan Umum yang Membuat Respons Gagal

**1. Melompat ke eradication tanpa scoping.** Ini yang paling merusak. Membersihkan satu mesin sementara penyerang masih punya pijakan di tempat lain hanya memberi mereka peringatan dan waktu.

**2. Containment sepotong-sepotong.** Mengisolasi sebagian host lalu menunggu sama dengan memberi tahu penyerang bahwa mereka ketahuan. Eksekusi serentak.

**3. Mengabaikan timeline dan konteks.** Lima login gagal Senin pagi adalah orang yang lupa password. Lima login gagal jam 3 dini hari Sabtu dari IP luar negeri adalah brute force. Event yang sama, arti yang sama sekali berbeda.

**4. Merusak bukti karena terburu-buru.** Mematikan atau memformat mesin menghancurkan artifact yang hanya hidup di memori. Kalau ada kemungkinan tindakan hukum, jaga chain of custody sejak awal.

**5. Terpaku pada satu temuan.** Menganggap satu malware yang ditemukan sebagai keseluruhan insiden membuat analis berhenti terlalu dini. Sering ada lebih dari satu mekanisme persistence, bahkan kadang lebih dari satu penyerang sekaligus di lingkungan yang sama, satu yang berisik dan satu yang senyap.

**6. Berkomunikasi lewat kanal yang mungkin disadap.** Membahas rencana respons lewat email internal saat penyerang masih punya akses adalah membocorkan strategi sendiri.

---

## Ilustrasi Singkat: Membaca Satu Insiden lewat Enam Fase

Bayangkan sebuah aplikasi manajemen yang menghadap internet masih memakai kredensial default. Penyerang login, mengeksploitasi kerentanan RCE, dan membangun C2 keluar lewat HTTPS ke sebuah host (misalnya `103.112.60[.]117`, ditulis defang). Dari sana mereka membuat akun Domain Admin baru, bergerak lateral via RDP ke workstation yang port-nya terekspos, lalu menyebarkan persistence ke seluruh domain lewat GPO.

Dipetakan ke enam fase:

- **Preparation** yang gagal: kredensial default tidak pernah diganti, MFA tidak dipaksakan, dan log aplikasi web tidak dikirim ke SIEM. Inilah yang membuka pintu.
- **Identification**: sysadmin melihat koneksi keluar yang janggal, lalu analis mengaitkannya dengan login dari IP asing dan eksekusi `msiexec` yang memasang MSI ke banyak host. Terobosan datang dari korelasi, bukan dari satu alert tunggal.
- **Containment**: blokir egress ke IP C2 di firewall dan host, isolasi mesin terdampak, nonaktifkan akun penyerang, lakukan serentak.
- **Eradication**: cabut scheduled task dan GPO jahat, hapus MSI, rebuild host yang dalam, tutup celah RCE awal dengan patch.
- **Recovery**: kembalikan layanan dengan verifikasi bisnis, lalu pantau ketat tanda persistence yang mungkin tersisa.
- **Lessons Learned**: paksa penggantian kredensial default sebagai kebijakan, kirim log aplikasi ke SIEM, dan buat deteksi berbasis perilaku (misalnya logon RDP dari IP publik) alih-alih sekadar memblokir satu IP.

Pelajaran terbesar dari pola seperti ini: menghapus jejak yang terlihat (file atau malware yang ketahuan) tidak menetralkan akar masalah selama mekanisme persistence dan celah masuk awal belum dibereskan.

---

## Kartu Referensi Cepat

| Fase | Tujuan utama | Keputusan kunci | Kesalahan fatal |
|------|--------------|-----------------|-----------------|
| Preparation | Siap sebelum insiden | Apa yang masuk jump bag dan playbook | Tidak punya baseline "normal" |
| Identification | Pastikan ini insiden, bangun konteks | Eskalasi atau belum, scope sampai mana | Terpaku satu temuan, abaikan timeline |
| Containment | Hentikan penyebaran | Bendung sekarang atau amati dulu | Eksekusi sepotong, bukan serentak |
| Eradication | Hapus akar dan persistence | Bersihkan atau rebuild | Eradication tanpa scoping tuntas |
| Recovery | Kembali normal dengan aman | Kapan boleh produksi (libatkan bisnis) | Lupa monitoring ketat pasca-pulih |
| Lessons Learned | Ubah insiden jadi perbaikan | Deteksi baru berbasis apa | Memotong fase ini karena lelah |

Pegangan akhir: prosesnya siklus, bukan garis lurus. Jangan melompati fase, jangan mengeradikasi sebelum tahu cakupan penuh, dan jangan biarkan satu insiden berlalu tanpa menghasilkan deteksi yang lebih baik.

---

## Referensi

- [NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS: Incident Handler's Handbook (model PICERL enam langkah)](https://www.sans.org/white-papers/33901/)
- [MITRE ATT&CK: Enterprise Matrix (pemetaan TTP)](https://attack.mitre.org/)
- [SANS: The Pyramid of Pain (David Bianco)](https://www.sans.org/tools/the-pyramid-of-pain/)
- [Microsoft: Incident response overview](https://learn.microsoft.com/en-us/security/operations/incident-response-overview)
