# Golden Ticket dan Abuse Kerberos: Cara Kerja dan Cara Mendeteksinya

## Kenapa Ini Penting

Golden Ticket adalah salah satu teknik paling ditakuti dalam serangan Active Directory, dan dengan alasan yang masuk akal. Begitu penyerang memilikinya, ia bisa menyamar sebagai user mana pun di domain, kapan pun, tanpa perlu password siapa pun lagi. Lebih buruk lagi, ini adalah teknik persistence: bahkan setelah tim keamanan mengira sudah membersihkan semuanya, penyerang bisa kembali masuk dengan tiket palsu yang masih sah.

Untuk memahami kenapa Golden Ticket begitu kuat dan begitu sulit dideteksi, kita perlu paham dulu bagaimana Kerberos sebenarnya bekerja. Tulisan ini membongkar alur tiket Kerberos secukupnya, lalu menjelaskan mengapa Golden Ticket nyaris tak terlihat saat dibuat, dan indikator anomali apa yang realistis untuk dipantau.

---

## Alur Kerberos Singkat

Kerberos adalah protokol autentikasi default di Active Directory. Pemain utamanya adalah Key Distribution Center (KDC), sebuah service di Domain Controller yang punya dua bagian: Authentication Server (AS) dan Ticket-Granting Server (TGS). Alurnya, disederhanakan:

1. User membuktikan identitasnya ke AS dan menerima sebuah **TGT (Ticket-Granting Ticket)**. TGT adalah bukti bahwa user sudah terautentikasi ke domain.
2. Saat user ingin mengakses sebuah service, ia menunjukkan TGT ke TGS dan menerima sebuah **service ticket (TGS)** untuk service itu.
3. User menyodorkan service ticket ke service tujuan, dan akses diberikan.

Yang krusial: seluruh kepercayaan sistem ini bertumpu pada satu akun bernama **krbtgt**. Semua TGT ditandatangani memakai hash password akun krbtgt. Akun ini adalah objek paling dipercaya di domain. Siapa pun yang memiliki hash password krbtgt bisa membuat TGT palsu yang ditandatangani dengan benar, dan KDC akan menerimanya sebagai sah. Itulah Golden Ticket.

---

## Cara Kerja Golden Ticket

Inti serangannya: penyerang memalsukan TGT untuk user mana pun (biasanya seorang Domain Admin) dengan menandatanganinya memakai hash krbtgt. Karena tiket itu ditandatangani dengan kunci yang dipercaya seluruh domain, KDC tidak punya alasan menolaknya.

Untuk melakukannya, penyerang butuh dua bahan: hash password akun krbtgt (umumnya didapat lewat DCSync setelah mencapai hak tinggi) dan SID domain. Dengan keduanya, tool seperti Mimikatz bisa membuat TGT palsu dengan parameter sesuka penyerang, termasuk user yang ditiru dan masa berlaku tiket.

Karena akun krbtgt adalah kunci semua kepercayaan Kerberos, Golden Ticket juga memungkinkan eskalasi dari child domain ke parent domain dalam forest yang sama. Domain bukanlah batas keamanan, forest-lah batasnya.

---

## Kenapa Golden Ticket Sangat Sulit Dideteksi

Inilah bagian yang membuat Golden Ticket menakutkan bagi defender. Tiket dipalsukan **secara offline**, di mesin penyerang yang sudah dikompromikan, tanpa menyentuh Domain Controller sama sekali. Pada langkah pembuatan tiket, DC tidak mencatat apa pun, karena memang tidak ada permintaan yang sampai kepadanya. Tidak ada Event 4768 (permintaan TGT yang sah) karena TGT tidak diminta dari AS, melainkan dibuat sendiri.

Akibatnya, kita tidak bisa mendeteksi pembuatan Golden Ticket secara langsung. Yang bisa dideteksi adalah jejak di sekitarnya: bahan baku yang dicuri sebelum tiket dibuat, dan penggunaan tiket setelah dibuat.

---

## Indikator Anomali yang Realistis

Karena pembuatannya tak terlihat, deteksi bergeser ke tiga sudut.

### 1. Deteksi pencurian bahan baku (hash krbtgt)

Golden Ticket hampir selalu didahului pencurian hash krbtgt, dan satu-satunya cara mendapatkannya adalah operasi yang berisiko terdeteksi: DCSync, pembacaan NTDS.dit, atau dump memori LSASS di Domain Controller. Mendeteksi DCSync yang tidak sah (lewat Event 4662 dengan GUID hak replikasi oleh akun yang bukan DC) sering menjadi peringatan dini sebelum Golden Ticket sempat dibuat. Dengan kata lain, deteksi DCSync yang baik adalah pertahanan terbaik terhadap Golden Ticket.

### 2. Deteksi anomali pada penggunaan tiket

Saat tiket palsu dipakai untuk mengakses sistem lain, jejak mulai muncul: Event 4624 dan 4625 (logon sukses dan gagal) pada sistem tujuan, yang berasal dari mesin terkompromi. Selain itu, ada anomali pada alur Kerberos itu sendiri. Karena TGT tidak pernah benar-benar diminta dari DC, penyerang bisa langsung meminta service ticket tanpa didahului permintaan TGT yang wajar. Pola "permintaan TGS tanpa TGT sebelumnya" dari satu sumber adalah anomali yang bisa dipantau.

### 3. Anomali pada masa berlaku dan enkripsi tiket

Mimikatz secara default membuat tiket dengan masa berlaku **sepuluh tahun**, jauh di luar kebijakan domain yang normal (biasanya jam-an). Tiket dengan lifetime yang absurd panjang adalah indikator klasik, dan inilah kenapa tool EDR modern memburu anomali ini. Penyerang yang teliti memang akan menyetel lifetime agar wajar, tapi banyak yang tidak. Tipe enkripsi yang tidak sesuai kebijakan domain juga bisa menjadi petunjuk tambahan. Bila SID History filtering aktif, eskalasi lintas domain memakai tiket palsu dapat memicu Event 4675.

---

## Pertahanan dan Pemulihan

Pencegahan berfokus pada melindungi krbtgt dan membatasi gerak penyerang:

- **Batasi login akun privileged** hanya ke mesin tepercaya (PAW), sehingga hash bernilai tinggi tidak tersebar ke workstation biasa yang mudah dikompromikan.
- **Reset password krbtgt secara berkala.** Microsoft menyediakan script resmi (KrbtgtKeys.ps1) yang punya mode audit untuk reset yang aman.
- **Aktifkan SID History filtering** antar domain untuk mencegah eskalasi child ke parent.

Soal pemulihan, ada satu detail yang sering salah dilakukan. Jika forest sudah terkompromi dan Golden Ticket dicurigai, reset password krbtgt **harus dilakukan dua kali**, karena akun ini menyimpan dua versi password (password history sebanyak dua). Reset sekali saja tidak menginvalidasi tiket yang ditandatangani versi sebelumnya. Antara dua reset, beri jeda minimal sepanjang masa hidup maksimum tiket (biasanya sekitar sepuluh jam) agar service yang sedang berjalan tidak rusak. Lakukan ini di tiap domain, dan iringi dengan reset password seluruh user serta pencabutan sertifikat bila perlu.

---

## Catatan tentang Silver Ticket

Saudara dekat Golden Ticket adalah Silver Ticket, dan membandingkannya membantu memahami keduanya. Bila Golden Ticket memalsukan TGT memakai hash krbtgt sehingga berkuasa atas seluruh domain dan tidak perlu mengontak DC saat dibuat, Silver Ticket memalsukan service ticket (TGS) memakai hash akun service atau komputer, sehingga cakupannya hanya satu service di satu host. Silver Ticket bahkan lebih senyap karena sama sekali tidak menyentuh DC, baik saat dibuat maupun dipakai. Deteksinya bertumpu pada anomali seperti membandingkan akun yang login (Event 4624) dengan daftar akun yang benar-benar pernah dibuat, serta memantau pemberian privilege khusus (Event 4672) yang tidak wajar.

---

## Kesalahan Umum

**1. Mengira Golden Ticket bisa dideteksi saat dibuat.** Tidak bisa, karena dibuat offline tanpa menyentuh DC. Deteksi harus bergeser ke pencurian krbtgt dan penggunaan tiket.

**2. Mengabaikan DCSync sebagai peringatan dini.** Hash krbtgt hampir selalu dicuri lewat DCSync. Deteksi DCSync yang baik mencegah Golden Ticket sejak hulu.

**3. Reset krbtgt hanya sekali.** Karena history dua password, reset sekali menyisakan celah. Harus dua kali dengan jeda yang aman.

**4. Hanya mengandalkan lifetime tiket.** Lifetime sepuluh tahun memang indikator bagus, tapi penyerang teliti akan menyetelnya wajar. Padukan dengan deteksi lain.

**5. Lupa bahwa forest, bukan domain, adalah batas keamanan.** Golden Ticket bisa mengeskalasi lintas domain dalam satu forest. Pemulihan harus mencakup seluruh forest.

---

## Kartu Referensi Cepat

| Aspek | Golden Ticket | Silver Ticket |
|-------|---------------|---------------|
| Yang dipalsukan | TGT | Service ticket (TGS) |
| Hash yang dipakai | krbtgt | Akun service/komputer |
| Cakupan | Seluruh domain | Satu service di satu host |
| Kontak ke DC | Tidak saat dibuat | Tidak sama sekali |
| Deteksi utama | Pencurian krbtgt (DCSync), penggunaan tiket (4624/4625), lifetime janggal | 4624 vs daftar akun, 4672 anomali |

Pegangan akhir: Golden Ticket tidak bisa dilihat saat lahir, jadi pertahanan terbaik adalah menjaga hulunya (lindungi dan rotasi krbtgt, deteksi DCSync) dan mengawasi hilirnya (anomali penggunaan tiket dan masa berlaku). Memahami alur Kerberos bukan teori belaka, itulah yang membuat kita tahu di titik mana sebuah tiket palsu meninggalkan jejak.

---

## Referensi

- [MITRE ATT&CK: Steal or Forge Kerberos Tickets, Golden Ticket (T1558.001)](https://attack.mitre.org/techniques/T1558/001/)
- [MITRE ATT&CK: Silver Ticket (T1558.002)](https://attack.mitre.org/techniques/T1558/002/)
- [Microsoft: AD Forest Recovery, resetting the krbtgt password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password)
- [Microsoft: How the Kerberos authentication protocol works](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [MITRE ATT&CK: OS Credential Dumping: DCSync (T1003.006)](https://attack.mitre.org/techniques/T1003/006/)
