# Mendeteksi Serangan Active Directory: Kerberoasting, AS-REP Roasting, dan DCSync

## Kenapa Ini Penting

Active Directory adalah jantung mayoritas lingkungan enterprise Windows, dan justru karena itu ia jadi target utama. Mengompromikan AD berarti akses ke hampir semua sistem dan data. Masalahnya bagi defender, banyak serangan AD tidak memakai exploit atau malware sama sekali. Mereka menyalahgunakan **fitur yang memang dirancang begitu**: Kerberos yang menerbitkan tiket, replikasi antar Domain Controller, properti objek yang bisa dibaca semua user. Akibatnya, serangan-serangan ini berbaur dengan aktivitas sah dan sulit dilihat kalau kita tidak tahu persis apa yang dicari.

Tulisan ini membahas tiga serangan AD yang paling sering muncul di laporan insiden, dari sudut pandang defender: bagaimana cara kerjanya, kenapa sulit dideteksi, dan indikator realistis yang benar-benar bisa dipakai. Tiga ini dipilih karena mewakili tiga pola berbeda, yaitu menyalahgunakan penerbitan tiket (Kerberoasting), menyalahgunakan tiket tanpa pre-authentication (AS-REP Roasting), dan menyamar sebagai Domain Controller (DCSync).

---

## Tantangan Umum: Sinyal Tenggelam di Lautan Normal

Sebelum masuk ke tiap serangan, ada satu kenyataan yang membentuk seluruh strategi deteksi AD. Event yang dihasilkan serangan-serangan ini, terutama event Kerberos seperti 4768 dan 4769, juga dihasilkan ribuan kali setiap hari oleh aktivitas yang sepenuhnya sah. Setiap kali user mengakses sebuah service, sebuah tiket diminta. Jadi memicu alert pada keberadaan event itu saja akan menghasilkan banjir false positive.

Kuncinya bukan mendeteksi event-nya, melainkan mendeteksi **atribut yang janggal di dalam event** atau **anomali volume dan pola**. Inilah benang merah ketiga deteksi di bawah, dan sebenarnya hampir semua deteksi AD yang baik.

---

## Kerberoasting: Mengincar Password Service Account

### Cara kerjanya

Akun service di AD sering ditandai dengan Service Principal Name (SPN). Setiap user terautentikasi boleh meminta service ticket (TGS) untuk akun ber-SPN, dan tiket itu dienkripsi dengan hash password akun service tersebut. Di sinilah celahnya: penyerang meminta tiket itu, lalu meng-crack-nya offline tanpa menyentuh jaringan lagi. Kalau password service lemah, ia akan jebol. Berhasil tidaknya murni bergantung pada kekuatan password akun service.

### Kenapa sulit dideteksi

Permintaan TGS adalah operasi paling lumrah di AD. Event 4769 yang menandainya muncul terus-menerus, jadi tidak mungkin dipakai mentah-mentah.

### Indikator realistis

Ada dua sinyal yang membuat Kerberoasting menonjol:

1. **Tipe enkripsi RC4.** Penyerang sengaja meminta tiket dengan enkripsi RC4 (kode `0x17`) karena jauh lebih cepat di-crack daripada AES. Di lingkungan modern yang sudah AES, permintaan RC4 sudah merupakan anomali. Maka alert pada Event 4769 yang bertipe enkripsi RC4 sangat berguna, justru karena RC4 bukan default lagi.
2. **Volume per user.** Tool seperti Rubeus mengambil tiket untuk banyak akun ber-SPN sekaligus. Satu user yang menghasilkan, misalnya, lebih dari sepuluh permintaan tiket dalam satu menit adalah pola yang tidak manusiawi. Kelompokkan 4769 per user dan per mesin asal, lalu tandai lonjakan.

### Pertahanan dan honeypot

Pertahanan terkuat adalah menghilangkan akar masalahnya: pakai Group Managed Service Account (gMSA) yang password-nya dirotasi otomatis menjadi 127 karakter acak, sehingga praktis mustahil di-crack. Selain itu, akun honeypot dengan SPN yang tampak sah (misalnya SQL atau IIS), password kuat tapi sengaja dibuat tua, dan sedikit privilege, adalah jebakan murah. Setiap permintaan TGS untuk akun umpan ini patut langsung dicurigai.

---

## AS-REP Roasting: Saudara Tanpa Pre-Authentication

### Cara kerjanya

AS-REP Roasting mirip Kerberoasting, tapi menyasar akun yang punya properti "Do not require Kerberos preauthentication" aktif. Pada akun seperti ini, penyerang bisa meminta material terenkripsi yang berisi turunan hash password user, lalu meng-crack-nya offline. Yang membuatnya lebih berbahaya, serangan ini tidak butuh kredensial valid sama sekali, cukup tahu nama akun yang rentan.

### Kenapa sulit dideteksi

Sama seperti Kerberoasting, event yang dipicu (4768, permintaan TGT) adalah event autentikasi yang volumenya sangat besar.

### Indikator realistis

Fokus pada dua field di dalam Event 4768:

1. **Pre-Authentication Type bernilai 0.** Artinya tiket diminta tanpa pre-authentication, yang persis menjadi syarat serangan ini. Tool seperti Rubeus menghasilkan tipe ini.
2. **Tipe enkripsi RC4 (`0x17`).** Sama seperti Kerberoasting, ini default tool penyerang dan menonjol di lingkungan AES.

Korelasikan juga dengan lokasi atau VLAN asal login, karena akun yang rentan ini sering adalah user biasa yang password-nya lebih lemah daripada service account.

### Pertahanan

Aktifkan properti "tanpa pre-authentication" hanya jika benar-benar perlu, dan tinjau daftarnya secara berkala. Karena akun yang terdampak biasanya user biasa, berikan kebijakan password yang lebih ketat (minimal 20 karakter) untuk mereka. Catatan untuk honeypot: hati-hati jika akun umpan menjadi satu-satunya akun dengan pre-auth dimatikan, karena justru jadi terlalu mencolok bagi penyerang yang teliti.

---

## DCSync: Menyamar Sebagai Domain Controller

### Cara kerjanya

DCSync adalah serangan yang berbeda kelas. Penyerang yang sudah punya hak tinggi menyamar sebagai Domain Controller dan meminta replikasi data direktori dari DC asli. Lewat operasi ini ia bisa mengekstrak hash password akun mana pun di domain, termasuk akun krbtgt yang merupakan kunci untuk Golden Ticket. Serangan ini menyalahgunakan permission "Replicating Directory Changes" dan turunannya.

### Kenapa sulit dicegah

Inilah bagian yang sering mengejutkan: DCSync nyaris tidak bisa dicegah secara bawaan, karena replikasi antar DC adalah operasi yang memang harus berjalan normal. Mematikannya berarti merusak AD itu sendiri. Pencegahan sejati biasanya butuh kontrol pihak ketiga seperti RPC Firewall yang hanya mengizinkan replikasi dari DC yang sah.

### Indikator realistis

Karena tidak bisa dicegah, deteksi menjadi sangat penting. DCSync memicu **Event 4662** (akses objek direktori). Tapi sekali lagi, jangan alert pada keberadaan event itu saja. Kuncinya ada pada dua hal:

1. **GUID hak replikasi.** Pastikan event memuat GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` atau `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, yang merupakan hak Replicating Directory Changes. Ini menyaring 4662 yang tidak relevan.
2. **Pelaku yang bukan DC.** Replikasi yang sah hanya dilakukan antar akun Domain Controller. Jadi jika pemicu event ini adalah akun user biasa, itu adalah tanda kuat kompromi. Whitelist sistem sah yang memang melakukan replikasi mirip, seperti Azure AD Connect, agar tidak jadi false positive.

Satu peringatan penting dari lapangan: jika DCSync dilakukan lewat NTLM relay (bukan dari sesi terkompromi langsung), Event 4662 bisa **tidak muncul**. Dalam kasus itu, yang tersisa adalah logon sukses untuk DC yang berasal dari IP mesin yang bukan DC. Maka korelasi logon dari server inti ke daftar IP yang dikenal tetap menjadi jaring pengaman.

---

## Pola Pertahanan yang Berlaku Lintas Serangan

Tiga serangan di atas, dan sebagian besar serangan AD lain, dilawan dengan beberapa prinsip yang sama:

- **Korelasi perilaku login.** Banyak serangan baru terlihat saat tiket atau kredensial curian dipakai. Login akun privileged dari mesin yang tidak biasa adalah sinyal lintas-serangan yang kuat.
- **Privileged Access Workstation (PAW).** Wajibkan semua aktivitas admin lewat mesin khusus, sehingga login admin dari mesin lain langsung mencurigakan.
- **Least privilege dan assessment berkala.** Banyak jalur serangan AD lahir dari delegasi hak yang berlebihan. Memetakan relasi dengan tool seperti BloodHound membantu menemukan jalur eskalasi sebelum penyerang melakukannya.
- **Honeypot yang proporsional.** Akun dan objek umpan sangat efektif, tapi jangan pasang semuanya sekaligus, karena pola yang terlalu rapi justru menyingkap keberadaan jebakan ke penyerang yang teliti.

---

## Kesalahan Umum

**1. Alert pada keberadaan event, bukan atributnya.** Event 4768 dan 4769 muncul ribuan kali sehari. Yang dideteksi adalah RC4, Pre-Auth Type 0, volume janggal, atau GUID replikasi, bukan event itu sendiri.

**2. Mengira DCSync bisa dicegah dengan setting bawaan.** Replikasi adalah operasi normal. Fokuslah pada deteksi 4662 yang tepat, bukan mencari tombol "matikan".

**3. Lupa kasus NTLM relay pada DCSync.** Relay bisa membuat 4662 tidak muncul. Sandingkan dengan korelasi logon berbasis IP.

**4. Mengabaikan tipe enkripsi.** RC4 di lingkungan yang seharusnya AES adalah salah satu sinyal termurah dan paling andal untuk serangan Kerberos.

**5. Memasang semua honeypot sekaligus.** Pola jebakan yang terlalu seragam mudah dikenali penyerang canggih.

---

## Kartu Referensi Cepat

| Serangan | Event ID kunci | Sinyal yang dicari |
|----------|----------------|--------------------|
| Kerberoasting | 4769 | Tipe enkripsi RC4 (0x17), volume tinggi per user/menit |
| AS-REP Roasting | 4768 | Pre-Auth Type = 0, enkripsi RC4 |
| DCSync | 4662 | GUID replikasi 1131f6aa.../1131f6ad..., pelaku bukan DC |
| DCSync via relay | 4624 | Logon DC dari IP yang bukan DC (4662 bisa hilang) |
| Honeypot (login gagal) | 4625, 4771, 4776 | Percobaan autentikasi ke akun umpan |

Pegangan akhir: serangan AD sulit dideteksi bukan karena rumit, tapi karena menyamar sebagai operasi yang sah. Kunci pertahanannya adalah berhenti mencari "event jahat" dan mulai mencari atribut serta pola yang janggal di dalam event yang tampak normal. Padukan itu dengan korelasi perilaku login dan least privilege, dan mayoritas jalur serangan AD jadi jauh lebih terang.

---

## Referensi

- [MITRE ATT&CK: Steal or Forge Kerberos Tickets, Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE ATT&CK: AS-REP Roasting (T1558.004)](https://attack.mitre.org/techniques/T1558/004/)
- [MITRE ATT&CK: OS Credential Dumping: DCSync (T1003.006)](https://attack.mitre.org/techniques/T1003/006/)
- [Microsoft: Audit Kerberos Service Ticket Operations (Event 4769)](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [Microsoft: Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
