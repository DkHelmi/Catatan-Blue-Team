# Event ID Windows Paling Penting untuk Investigasi SOC

## Kenapa Ini Penting

Saat sebuah alarm berbunyi, Windows Event Log hampir selalu jadi sumber bukti pertama yang dibuka analis. Masalahnya, Windows menghasilkan ribuan event per jam dan mayoritas adalah noise. Yang membedakan investigasi yang cepat dari yang berputar-putar adalah tahu Event ID mana yang benar-benar bercerita, dan yang lebih penting, tahu **field mana di dalamnya** yang harus dibaca.

Kesalahan paling umum yang saya lihat adalah menyaring berdasarkan Event ID saja lalu berhenti. Event 4624 dari domain controller itu normal. Event 4624 yang sama dari workstation acak jam tiga pagi bisa jadi cerita yang sama sekali berbeda. Event ID hanyalah pintu masuk, konteks di dalamnyalah yang menentukan arti. Tulisan ini adalah peta praktis Event ID yang paling sering menyelamatkan investigasi, beserta field yang harus dibaca pada masing-masing.

---

## Titik Awal Hampir Semua Investigasi: Event Autentikasi

Hampir setiap investigasi dimulai dari pertanyaan yang sama: siapa yang login, dari mana, dan bagaimana.

### Event 4624: Logon Sukses

Ini event yang paling sering saya lihat. Tapi tidak semua 4624 sama. Field yang benar-benar menentukan adalah **LogonType**:

| LogonType | Arti | Kenapa peduli |
|-----------|------|---------------|
| 2 | Interactive (konsol) | Seseorang fisik di mesin atau via KVM |
| 3 | Network | Akses SMB, PsExec, WMI remote. Lateral movement hidup di sini |
| 4 | Batch | Eksekusi scheduled task |
| 5 | Service | Akun service memulai |
| 7 | Unlock | Workstation di-unlock |
| 9 | NewCredentials | RunAs dengan /netonly, indikator penyalahgunaan kredensial |
| 10 | RemoteInteractive | Logon RDP |

Yang benar-benar dicari di lapangan:

- **LogonType 3 antar-workstation** (bukan dari server) itu janggal. User biasa tidak melakukan SMB ke mesin satu sama lain. Kalau muncul, selidiki kemungkinan lateral movement.
- **LogonType 10 dari source IP tak terduga** bisa berarti RDP brute force yang berhasil atau kredensial curian.
- **LogonType 9 jarang** muncul di operasi normal. Kalau ada, seseorang memakai `runas /netonly`, teknik yang umum dipakai penyerang yang sudah punya kredensial tapi ingin memakainya tanpa berganti konteks sepenuhnya.

Satu field lagi yang sangat berharga di 4624 adalah **Logon ID**. Nilai ini memungkinkan kita mengkorelasikan satu sesi logon dengan event lain yang berbagi Logon ID yang sama, sehingga kita bisa merangkai apa yang dilakukan sesi itu setelah login.

### Event 4625: Logon Gagal

Banyak 4625 yang diikuti satu 4624 dari sumber yang sama adalah pola klasik brute force yang berhasil. Tapi jangan cuma menghitung kegagalan, baca kode **SubStatus**-nya:

| SubStatus | Arti |
|-----------|------|
| 0xC0000064 | Username tidak ada |
| 0xC000006A | Username benar, password salah |
| 0xC000006E | Account restriction (diblokir policy) |
| 0xC0000234 | Akun terkunci (locked out) |
| 0xC0000072 | Akun dinonaktifkan (disabled) |

Kalau muncul rentetan `0xC0000064` (user tidak ada), seseorang sedang melakukan enumerasi username. Itu reconnaissance, bukan sekadar salah password. Sementara `0xC0000072` (login ke akun disabled) sangat mencurigakan, karena artinya seseorang tahu kredensial dari akun yang sudah dimatikan.

### Event 4648: Logon dengan Explicit Credentials

Sering terlewat, padahal penting. Event ini berarti seseorang secara eksplisit memberikan kredensial yang berbeda dari sesi yang sedang berjalan. Lazim pada pekerjaan admin yang sah (RunAs), tapi juga lazim pada skenario pencurian kredensial saat penyerang memakai kredensial hasil panen.

### Event 4672: Special Privileges ke Logon Baru

Menandai bahwa sebuah logon diberi privilege tingkat tinggi (misalnya SeDebugPrivilege, yang berarti proses bisa mengutak-atik memori proses lain). Pasangan 4624 (khususnya untuk akun istimewa) dengan 4672 layak dipantau ketat.

---

## Eksekusi Proses: Menangkap Aktivitas Jahat

### Event 4688: Process Creation (native)

Ini log pembuatan proses bawaan Windows. Field krusial:

- `NewProcessName`: apa yang dieksekusi
- `ParentProcessName`: apa yang memunculkannya (ini emasnya)
- `CommandLine`: command lengkap dengan argumen (harus diaktifkan via GPO)
- `SubjectUserName`: siapa yang menjalankan

Hubungan parent-child yang harus memicu kecurigaan:

```
winword.exe  -> cmd.exe -> powershell.exe   (eksekusi makro)
outlook.exe  -> powershell.exe              (payload phishing)
winword.exe  -> certutil.exe                (unduh LOLBin via makro)
spoolsv.exe  -> cmd.exe                     (kemungkinan abuse service)
explorer.exe -> mshta.exe                   (eksekusi HTA dari aksi user)
wmiprvse.exe -> powershell.exe              (eksekusi remote via WMI)
```

Parent process memberi tahu bagaimana sesuatu diluncurkan. Sebuah `powershell.exe` sendirian tidak berarti apa-apa. PowerShell yang di-spawn oleh `winword.exe` adalah cerita yang sama sekali berbeda.

### Sysmon Event 1: Process Creation (versi lebih kaya)

Kalau Sysmon terpasang, selalu lebih baik memakai Event ID 1 daripada 4688. Ia memberi field yang tidak ada di 4688:

- `OriginalFileName`: nama asli binary meski sudah di-rename
- `Hashes`: hash file saat eksekusi (bisa dicek di VirusTotal)
- `CurrentDirectory`: dari mana proses berjalan
- `IntegrityLevel`: apakah berjalan dengan privilege tinggi

Binary yang di-rename adalah indikator kuat. Kalau `OriginalFileName` menunjukkan `powershell.exe` tapi `Image` menampilkan `update-service.exe`, itu penyerang yang berusaha menghindari deteksi berbasis nama.

---

## Persistence: Apakah Mereka Berencana Kembali

### Event 7045: Service Diinstal

Instalasi service baru di workstation (bukan di server saat maintenance terjadwal) itu mencurigakan. Periksa:

- `ServiceName`: nama acak atau gibberish adalah tanda bahaya
- `ServiceFileName`: apakah menunjuk ke direktori temp, profil user, atau path tidak standar
- `ServiceType`: kernel driver di workstation hampir selalu buruk
- `ServiceStartType`: auto start berarti persistence

### Event 4698: Scheduled Task Dibuat

Penyerang gemar memakai scheduled task untuk persistence dan eksekusi. Perhatikan `TaskName` (apakah menyamar sebagai task Windows yang sah), command yang dieksekusi, dan kapan dibuat (jam dua pagi, oleh siapa). Event 4702 (task diperbarui) sering jadi pasangannya.

### Event 4907: Perubahan SACL / Audit Policy Objek

Menandai perubahan System Access Control List sebuah objek (file atau registry key). Kalau permission objek diubah untuk memodifikasi apa yang dicatat, itu patut dicurigai sebagai upaya menutupi jejak. Pasangannya yang lebih terang adalah Event 1102 (audit log dibersihkan), yang sering menjadi tanda upaya menghapus bukti.

---

## Indikator Lateral Movement

### Event 5140 dan 5145: Akses Network Share

5140 menandai sebuah share diakses. Saring untuk akses ke `C$`, `ADMIN$`, atau `IPC$` dari workstation, karena ini admin share dan user biasa tidak memakainya. Akses berulang dari satu sumber ke banyak mesin menandakan scanning. Event 5145 lebih granular, menunjukkan file mana yang diakses di share, berguna untuk melacak apa yang benar-benar disentuh penyerang.

### Event Kerberos: 4768, 4769, 4771

Pada lingkungan Active Directory, autentikasi sering lewat Kerberos, bukan logon biasa. 4768 (TGT diminta) dan 4769 (service ticket diminta) adalah dasar untuk mendeteksi serangan seperti Kerberoasting, sedangkan 4771 (pre-authentication gagal) adalah padanan Kerberos dari 4625 untuk brute force. Pola-pola ini dibahas lebih dalam pada artikel deteksi serangan Active Directory.

---

## Membangun Query Deteksi

Berikut contoh dalam Splunk SPL untuk skenario di atas. Anggap ini titik awal, sesuaikan ambang dan pengecualian dengan lingkunganmu.

Deteksi brute force:
```spl
index=windows EventCode=4625
| stats count by TargetUserName, IpAddress, SubStatus
| where count > 10
| sort -count
```

Parent-child mencurigakan:
```spl
index=windows EventCode=4688
| where ParentProcessName LIKE "%winword.exe"
  AND (NewProcessName LIKE "%cmd.exe"
       OR NewProcessName LIKE "%powershell.exe"
       OR NewProcessName LIKE "%certutil.exe")
| table _time, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
```

Instalasi service baru di workstation:
```spl
index=windows EventCode=7045 host!=*server*
| where ServiceStartType="auto start"
| table _time, host, ServiceName, ServiceFileName, ServiceType
```

---

## Kesalahan Umum (yang Juga Pernah Saya Lakukan)

**1. Menyaring hanya berdasarkan Event ID tanpa membaca isi event.** Event 4624 LogonType 3 dari DC itu normal, dari workstation acak tidak. Konteks lebih penting dari Event ID itu sendiri.

**2. Mengabaikan timeline.** Lima login gagal Senin pagi adalah orang yang lupa password. Lima login gagal jam tiga pagi Sabtu dari IP eksternal adalah brute force. Event ID sama, arti berbeda total.

**3. Tidak mengaktifkan Command Line Logging.** Event 4688 tanpa `CommandLine` nyaris tidak berguna untuk investigasi eksekusi. Aktifkan via GPO (`Administrative Templates > System > Audit Process Creation > Include command line in process creation events`) atau pasang Sysmon.

**4. Memperlakukan tiap alert sebagai terisolasi.** Satu 4625 tidak berarti apa-apa. Tapi 4625 lalu 4624 lalu 4648 lalu 5140 dari sumber yang sama dalam sepuluh menit menceritakan sebuah cerita: brute force berhasil, penyerang memakai kredensial baru, lalu mengakses network share. Selalu korelasikan lintas Event ID, dan gunakan Logon ID untuk merangkainya.

---

## Kartu Referensi Cepat

| Skenario | Event ID kunci | Yang dicek |
|----------|----------------|------------|
| Brute force | 4625 lalu 4624 | SubStatus, source IP, timing |
| Lateral movement (SMB) | 4624 (Type 3), 5140, 5145 | Workstation sumber, admin share |
| Lateral movement (RDP) | 4624 (Type 10), 4648 | Source IP, kredensial yang dipakai |
| Eksekusi jahat | 4688 / Sysmon 1 | Parent-child, command line, OriginalFileName |
| Persistence (service) | 7045 | Path service, start type |
| Persistence (schtask) | 4698 / 4702 | Command, jadwal, pembuat |
| Menutupi jejak | 1102, 4907 | Audit log dibersihkan, SACL diubah |
| Privilege tinggi | 4672 | Special privileges ke logon |

Pegangan akhir: jangan baca Event ID sebagai fakta tunggal, baca sebagai potongan cerita. Kekuatan investigasi Windows Event Log ada pada korelasi antar event dan pada disiplin membaca field di dalamnya, bukan pada menghafal angka.

---

## Referensi

- [Microsoft: Security auditing overview](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Microsoft: Audit logon events dan tabel Logon Type](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events)
- [MITRE ATT&CK: Data Sources (Windows event logging)](https://attack.mitre.org/datasources/)
- [Microsoft Sysinternals: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SANS: Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/)
