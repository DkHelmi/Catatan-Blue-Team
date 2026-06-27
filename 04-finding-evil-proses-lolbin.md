# Finding Evil: Mendeteksi Proses Mencurigakan dan LOLBin di Windows

## Kenapa Ini Penting

Artikel sebelumnya membahas Event ID Windows sebagai peta investigasi. Tulisan ini melangkah lebih jauh: bagaimana mengenali proses yang jahat ketika penyerang sengaja berusaha terlihat normal. Penyerang modern jarang membawa malware mencolok. Mereka memakai binary yang sudah ada di Windows, menyuntik kode ke proses yang sah, dan memalsukan jejak agar tool monitoring tertipu. Mendeteksi mereka butuh pergeseran cara pandang, dari "cari file jahat" menjadi "cari perilaku yang janggal".

Kunci dari semua ini satu kata: baseline. Deteksi ancaman bertumpu pada pemahaman apa yang normal di lingkunganmu. Tanpa tahu seperti apa proses yang wajar, mustahil mengenali yang menyimpang. Mari bahas pola-pola penyimpangan yang paling sering dipakai penyerang.

---

## Hubungan Parent-Child yang Janggal

Di Windows yang sehat, proses tertentu tidak pernah memunculkan proses lain. `calc.exe` tidak mungkin men-spawn `cmd.exe`. `spoolsv.exe` (service printer) tidak punya alasan membuat `whoami.exe`. Ketika pola ini muncul, hampir selalu ada yang salah.

Beberapa rantai parent-child yang harus langsung memicu kecurigaan:

```
winword.exe  -> powershell.exe    (makro dokumen menjalankan payload)
outlook.exe  -> cmd.exe           (lampiran phishing dieksekusi)
spoolsv.exe  -> cmd.exe           (service dieksploitasi)
services.exe -> proses tak dikenal di path aneh
```

Referensi pola normal yang berguna adalah mind map process relationship dari komunitas (salah satu yang terkenal disusun Samir Bousseaden). Membandingkan apa yang kamu lihat dengan pohon proses normal adalah cara tercepat mengenali anomali.

### Jebakan: Parent PID Spoofing

Ada satu hal penting yang sering tidak disadari analis. Penyerang bisa **memalsukan parent process**. Dengan teknik Parent PID Spoofing, penyerang membuat sebuah proses seolah-olah dilahirkan oleh proses lain. Akibatnya, Sysmon Event ID 1 bisa keliru menampilkan `spoolsv.exe` sebagai parent dari `cmd.exe`, padahal yang sebenarnya membuatnya adalah `powershell.exe`. Di sinilah Sysmon tertipu.

Solusinya adalah turun ke level kernel lewat Event Tracing for Windows (ETW), khususnya provider `Microsoft-Windows-Kernel-Process`. Provider ini melaporkan parent yang sebenarnya, tidak peduli spoofing di level user. Tool seperti SilkETW bisa menangkap data ini. Pelajarannya umum: jangan pernah menganggap satu sumber telemetri sebagai kebenaran absolut. Ketika sebuah pohon proses terlihat aneh tapi "sah", cek dari sudut lain.

---

## Binary yang Di-rename

Trik klasik penyerang adalah menyalin binary sah lalu mengganti namanya agar tidak mencolok. `powershell.exe` di-rename jadi `update-service.exe`, atau `cmd.exe` jadi sesuatu yang membaur dengan nama proses lain.

Deteksinya bergantung pada satu field emas di Sysmon Event ID 1: `OriginalFileName`. Field ini menyimpan nama asli binary yang tertanam di metadata file, dan tidak ikut berubah saat file di-rename. Kalau `OriginalFileName` menunjukkan `powershell.exe` sementara `Image` menampilkan `update-service.exe`, itu sinyal kuat penyerang sedang menghindari deteksi berbasis nama. Bandingkan keduanya, jangan percaya nama file di permukaan.

Field pendukung lain di Sysmon Event 1 yang memperkuat verdict: `Hashes` (bisa dicocokkan ke threat intelligence), `CurrentDirectory` (binary sistem yang berjalan dari Downloads atau AppData itu janggal), dan `IntegrityLevel`.

---

## LOLBin: Hidup dari Tanah Sendiri

Living off the Land (LotL) adalah strategi memakai tool sah bawaan Windows agar aktivitas tidak mencurigakan. Binary semacam ini disebut LOLBin (Living-off-the-land binaries). Karena mereka ditandatangani Microsoft dan memang ada di setiap Windows, antivirus cenderung mengabaikannya. Beberapa yang paling sering disalahgunakan:

- **certutil.exe**: sebenarnya untuk mengelola sertifikat, tapi dipakai mengunduh file dari internet atau men-decode payload base64.
- **mshta.exe**: menjalankan file HTA, dipakai mengeksekusi script jahat.
- **rundll32.exe**: memuat dan menjalankan DLL, dipakai mengeksekusi kode dari DLL jahat.
- **regsvr32.exe**: mendaftarkan DLL, bisa dipakai menjalankan script remote (teknik "Squiblydoo").
- **msbuild.exe**: utilitas build, dipakai mengeksekusi kode dari file project XML.

Kuncinya bukan memblokir binary ini (mereka dibutuhkan sistem), melainkan memeriksa **konteks pemakaiannya**. `certutil.exe` yang dijalankan oleh dokumen Office, atau `rundll32.exe` tanpa argumen DLL yang wajar, atau `msbuild.exe` yang dipicu browser, semuanya janggal. Command line adalah tempat kebenaran berada, jadi pastikan logging command line aktif.

---

## Injeksi ke Proses yang Sah

Penyerang sering tidak menjalankan proses baru sama sekali. Mereka menyuntikkan kode ke proses yang sudah berjalan agar bersembunyi di balik sesuatu yang tepercaya.

### Unmanaged PowerShell dan .NET Injection

Ada konsep yang berguna di sini. C# dan PowerShell adalah kode managed, artinya butuh runtime .NET (Common Language Runtime, CLR) untuk berjalan. Ketika kode managed dieksekusi, ia memuat DLL khas seperti `clr.dll`, `clrjit.dll`, dan `mscoree.dll`.

Inilah celah deteksinya. Kalau DLL-DLL .NET ini muncul di proses yang **biasanya tidak memerlukannya** (misalnya `spoolsv.exe` tiba-tiba memuat `clr.dll`), itu menandakan kemungkinan injeksi unmanaged PowerShell atau eksekusi .NET assembly di dalam proses tersebut. Pantau lewat Sysmon Event ID 7 (Image Loaded).

### Bring Your Own Land (BYOL)

Seiring pertahanan makin matang, penyerang berevolusi dari sekadar memakai tool sistem menjadi membawa .NET assembly buatan sendiri yang dieksekusi sepenuhnya di memori (istilah Mandiant: Bring Your Own Land). Karena dimuat langsung ke memori tanpa ditulis ke disk, teknik ini meminimalkan artifact dan melewati deteksi berbasis inspeksi file. Contoh nyatanya adalah command `execute-assembly` di Cobalt Strike.

Sysmon Event 7 memberi tahu DLL .NET dimuat, tapi tidak memberi tahu isi assembly-nya. Untuk melihat lebih dalam, termasuk nama method yang dieksekusi, gunakan provider ETW `Microsoft-Windows-DotNETRuntime`. Inilah contoh nyata kenapa Sysmon saja kadang tidak cukup, dan ETW mengisi celahnya.

---

## Credential Dumping: Mengincar LSASS

Salah satu aksi paling berbahaya pasca-kompromi adalah mencuri kredensial dari memori. Proses LSASS (Local Security Authority Subsystem Service) mengelola kredensial user dan menjadi target utama tool seperti Mimikatz.

Untuk mendeteksi, jangan fokus ke pemuatan DLL, melainkan ke **akses proses**, yaitu Sysmon Event ID 10 (ProcessAccess). Tanda-tanda mencurigakan saat sebuah proses mengakses LSASS:

- Proses dengan nama acak dari folder acak (misalnya sebuah executable di Downloads) mengakses LSASS.
- `SourceUser` berbeda dari `TargetUser` (misalnya proses berjalan sebagai user biasa tapi mengakses konteks SYSTEM).
- Proses yang meminta `SeDebugPrivilege`, privilege yang memungkinkan akses ke memori proses lain, menjadi IOC tambahan yang kuat.

Hati-hati, sebagian proses sah memang mengakses LSASS (proses autentikasi, antivirus, EDR), jadi kunci pembedanya tetap pada konteks: siapa yang mengakses, dari mana, dengan privilege apa.

---

## DLL Hijacking

Teknik ini memanfaatkan cara Windows mencari DLL. Penyerang menempatkan DLL jahat dengan nama yang dicari sebuah aplikasi sah, di lokasi yang diperiksa lebih dulu daripada lokasi DLL aslinya. Saat aplikasi berjalan, ia memuat DLL jahat tanpa sadar.

Deteksinya lewat Sysmon Event ID 7, dengan tiga IOC yang kuat:

1. Binary sistem yang berjalan dari lokasi tidak wajar. Misalnya `calc.exe` seharusnya selalu di System32 atau Syswow64. Salinannya di folder yang bisa ditulis user adalah tanda bahaya.
2. DLL sistem yang dimuat dari luar System32. Kalau sebuah DLL yang seharusnya ada di System32 dimuat dari folder lain oleh proses sistem, itu hijack.
3. Status signing. DLL Microsoft yang asli ditandatangani, sedangkan DLL yang disuntikkan penyerang umumnya **unsigned**.

---

## Kesalahan Umum

**1. Percaya satu sumber telemetri.** Sysmon bisa ditipu Parent PID Spoofing. Ketika pohon proses terlihat janggal, verifikasi dengan ETW level kernel.

**2. Memblokir LOLBin alih-alih memantau konteksnya.** Binary ini dibutuhkan sistem. Yang dideteksi adalah pemakaian yang tidak wajar, bukan keberadaannya.

**3. Berhenti di nama file.** Nama bisa di-rename. Selalu bandingkan dengan `OriginalFileName` dan hash.

**4. Tidak punya baseline.** Tanpa tahu apa yang normal di lingkunganmu, semua terlihat mencurigakan atau tidak ada yang terlihat mencurigakan. Bangun baseline lebih dulu.

**5. Mengabaikan command line.** Mayoritas deteksi LOLBin dan injeksi bergantung pada command line. Kalau logging-nya mati, kamu buta.

---

## Kartu Referensi Cepat

| Teknik | Sumber deteksi utama | IOC kunci |
|--------|----------------------|-----------|
| Parent-child janggal | Sysmon 1, ETW Kernel-Process | Pohon proses tak wajar, cek spoofing |
| Binary di-rename | Sysmon 1 | `OriginalFileName` beda dari `Image` |
| LOLBin abuse | Sysmon 1 (+ command line) | certutil/mshta/rundll32 di konteks aneh |
| .NET / PowerShell injection | Sysmon 7, ETW DotNETRuntime | clr.dll/mscoree.dll di proses tak lazim |
| Credential dumping | Sysmon 10 (ProcessAccess) | Akses LSASS, SourceUser != TargetUser, SeDebugPrivilege |
| DLL hijacking | Sysmon 7 | DLL unsigned dari luar System32 |

Pegangan akhir: penyerang yang baik berusaha terlihat normal. Mendeteksi mereka bukan soal mencari yang jelas jahat, tapi soal mengenali yang seharusnya tidak terjadi. Itu hanya mungkin kalau kamu paham betul seperti apa "normal" di lingkunganmu, dan bersedia memverifikasi satu sinyal dengan sinyal lain.

---

## Referensi

- [MITRE ATT&CK: Signed Binary Proxy Execution (LOLBins, T1218)](https://attack.mitre.org/techniques/T1218/)
- [LOLBAS Project: daftar Living-off-the-land binaries](https://lolbas-project.github.io/)
- [MITRE ATT&CK: OS Credential Dumping (LSASS Memory, T1003.001)](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft Sysinternals: Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK: Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/)
