# Investigasi dengan Splunk: Query SPL yang Wajib Dikuasai Analis SOC

## Kenapa Ini Penting

Splunk sering disalahpahami sebagai "kotak pencarian raksasa". Analis baru mengetik kata kunci, dapat ribuan baris, lalu kewalahan. Padahal kekuatan Splunk bukan pada mencari, melainkan pada **memproses**: menyaring lautan event menjadi satu tabel yang menjawab pertanyaan spesifik. Itu pekerjaan Search Processing Language (SPL).

Tulisan ini bukan daftar lengkap command SPL (ada lebih dari seratus). Ini kumpulan pola yang benar-benar dipakai saat investigasi, plus cara berpikir yang jauh lebih penting daripada hafal sintaks: bagaimana mengubah sebuah hipotesis menjadi query yang menyempit langkah demi langkah. Begitu pola ini masuk ke kepala, mayoritas investigasi jadi soal merangkai potongan yang sama dengan urutan berbeda.

---

## Cara Berpikir: Dari Hipotesis ke Query

Investigasi yang baik tidak dimulai dari mengetik command, tapi dari sebuah dugaan. "Ada yang melakukan brute force." "Sebuah proses mengunduh payload." "Akun ini dipakai di tempat yang tidak wajar." Query hanyalah cara membuktikan atau menyangkal dugaan itu.

Pola pikirnya hampir selalu sama: mulai luas, lalu sempitkan. Sebuah pipeline SPL dibaca dari kiri ke kanan, tiap tanda pipe (`|`) meneruskan hasil ke command berikutnya. Jadi kita biasanya:

1. Ambil data yang relevan (indeks, sourcetype, rentang waktu).
2. Saring ke kondisi yang sesuai hipotesis.
3. Agregasi untuk melihat pola (siapa, berapa kali, di mana).
4. Urutkan dan tampilkan agar yang penting muncul di atas.

Satu prinsip efisiensi yang harus tertanam sejak awal: **pencarian yang ditarget ke field jauh lebih cepat daripada pencarian kata kunci bebas**. Contohnya:

```
index="main" *uniwaldo.local*              (lambat, wildcard di kedua sisi)
index="main" ComputerName="*uniwaldo.local" (jauh lebih cepat, menarget satu field)
```

Ini bukan sekadar soal kecepatan. Query yang nantinya dijadikan alert harus ramping, karena ia berjalan berulang kali. Query yang boros bisa membebani SIEM dan justru memperlambat respons.

---

## Fondasi: Menyaring dan Menampilkan

Command `search` bersifat implisit di awal tiap query. Ia mendukung boolean (AND, OR, NOT), operator perbandingan, dan wildcard.

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
```

Setelah data tersaring, beberapa command dasar membentuk tampilan:

- `table` menampilkan field terpilih sebagai tabel: `| table _time, host, Image`
- `fields` memilih atau membuang field (tanda minus membuang): `| fields - User`
- `rename` mengganti nama field agar lebih jelas: `| rename Image as Process`
- `dedup` membuang duplikat berdasarkan field: `| dedup Image`
- `sort` mengurutkan (minus untuk menurun): `| sort - _time`

Ini perkakas paling sering dipakai, dan mayoritas query investigasi diakhiri dengan kombinasi `table` dan `sort` agar hasilnya terbaca.

---

## Jantung Investigasi: stats dan Kerabatnya

Kalau hanya boleh menguasai satu command SPL, kuasai `stats`. Ia meringkas event menjadi tabel per kombinasi unik, dan inilah cara kita melihat pola alih-alih baris mentah.

Pola paling sering: menghitung kejadian per dimensi tertentu.

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
| stats count by ParentImage, Image
```

Query sederhana ini sudah cukup untuk menemukan parent-child yang janggal. Saat hasilnya muncul, anomali seperti `notepad.exe` yang melahirkan `powershell.exe` langsung mencolok, karena pasangan itu tidak pernah wajar.

Ada tiga varian `stats` yang sering tertukar, padahal perannya berbeda:

- **`stats`** mengelompokkan dan meringkas, baris asli hilang diganti ringkasan.
- **`eventstats`** menambahkan kolom agregat ke tiap event tanpa membuang baris. Berguna saat ingin membandingkan tiap event dengan rata-rata keseluruhan.
- **`streamstats`** menghitung agregat berjalan (rolling), cocok untuk membangun baseline dinamis sepanjang waktu.

Sementara `chart` mirip `stats` tapi membuat tiap nilai jadi kolom sendiri, sehingga enak untuk memvisualisasikan tren per waktu.

---

## Menemukan yang Langka: rare dan top

Sebuah heuristik yang ampuh: aktivitas yang sering terjadi cenderung normal, sedangkan yang langka lebih layak dicurigai. SPL punya `top` dan `rare` untuk ini.

```
index="main" | rare limit=20 ParentImage
```

Pola ini sering jadi titik awal threat hunting. Saat memburu credential dumping misalnya, melihat proses mana yang paling jarang membuka handle ke LSASS langsung menyorot kandidat aneh seperti `notepad.exe` atau `rundll32.exe`, di tengah lautan akses yang sah.

Teknik terkait adalah subsearch, yaitu menempatkan satu pencarian di dalam kurung siku untuk dipakai oleh pencarian utama. Contoh klasik: tonjolkan proses langka dengan mengecualikan seratus proses paling umum.

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
NOT [ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
      | top limit=100 Image | fields Image ]
| table _time, Image, CommandLine, User
```

---

## Merangkai Aktivitas: transaction

Sering kali sebuah serangan bukan satu event, melainkan rangkaian. Command `transaction` mengelompokkan event yang berbagi karakteristik menjadi satu kesatuan, sehingga kita bisa melacak aktivitas yang melintasi banyak event.

```
index="main" sourcetype="WinEventLog:Sysmon" (EventCode=1 OR EventCode=3)
| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m
| table Image | dedup Image
```

Query ini mengikat pembuatan proses (Event 1) yang diikuti koneksi jaringan (Event 3) oleh executable yang sama dalam jendela satu menit. Hasilnya: daftar proses yang langsung berkomunikasi keluar setelah dijalankan, pola klasik malware yang menghubungi server C2.

---

## Memperkaya dan Mengekstrak: eval, rex, lookup

Tidak semua informasi tersaji rapi di field. Tiga command ini menutup celah itu.

- **`eval`** membuat atau mendefinisikan ulang field, misalnya menormalkan huruf besar-kecil atau menghitung panjang command line.
- **`rex`** mengekstrak field baru dengan regex. Berguna ketika sesuatu yang penting tidak otomatis terurai, misalnya GUID dari event akses Active Directory. Tambahkan `max_match=0` untuk menangkap semua kemunculan, bukan hanya yang pertama.
- **`lookup`** memperkaya data dengan sumber eksternal seperti CSV, contohnya mencocokkan nama file dengan daftar hash malware yang dikenal.

Contoh `eval` untuk mencari command line yang abnormal panjang, ciri umum perintah terobfuscasi:

```
index="main" sourcetype="WinEventLog:Sysmon" Image=*cmd.exe
| eval len=len(CommandLine)
| table User, len, CommandLine | sort - len
```

---

## Dua Cara Pikir Deteksi: TTP dan Analytics

Saat menyusun deteksi, ada dua pendekatan yang saling melengkapi.

**Berbasis TTP (spot the known).** Mengenali pola yang sudah dikenal sebagai ciri serangan. Contohnya berburu pemakaian binary recon bawaan Windows:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
(Image=*\\whoami.exe OR Image=*\\net.exe OR Image=*\\ipconfig.exe OR Image=*\\netstat.exe)
| stats count by Image, CommandLine | sort - count
```

Atau memvalidasi serangan DCSync, yang terlihat sebagai akses objek Active Directory (Event 4662) dengan Access Mask `0x100` oleh akun yang bukan machine account:

```
index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$
```

Logikanya: DCSync yang sah hanya dilakukan machine account atau SYSTEM, jadi user biasa yang meminta hak replikasi adalah tanda kompromi penuh. Validasi lebih lanjut dengan mencocokkan GUID ke hak `DS-Replication-Get-Changes-All`.

**Berbasis analytics (spot the unusual).** Membangun profil "normal" lalu menandai penyimpangan. Contohnya mendeteksi outlier koneksi jaringan dengan baseline dinamis:

```
index="main" sourcetype="WinEventLog:Sysmon" EventCode=3
| bin _time span=1h
| stats count as NetworkConnections by _time, Image
| streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image
| eval isOutlier=if(NetworkConnections > (avg + (0.5*stdev)), 1, 0)
| search isOutlier=1
```

Kedua pendekatan punya batas. TTP gagal saat penyerang memakai teknik yang belum dikenal. Analytics bisa berisik tanpa tuning. Yang matang memakai keduanya.

---

## Dari Hunting ke Alert: Beda Tujuan, Beda Disiplin

Ada perbedaan penting antara query untuk hunting dan query untuk alert. Hunting boleh longgar dan eksploratif, karena seorang analis sedang membaca hasilnya. Alert berjalan otomatis dan berulang, jadi ia harus tahan banting dan sulit di-bypass.

Contohnya, saat menyaring deteksi shellcode (call stack mengandung region `UNKNOWN`), penyaringan dilakukan bertahap: buang proses yang mengakses dirinya sendiri, lalu proses JIT seperti .NET, lalu region terkait runtime C#, dan seterusnya. Tapi catatan jujurnya, alert semacam ini tetap bisa dielakkan, misalnya penyerang sengaja memuat DLL dengan nama yang lolos filter. Pelajarannya: rancang alert agar tidak runtuh hanya karena penyerang menyisipkan satu string sembarang. Alert yang buruk bukan cuma tidak berguna, ia menghasilkan false positive yang jadi tabir asap bagi serangan asli.

---

## Kesalahan Umum

**1. Mengetik kata kunci tanpa hipotesis.** Tanpa dugaan yang jelas, hasil pencarian hanya jadi tumpukan baris. Mulai dari pertanyaan, bukan dari command.

**2. Wildcard di kedua sisi.** `*kata*` memaksa Splunk memindai semuanya. Targetkan ke field bila bisa.

**3. Berhenti di `search`, lupa agregasi.** Kekuatan SPL ada setelah tanda pipe pertama. `stats`, `rare`, dan `transaction` yang mengubah data jadi cerita.

**4. Menyamakan query hunting dengan query alert.** Alert butuh ketahanan terhadap bypass dan disiplin false positive yang jauh lebih ketat.

**5. Tidak mengenal data sendiri.** Sebelum menulis query, tahu dulu sourcetype dan field apa yang tersedia (`| metadata type=sourcetypes`, `| fieldsummary`). Query terhadap field yang salah eja akan diam-diam mengembalikan kosong.

---

## Kartu Referensi Cepat

| Kebutuhan | Command SPL |
|-----------|-------------|
| Saring data | `search` (implisit), boolean, wildcard |
| Pilih/buang kolom | `fields`, `table` |
| Rapikan tampilan | `rename`, `dedup`, `sort` |
| Lihat pola/hitung | `stats count by ...` |
| Agregat per event | `eventstats` |
| Baseline berjalan | `streamstats` |
| Tren visual | `chart` |
| Temukan yang langka | `rare`, `top` (+ subsearch) |
| Rangkai rangkaian event | `transaction` |
| Buat/ubah field | `eval` |
| Ekstrak via regex | `rex` (`max_match=0`) |
| Perkaya dari CSV | `lookup`, `inputlookup` |
| Kenali data tersedia | `metadata`, `fieldsummary` |

Pegangan akhir: SPL bukan soal menghafal seratus command, tapi soal menguasai sepuluh yang benar dan tahu kapan merangkainya. Mulai dari hipotesis, ambil data seperlunya, agregasi untuk melihat pola, lalu sempitkan sampai yang tersisa adalah jawaban.

---

## Referensi

- [Splunk: Search Reference (daftar command SPL)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Splunk: Search Manual (cara kerja pencarian dan pipeline)](https://docs.splunk.com/Documentation/Splunk/latest/Search/GetstartedwithSearch)
- [MITRE ATT&CK: OS Credential Dumping: DCSync (T1003.006)](https://attack.mitre.org/techniques/T1003/006/)
- [Microsoft Sysinternals: Sysmon (event reference)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK: Enterprise Matrix](https://attack.mitre.org/)
