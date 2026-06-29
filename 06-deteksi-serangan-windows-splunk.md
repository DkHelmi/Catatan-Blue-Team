# Mendeteksi Serangan Windows dengan Splunk: Dari Beaconing sampai TTP Attacker

## Kenapa Ini Penting

Artikel sebelumnya membahas SPL sebagai bahasa investigasi. Tulisan ini melangkah ke detection engineering: bukan lagi sekadar mencari jawaban setelah insiden, tapi membangun query yang otomatis memunculkan serangan di tengah lautan log normal, sebelum atau saat serangan terjadi.

Ada satu kabar baik yang jarang disampaikan ke analis baru. Sebagian besar deteksi serangan Windows dan Active Directory, dari beaconing C2 sampai Kerberoasting, sebenarnya merupakan variasi dari **satu pola SPL yang sama**. Begitu pola itu dikuasai, menulis deteksi untuk teknik baru jadi soal mengganti beberapa nilai, bukan memulai dari nol. Tulisan ini membongkar pola itu, lalu menunjukkannya bekerja pada beberapa teknik nyata.

---

## Pola Inti: Binning, Agregasi, Threshold

Hampir semua deteksi serangan otomatis bertumpu pada satu kenyataan: aktivitas sah cenderung jarang dan tidak teratur, sedangkan serangan otomatis menghasilkan banyak event yang seragam dalam jendela waktu sempit. Brute force melempar ratusan percobaan login. Scanner menyentuh puluhan port. Beacon menelepon pulang dengan interval rapi. Semuanya meninggalkan jejak berupa anomali volume dan pola.

SPL menangkap ini dengan tiga langkah yang berulang terus:

```
<filter event yang relevan>
| bin _time span=5m              (kelompokkan per jendela waktu)
| stats count by src, dest       (agregasi: berapa kali, dari mana, ke mana)
| where count > 30               (tandai yang melewati ambang)
```

Ingat tiga langkah ini: **bin** (potong waktu jadi jendela), **stats** (hitung dan kelompokkan), **where** (saring yang abnormal). Hampir setiap contoh di bawah hanyalah pola ini dengan filter dan ambang yang disesuaikan. Yang membedakan deteksi yang baik dari yang berisik bukan kerumitan query, melainkan pemahaman tentang seperti apa volume "normal" di lingkunganmu, yang menentukan ambang yang tepat.

---

## Beaconing: Menangkap C2 dari Iramanya

Beaconing adalah komunikasi periodik malware ke server command and control. Yang khas bukan isinya (sering terenkripsi dan menyamar sebagai trafik web sah), melainkan **keteraturan waktunya**. Sebuah beacon menelepon pulang tiap sekian detik, kadang dengan sedikit variasi acak (jitter) untuk mengaburkan pola.

Karena yang dicari adalah keteraturan interval, deteksinya sedikit berbeda dari pola threshold biasa. Idenya: hitung selisih waktu antar koneksi berurutan, lalu lihat apakah mayoritas selisih itu konsisten.

```
sourcetype="bro:http:json"
| streamstats last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg by src, dest
| eval isRegular = if(timedelta > avg*0.9 AND timedelta < avg*1.1, 1, 0)
| stats sum(isRegular) as regular, count as total by src, dest
| eval prcnt = (regular/total)*100
| where prcnt > 90 AND total > 10
```

Logikanya: kalau lebih dari 90 persen koneksi antara satu sumber dan satu tujuan punya interval yang konsisten (dalam toleransi 10 persen), itu beaconing, bukan perilaku manusia. Cara visual tercepat untuk melihatnya adalah `timechart`, yang langsung menampilkan irama yang terlalu rapi untuk jadi trafik organik.

---

## Brute Force dan Password Spraying

Brute force adalah contoh paling murni dari pola volume. Banyak kegagalan autentikasi dari satu sumber dalam waktu singkat.

Untuk RDP lewat Zeek, pola intinya langsung terlihat:

```
sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) as users by id.orig_h, id.resp_h
| where count > 30
```

Yang menarik, **password spraying** adalah pembalikan halus dari brute force. Alih-alih banyak password ke satu akun (yang memicu lockout), penyerang mencoba sedikit password umum ke banyak akun. Jadi sinyalnya bukan banyak kegagalan per akun, melainkan banyak akun berbeda yang gagal dari satu sumber. SPL menangkapnya dengan `dc()` (distinct count):

```
EventCode=4625
| bin _time span=15m
| stats dc(user) as unique_users, values(user) as users by src
| where unique_users > 10
```

Satu sumber yang gagal login ke sepuluh akun berbeda dalam lima belas menit adalah pola spraying yang khas. Event 4625 adalah tulang punggungnya, dengan dukungan 4768 (Kerberos) dan 4776 (NTLM) tergantung protokol yang dipakai.

---

## Kerberoasting: Anomali di Detail Tiket

Kerberoasting menyalahgunakan cara Kerberos bekerja. Penyerang meminta service ticket untuk akun yang punya Service Principal Name, lalu meng-crack tiket itu secara offline untuk mendapatkan password service. Jejaknya halus, tapi ada satu detail yang sangat menonjol: **tipe enkripsi tiket**.

Penyerang sengaja meminta tiket dengan enkripsi RC4 (kode `0x17`) karena jauh lebih mudah di-crack daripada AES. Di lingkungan modern, RC4 sudah jarang dipakai secara sah, jadi permintaannya sendiri sudah mencurigakan.

Lewat Windows Event Log:

```
EventCode=4769 Ticket_Encryption_Type=0x17
| stats count by Account_Name, Service_Name, src
| where count > 5
```

Atau dari sisi jaringan lewat Zeek, di mana RC4 untuk request TGS adalah indikator downgrade yang sama:

```
sourcetype="bro:kerberos:json" request_type=TGS cipher="rc4-hmac"
```

Ini contoh bagus bahwa deteksi terbaik kadang bukan soal volume, melainkan soal mengenali satu atribut yang seharusnya langka.

---

## Lateral Movement: PsExec dan Kerabatnya

Setelah masuk, penyerang bergerak menyamping ke host lain. Salah satu cara klasik adalah pola ala PsExec: transfer payload ke hidden share (`ADMIN$` atau `C$`) lewat SMB, buat service untuk menjalankannya, lalu hapus jejak service.

Dari trafik SMB lewat Zeek:

```
sourcetype="bro:smb_files:json" action="SMB::FILE_OPEN"
name IN ("*.exe","*.dll","*.bat") path IN ("*\\c$","*\\ADMIN$") size>0
| stats count by source_ip, dest_ip, name
```

Yang menarik dari sisi detection engineering adalah bagaimana penyerang beradaptasi. Varian seperti SharpNoPSExec menghindari pembuatan service baru (yang gampang terdeteksi) dengan membajak service idle yang sudah ada lewat DCE/RPC. Maka deteksinya pun bergeser, dari memantau pembuatan service ke memantau operasi `change_service_config` di log `bro:dce_rpc:json`. Pelajarannya: deteksi bukan artefak statis, ia harus ikut berevolusi mengejar adaptasi penyerang.

---

## Exfiltration: Volume Keluar yang Janggal

Pencurian data meninggalkan jejak berupa volume keluar yang tidak wajar. Untuk exfiltration lewat HTTP, datanya ada di body POST:

```
sourcetype="bro:http:json" method=POST
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| sort - TotalBytes
```

Untuk HTTPS yang terenkripsi, kita tidak bisa lihat isinya, jadi bertumpu pada ukuran koneksi (`orig_bytes`) ke port 443. Sedangkan exfiltration lewat DNS menyembunyikan data di subdomain query, sehingga digabung dua sinyal: query yang **panjang** (data ter-encode) dan **volume tinggi** ke domain yang sama.

```
sourcetype="bro:dns:json"
| eval len_query = len(query)
| search len_query >= 40
| bin _time span=24h
| stats count(query) as req_by_day by id.orig_h, id.resp_h
| where req_by_day > 60
```

Sekali lagi, ini pola yang sama: filter, agregasi, threshold. Yang berubah hanya sinyal apa yang dihitung.

---

## Dua Sumber Data, Dua Sudut Pandang

Satu kerangka mental yang berguna: serangan bisa dilihat dari endpoint atau dari jaringan, dan keduanya saling menutup celah.

- **Windows Event Log dan Sysmon** memberi sudut pandang host. Bagus untuk teknik yang meninggalkan jejak di endpoint: Pass-the-Hash (Event 4624 LogonType 9 dipadu Sysmon 10 akses LSASS), DCSync (Event 4662 dengan GUID hak replikasi oleh akun yang bukan DC), atau eksekusi mencurigakan.
- **Zeek network log** memberi sudut pandang kawat. Bagus untuk teknik yang terlihat di trafik bahkan saat logging endpoint kurang: brute force, beaconing, scanning, Zerologon (ratusan operasi Netlogon dalam semenit lewat DCE/RPC).

Penyerang yang menutup satu sumber sering masih terlihat di sumber lain. Inilah kenapa korelasi lintas sumber, yang menjadi alasan keberadaan SIEM, begitu penting.

---

## Kesalahan Umum

**1. Menetapkan ambang tanpa baseline.** Ambang `count > 30` yang bagus di satu lingkungan bisa banjir false positive di lingkungan lain. Ukur dulu volume normalmu, baru tetapkan ambang.

**2. Mengandalkan satu sumber data.** Endpoint log bisa dimatikan penyerang. Selalu sandingkan dengan visibilitas jaringan.

**3. Membuat deteksi statis.** Penyerang beradaptasi (PsExec jadi SharpNoPSExec). Deteksi harus ditinjau dan diperbarui mengikuti teknik baru.

**4. Mengejar isi, bukan pola.** Beacon C2 sering terenkripsi. Yang menangkapnya adalah irama waktunya, bukan payload-nya.

**5. Lupa memetakan ke MITRE ATT&CK.** Tanpa peta teknik, mudah punya deteksi menumpuk di satu taktik dan buta di taktik lain. Pemetaan membantu melihat lubang cakupan.

---

## Kartu Referensi Cepat

| Serangan | Sinyal kunci | Sumber |
|----------|--------------|--------|
| Beaconing C2 | Interval koneksi terlalu konsisten | bro:http / conn |
| RDP/SSH brute force | Banyak percobaan dari satu sumber | bro:rdp / ssh |
| Password spraying | Banyak akun gagal dari satu sumber | Event 4625 |
| Kerberoasting | Tiket RC4 (0x17) untuk akun SPN | Event 4769 / bro:kerberos |
| Pass-the-Hash | Logon Type 9 + akses LSASS | Event 4624 + Sysmon 10 |
| Lateral movement (PsExec) | Payload ke ADMIN$/C$ via SMB | bro:smb_files |
| DCSync | Event 4662 GUID replikasi oleh non-DC | Windows Security |
| Zerologon | Ratusan operasi Netlogon per menit | bro:dce_rpc |
| Exfiltration DNS | Query panjang + volume tinggi | bro:dns |

Pegangan akhir: deteksi serangan di Splunk bukan soal menghafal ratusan query, tapi soal menguasai satu pola (bin, stats, where) dan paham sinyal apa yang membedakan tiap teknik. Kuasai polanya, kenali lingkunganmu untuk menyetel ambang, lalu sandingkan sudut pandang host dan jaringan.

---

## Referensi

- [MITRE ATT&CK: Enterprise Matrix (pemetaan teknik)](https://attack.mitre.org/matrices/enterprise/)
- [Splunk: Search Reference (streamstats, eventstats, bin)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Zeek: Logs dan protokol (kerberos, smb, dce_rpc, dns)](https://docs.zeek.org/en/master/logs/index.html)
- [MITRE ATT&CK: Application Layer Protocol (C2 beaconing, T1071)](https://attack.mitre.org/techniques/T1071/)
- [Microsoft: CVE-2020-1472 (Zerologon) Netlogon elevation](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472)
