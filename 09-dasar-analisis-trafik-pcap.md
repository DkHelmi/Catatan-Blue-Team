# Dasar Analisis Trafik Jaringan: Membaca PCAP seperti Analis Keamanan

## Kenapa Ini Penting

Membuka sebuah file PCAP untuk pertama kali sering terasa seperti menatap air bah. Ribuan paket mengalir, penuh protokol, port, dan flag yang tidak jelas mana yang penting. Analis baru cenderung melakukan dua kesalahan: men-scroll tanpa arah berharap menemukan sesuatu yang "kelihatan jahat", atau langsung tenggelam di detail satu paket tanpa konteks. Keduanya membuang waktu.

Analis yang berpengalaman membaca PCAP dengan cara berbeda. Mereka mulai dari pertanyaan, menyaring agresif untuk membuang noise, lalu mengikuti benang dari satu paket menuju cerita utuh. Trafik jaringan adalah salah satu sumber bukti paling jujur yang kita punya, karena ia merekam apa yang benar-benar terjadi di kawat, bukan apa yang diklaim sebuah log. Tulisan ini membahas cara membacanya secara sistematis.

---

## Fondasi: Tahu Dulu Apa yang Normal

Sebelum menyentuh filter apa pun, ada satu fondasi yang menentukan segalanya: baseline. Mustahil mengenali yang abnormal tanpa tahu yang normal. Dua workstation user yang saling berkomunikasi di port 445 (SMB) atau 8080 itu janggal, karena trafik semacam itu seharusnya antara host dan server, bukan antar workstation. Tapi "janggal" itu hanya terlihat kalau kita paham bahwa di lingkungan ini host-to-host memang tidak wajar.

Maka tiga komponen ini membentuk pondasi analisis yang efektif:

- **Kenali lingkunganmu.** Inventaris aset dan peta jaringan membuat kita bisa mengenali host asing atau komunikasi yang tidak seharusnya ada.
- **Penempatan capture itu kunci.** Tangkap trafik sedekat mungkin ke sumber masalah, supaya tidak kehilangan konteks.
- **Kesabaran.** Sebagian anomali, seperti malware yang menelepon pulang ke C2, mungkin hanya muncul sekali tiap beberapa jam atau hari. Jangan menyerah karena lima menit pertama terlihat bersih.

---

## Alur Kerja: Lima Langkah agar Tidak Tersesat

Analisis trafik yang terstruktur mengikuti alur yang berulang:

1. **Ingest.** Mulai menangkap trafik sesuai penempatan. Kalau sudah tahu yang dicari, pakai capture filter sejak awal.
2. **Reduce noise.** Saring trafik yang tidak relevan, seperti broadcast dan multicast, agar yang tersisa bisa dicerna.
3. **Analyze.** Gali host, protokol, dan flag yang relevan. Pertanyaan pemandu: apakah trafik ini seharusnya terenkripsi tapi malah clear text, apakah ada host yang biasanya tidak saling bicara kini berkomunikasi.
4. **Detect dan alert.** Apakah ada error, device yang tidak merespons, atau pola yang cocok dengan known-bad.
5. **Fix dan monitor.** Setelah perbaikan, terus pantau untuk memastikan masalah benar selesai.

Inti dari langkah dua adalah penyaringan. Di sinilah perbedaan terbesar antara analis yang efektif dan yang kewalahan. Membuang noise lebih dulu membuat sinyal yang penting jadi terlihat.

---

## Dua Jenis Filter yang Sering Tertukar

Ini salah satu sumber kebingungan paling umum bagi pemula, padahal konsepnya sederhana setelah dipahami.

- **Capture filter** diterapkan **sebelum** trafik ditangkap, memakai sintaks BPF (Berkeley Packet Filter). Ia benar-benar **membuang** paket yang tidak cocok, sehingga tidak pernah tersimpan. Hemat disk, tapi data yang terbuang hilang selamanya.
- **Display filter** diterapkan **selama atau sesudah** capture, memakai sintaks khusus Wireshark. Ia hanya mengubah apa yang ditampilkan, **tidak menyentuh file** aslinya. Aman untuk eksplorasi karena bisa diubah-ubah tanpa kehilangan data.

Aturan praktisnya: pakai capture filter saat sudah yakin apa yang dicari dan ingin menghemat ruang, pakai display filter saat sedang menyelidiki dan ingin keleluasaan.

Satu jebakan klasik yang harus diingat: **filter port bukan filter protokol**. Di BPF, `port 80` menampilkan semua trafik di port itu apa pun isinya, sedangkan `tcp port 80` baru memastikan transport-nya. Di Wireshark, `tcp.port == 80` berbeda dari `http`: yang pertama menampilkan apa pun di port 80, yang kedua mencari penanda protokol HTTP yang sebenarnya. Penyerang yang memakai port 80 untuk sesuatu yang bukan HTTP akan lolos kalau kita menyamakan keduanya.

---

## Filter yang Benar-Benar Dipakai

Untuk tcpdump (dan capture filter), sintaks BPF yang paling sering:

```
host 10.10.20.1            (trafik dari atau ke satu host)
src host 10.10.20.1        (hanya sebagai sumber)
net 172.16.0.0/24          (seluruh network)
tcp port 443               (port TCP spesifik)
not icmp                   (negasi)
host x and port 23         (gabungan)
greater 500                (paket lebih besar dari 500 byte, ciri transfer file)
```

Untuk display filter Wireshark, padanannya:

```
ip.addr == 10.10.20.1      (satu host)
ip.src == 10.10.20.1       (hanya sumber)
tcp.port == 443            (port TCP)
http                       (penanda protokol, bukan sekadar port 80)
!udp && !arp               (buang UDP dan ARP, sisakan TCP, untuk fokus)
```

Filter `!udp && !arp` itu sederhana tapi sering jadi langkah pembuka yang ampuh: ia membuang noise broadcast dan langsung menyisakan sesi TCP yang biasanya menyimpan cerita.

---

## Dari Satu Paket ke Cerita Utuh: Follow Stream

Paket tunggal jarang bercerita. Yang bercerita adalah rangkaiannya. Fitur paling berharga di Wireshark untuk ini adalah **Follow TCP Stream**, yang merakit ulang paket-paket TCP menjadi percakapan yang bisa dibaca.

Contoh nyata bagaimana ini bekerja. Bayangkan sebuah PCAP kecil dengan beberapa percakapan. Setelah membuang UDP dan ARP, tersisa satu sesi TCP. Follow stream pada sesi itu menampilkan teks polos: sebuah shell yang berkomunikasi lewat port 4444 (port default reverse shell yang umum dipakai Metasploit, ditulis sebagai indikator), diikuti perintah recon seperti `whoami` dan `ipconfig`, lalu pembuatan akun bernama `hacker` yang ditambahkan ke grup administrators. Tidak ada teardown TCP yang wajar, artinya sesi masih aktif. Dari satu sesi yang tersaring, seluruh narasi serangan terbaca: akses, recon, dan persistence.

Inilah esensi membaca PCAP seperti analis. Bukan menatap paket satu per satu, tapi menyaring sampai tersisa percakapan, lalu merakitnya jadi cerita.

---

## Menarik Bukti: Ekstraksi File

Trafik yang tidak terenkripsi sering membawa file utuh yang bisa ditarik kembali. Wireshark bisa mengekstraknya lewat File, Export Objects (untuk HTTP, SMB, dan lainnya), selama percakapannya tertangkap utuh.

Kasus FTP punya alur baku yang berguna dihafal, karena FTP memakai dua port terpisah:

1. Filter `ftp` untuk melihat sesi FTP.
2. `ftp.request.command` menampilkan perintah di control channel (port 21), tempat username dan password (`USER`, `PASS`) serta nama file terlihat dalam teks polos.
3. `ftp-data` menampilkan data di data channel (port 20), tempat isi file sebenarnya mengalir.
4. Follow stream pada paket data, ubah tampilan ke Raw, simpan dengan nama file asli.

Ingat pasangannya: `ftp.request.command` itu port 21 (kontrol), `ftp-data` itu port 20 (data). Tertukar di sini membuat investigasi mandek.

---

## Saat Trafik Terenkripsi

Tidak semua bisa dibaca langsung. RDP, misalnya, dienkripsi TLS secara default, jadi filter `rdp` awalnya kosong. Trik pertama: verifikasi keberadaannya lewat `tcp.port == 3389`, karena protokolnya ada walau isinya tersembunyi.

Kalau kita memiliki private key RSA server, Wireshark bisa mendekripsi sesinya lewat Preferences, Protocols, TLS, dengan menambahkan key beserta IP dan port server. Setelah itu trafik terbuka dan bisa di-follow seperti biasa. Prinsip ini berlaku untuk protokol terenkripsi apa pun selama kita punya kuncinya. Ini juga pengingat penting: enkripsi melindungi isi, tapi metadata (siapa bicara dengan siapa, kapan, seberapa banyak) tetap terlihat dan sering sudah cukup untuk menemukan anomali.

---

## Kesalahan Umum

**1. Men-scroll tanpa hipotesis.** PCAP besar mustahil dibaca paket per paket. Mulai dari pertanyaan, lalu saring untuk membuktikannya.

**2. Menyamakan port dengan protokol.** `port 80` bukan `http`. Penyerang sengaja memakai port umum untuk hal yang bukan semestinya.

**3. Tidak punya baseline.** Tanpa tahu komunikasi normal, host-to-host yang mencurigakan terlihat biasa saja.

**4. Menyerah terlalu cepat.** Callback C2 bisa berselang jam. Trafik yang terlihat bersih sebentar belum tentu bersih.

**5. Lupa bahwa metadata berbicara.** Walau payload terenkripsi, pola siapa-bicara-dengan-siapa dan volume sering sudah membongkar anomali.

---

## Kartu Referensi Cepat

| Kebutuhan | tcpdump / BPF | Wireshark display |
|-----------|---------------|-------------------|
| Satu host | `host 10.10.20.1` | `ip.addr == 10.10.20.1` |
| Network | `net 172.16.0.0/24` | `ip.addr == 172.16.0.0/24` |
| Port TCP | `tcp port 443` | `tcp.port == 443` |
| Protokol asli | `udp` / `icmp` | `http` / `dns` / `arp` |
| Buang noise | `not arp and not broadcast` | `!udp && !arp` |
| Rakit percakapan | (gabung dengan Wireshark) | Follow TCP Stream / `tcp.stream eq N` |
| Cek protokol terenkripsi | `tcp port 3389` | `tcp.port == 3389` |

Pegangan akhir: membaca PCAP bukan soal menatap setiap paket, tapi soal menyaring sampai tersisa yang berarti, lalu merangkainya jadi cerita. Mulai dari pertanyaan, buang noise, ikuti stream, dan ingat bahwa bahkan trafik terenkripsi pun meninggalkan metadata yang berbicara.

---

## Referensi

- [Wireshark: User's Guide (display filter, Follow Stream, Export Objects)](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark: Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [tcpdump: Manual page (switch dan BPF)](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [SANS: tcpdump cheat sheet](https://www.sans.org/posters/tcpip-and-tcpdump/)
- [MITRE ATT&CK: Application Layer Protocol (C2 di kawat, T1071)](https://attack.mitre.org/techniques/T1071/)
