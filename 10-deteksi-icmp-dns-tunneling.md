# Mendeteksi Covert Channel: ICMP dan DNS Tunneling di Trafik Jaringan

## Kenapa Ini Penting

Sebagian besar kontrol keamanan jaringan fokus pada protokol yang "berbahaya": memblokir port aneh, mengawasi koneksi keluar yang tidak dikenal, menyaring trafik web. Tapi ada dua protokol yang hampir selalu lolos tanpa diperiksa karena dianggap remeh dan esensial: ICMP (ping) dan DNS. Justru karena itu, keduanya jadi kendaraan favorit penyerang untuk membangun covert channel, yaitu saluran tersembunyi untuk menyelundupkan data keluar atau berkomunikasi dengan server command and control.

Idenya sederhana dan licik: kalau firewall mengizinkan ping dan resolusi nama (dan hampir semua mengizinkan), kenapa tidak menyembunyikan data curian di dalamnya. Tulisan ini membahas kenapa tunneling efektif, seperti apa ciri trafik ICMP dan DNS yang janggal, dan bagaimana membedakannya dari trafik yang sah.

---

## Kenapa Tunneling Dipakai

Tunneling menarik bagi penyerang karena tiga alasan yang saling menguatkan.

Pertama, **protokolnya hampir selalu diizinkan**. DNS adalah tulang punggung internet, mematikannya berarti melumpuhkan jaringan. ICMP dipakai untuk diagnostik dasar. Aturan firewall jarang memblokir keduanya, jadi data yang dibungkus di dalamnya bisa lewat tanpa hambatan.

Kedua, **keduanya jarang diinspeksi secara mendalam**. Banyak tim memantau trafik HTTP dan koneksi mencurigakan, tapi mengabaikan isi paket ICMP atau detail query DNS. Sebuah ping dianggap sekadar ping.

Ketiga, **cocok untuk exfiltration dan C2 yang senyap**. Data sensitif bisa dipecah dan diselipkan sedikit demi sedikit, sehingga sulit dikenali sebagai pencurian. Untuk DNS, ada bonus tambahan: teknik seperti Domain Generation Algorithm membuat domain C2 terus berganti, mempersulit pemblokiran berbasis daftar.

Kunci untuk mendeteksinya satu: tunneling memaksa protokol melakukan sesuatu yang **tidak wajar bagi sifat aslinya**. Dan ketidakwajaran itu meninggalkan jejak.

---

## ICMP Tunneling: Ping yang Kegemukan

### Cara kerjanya

ICMP, protokol di balik ping, punya field data di dalam paketnya. Secara normal field ini berisi padding kecil yang tidak berarti. Penyerang menyalahgunakannya dengan menjejalkan data exfiltrasi ke field data tersebut, lalu mengirim rentetan paket ICMP yang dari luar tampak seperti ping biasa.

### Ciri yang janggal

Indikator paling kuat adalah **ukuran data ICMP yang tidak wajar**. Paket ICMP normal membawa data sekitar 48 byte. Paket tunneling bisa membawa ribuan byte, kadang sampai puluhan ribu, untuk memuat data sebanyak mungkin per paket. Ukuran inilah yang membongkar penyamaran.

Di Wireshark, mulai sederhana:

```
icmp
```

Lalu urutkan berdasarkan kolom Length. Paket ICMP yang ukurannya jauh di atas normal langsung menonjol. Buka isinya di pane detail, dan sering kali datanya bisa langsung terbaca: kredensial dalam teks polos, atau string base64 yang tinggal di-decode. Sering pula disertai fragmentation karena data yang besar harus dipecah.

### Mitigasi

Pilihan paling tegas adalah memblokir ICMP sama sekali bila lingkungan tidak membutuhkannya. Bila ping tetap diperlukan, inspeksi atau strip field data pada paket ICMP request dan reply, sehingga tidak ada ruang untuk menyembunyikan muatan.

---

## DNS Tunneling: Pertanyaan yang Menyimpan Rahasia

### Cara kerjanya

DNS tunneling lebih canggih dan lebih sering ditemui. Data diselipkan ke dalam **subdomain** sebuah query atau ke dalam isi **TXT record**. Karena klien terus-menerus mengirim query DNS ke server attacker (yang berperan sebagai name server otoritatif untuk domain tertentu), data mengalir keluar sedikit demi sedikit, terbungkus sebagai resolusi nama yang tampak sah.

TXT record sangat disukai untuk ini karena memang dirancang untuk membawa teks bebas, sehingga lebih lapang untuk menyembunyikan data dibanding record lain.

### Ciri yang janggal

Dua sinyal digabung untuk mengenalinya:

1. **Query yang panjang dan tidak wajar.** Subdomain normal pendek dan bermakna. Subdomain hasil encoding data terlihat panjang, acak, dan sering mengandung karakter base64.
2. **Volume tinggi ke domain yang sama.** Satu host yang mengirim puluhan atau ratusan query ke domain yang sama dalam waktu singkat adalah pola yang tidak manusiawi.

Di Wireshark, filter dasarnya `dns`, lalu perhatikan banyaknya TXT record dari satu host dan panjang query-nya. Sering kali isi yang ter-encode adalah base64 bertingkat (double atau triple), jadi perlu di-decode beberapa kali untuk membongkar isinya. Query yang diakhiri tipe `ANY` dalam jumlah banyak juga menandakan enumerasi DNS, yang sering mendahului tunneling.

### Membedakan dari DNS yang sah

Inilah bagian yang menentukan. DNS yang sah punya ciri: query pendek dan bermakna, ke beragam domain yang dikenal, dengan volume yang wajar mengikuti aktivitas user. DNS tunneling kebalikannya: query panjang dan acak, terkonsentrasi ke satu atau sedikit domain, dengan volume tinggi dan teratur. Saat ragu, gabungkan dua sinyal (panjang query dan volume per domain), karena masing-masing sendirian bisa menipu, tapi keduanya bersamaan jarang salah.

---

## Pola Umum: Membedakan Tunneling dari Banjir Biasa

Satu hal yang sering membingungkan analis: bagaimana membedakan tunneling dari serangan volume lain seperti flooding atau SMURF (yang juga menghasilkan banyak ICMP). Kuncinya, tunneling bertujuan **menyimpan data**, bukan sekadar membanjiri. Maka cirinya bukan hanya volume, tapi:

- **Ukuran atau panjang yang tidak wajar** untuk menampung data.
- **Pola berulang yang terstruktur**, bukan banjir acak.
- **Isi yang ter-encode** (base64 dan turunannya) saat di-follow stream.

Jadi langkah praktisnya: temukan paket dengan ukuran janggal, kenali pola berulangnya, lalu follow stream untuk membuktikan ada data tersembunyi di dalamnya. Flooding tidak menyimpan data bermakna, tunneling menyimpan.

---

## Kesalahan Umum

**1. Menganggap ICMP dan DNS terlalu sepele untuk diperiksa.** Justru karena dianggap remeh, keduanya jadi jalur favorit penyerang.

**2. Hanya melihat volume, bukan isi dan ukuran.** Banyak ICMP bisa berarti flooding. ICMP berukuran raksasa berarti tunneling. Bedanya ada pada ukuran dan isi.

**3. Mengandalkan satu sinyal pada DNS.** Query panjang saja, atau volume tinggi saja, bisa menipu. Gabungkan keduanya.

**4. Lupa men-decode bertingkat.** Data tunneling sering di-encode base64 dua atau tiga lapis. Sekali decode belum tentu menampakkan isinya.

**5. Tidak memantau secara berkala.** Exfiltration lewat tunneling bisa berlangsung perlahan untuk menghindari deteksi. Pemantauan sesaat mudah melewatkannya.

---

## Kartu Referensi Cepat

| Aspek | ICMP Tunneling | DNS Tunneling |
|-------|----------------|---------------|
| Tempat data disembunyikan | Field data paket ICMP | Subdomain query atau TXT record |
| Sinyal utama | Ukuran data jauh di atas ~48 byte | Query panjang/acak + volume tinggi ke satu domain |
| Filter awal | `icmp` (urutkan Length) | `dns` (cek TXT dan ANY) |
| Isi saat dibuka | Teks polos atau base64 | Base64 bertingkat |
| Mitigasi | Blokir atau strip data ICMP | Inspeksi DNS, batasi query keluar, pantau TXT |

Pegangan akhir: covert channel bekerja dengan menyembunyikan data di tempat yang tidak diperiksa orang. Pertahanannya adalah berhenti menganggap ICMP dan DNS sebagai trafik tak berbahaya, dan mulai memperhatikan ketidakwajaran ukuran, panjang, volume, dan isi. Tunneling memaksa protokol melakukan hal yang tidak alami, dan di situlah ia ketahuan.

---

## Referensi

- [MITRE ATT&CK: Protocol Tunneling (T1572)](https://attack.mitre.org/techniques/T1572/)
- [MITRE ATT&CK: Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK: Application Layer Protocol: DNS (T1071.004)](https://attack.mitre.org/techniques/T1071/004/)
- [SANS: Detecting DNS Tunneling](https://www.sans.org/white-papers/34152/)
- [Wireshark: User's Guide (filter dan Follow Stream)](https://www.wireshark.org/docs/wsug_html_chunked/)
