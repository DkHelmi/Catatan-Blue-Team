# Serangan Layer 2 di Jaringan: Deteksi ARP Spoofing dan Evil Twin

## Kenapa Ini Penting

Sebagian besar perhatian keamanan tertuju ke layer atas: aplikasi web, malware, kredensial. Tapi ada kelas serangan yang bekerja di fondasi paling bawah jaringan, di Layer 2 (data link), tempat host saling menemukan satu sama lain sebelum protokol apa pun di atasnya berjalan. Serangan di sini berbahaya justru karena tak kasat mata di layer atas: korban merasa terhubung ke gateway atau access point yang benar, padahal seluruh trafiknya sedang dibajak.

Dua serangan Layer 2 yang paling sering ditemui adalah ARP spoofing (di jaringan kabel) dan Evil Twin (di jaringan nirkabel). Keduanya berujung sama: man-in-the-middle, posisi di mana penyerang bisa membaca, mengubah, atau memutus trafik korban. Tulisan ini membahas cara kerjanya dan indikator konkret yang muncul di capture.

---

## ARP Spoofing: Meracuni Peta Jaringan Lokal

### Cara kerja ARP yang normal

Untuk berkomunikasi dalam satu jaringan lokal, sebuah host perlu tahu MAC address dari IP tujuan. Mekanismenya sederhana dan, sayangnya, tanpa autentikasi: host menyiarkan ARP request "siapa yang punya IP ini?", pemilik IP membalas dengan ARP reply berisi MAC-nya, dan host menyimpannya di ARP cache. Tidak ada verifikasi bahwa yang menjawab benar-benar pemilik sah IP itu.

### Cara serangannya

Penyerang mengeksploitasi ketiadaan autentikasi itu. Ia mengirim ARP reply palsu ke korban (mengaku bahwa MAC gateway adalah MAC penyerang) dan ke gateway (mengaku bahwa MAC korban adalah MAC penyerang). Akibatnya, kedua cache teracuni, dan seluruh trafik korban mengalir lewat mesin penyerang.

Dari sini ada dua kemungkinan. Jika penyerang tidak meneruskan trafik, koneksi korban putus total (denial of service). Jika penyerang meneruskannya, ia menjadi man-in-the-middle yang bisa menguping dan memanipulasi, sering dilanjutkan ke serangan seperti DNS spoofing atau SSL stripping.

### Indikator di capture

Tanda paling kuat dan paling mudah dikenali: **satu IP address yang dipetakan ke dua MAC address berbeda**. Dalam kondisi normal, satu IP punya satu MAC. Kemunculan dua MAC untuk satu IP adalah red flag utama. Indikator lain adalah satu host yang membanjiri jaringan dengan ARP reply terus-menerus.

Filter Wireshark yang berguna:

```
arp.duplicate-address-detected && arp.opcode == 2
```

Ini langsung menyorot ARP reply yang menimbulkan konflik alamat. Untuk menelusuri lebih jauh, kita bisa melacak IP mana saja yang pernah dikaitkan dengan sebuah MAC mencurigakan, atau memeriksa trafik antara dua MAC yang dicurigai. Validasi di host korban bisa dilakukan dengan melihat ARP table-nya: bila MAC penyerang muncul untuk IP gateway, peracunan terkonfirmasi.

Cara membedakan tujuan serangan: bila koneksi TCP korban terus putus, penyerang tidak meneruskan trafik (DoS). Bila terlihat transmisi simetris korban ke penyerang lalu ke gateway, MITM sedang aktif.

### Pendekatan terkait: ARP scanning

Sebelum meracuni, penyerang sering memetakan jaringan dulu lewat ARP scanning. Cirinya: ARP request broadcast ke IP yang berurutan (.1, .2, .3, dan seterusnya) atau ke host yang tidak ada, dengan volume tidak wajar dari satu sumber. Ini pola khas scanner. Filter `arp.opcode == 1` menampilkan semua request untuk memeriksanya.

### Mitigasi

Pertahanan utamanya bekerja di infrastruktur: **static ARP entries** untuk host kritis (sehingga cache tidak bisa ditimpa), dan **port security** di switch yang membatasi MAC per port serta fitur seperti Dynamic ARP Inspection.

---

## Evil Twin dan Rogue AP: Jebakan di Udara

Di jaringan nirkabel, serangan Layer 2 mengambil bentuk lain. Penting membedakan dua istilah yang sering tertukar.

- **Rogue AP** adalah access point tidak sah yang **terhubung ke jaringan internal kita**, misalnya seseorang menancapkan AP murah atau mengaktifkan tethering untuk membypass kontrol perimeter. Bahayanya, ia membuka pintu belakang ke jaringan.
- **Evil Twin** adalah access point yang berdiri sendiri, **tidak terhubung ke jaringan kita**, tapi menyiarkan nama jaringan (ESSID) yang sama dengan AP sah. Tujuannya menipu korban agar terhubung kepadanya, lalu melakukan man-in-the-middle atau memanen kredensial lewat halaman login palsu.

### Cara kerja Evil Twin

Penyerang menyiarkan ESSID yang identik dengan jaringan asli, sering dengan sinyal lebih kuat agar perangkat korban memilihnya. Begitu korban terhubung, seluruh trafiknya melewati penyerang. Karena Evil Twin sering dibuat tanpa enkripsi (open), trafik korban bahkan bisa terlihat dalam teks polos.

### Indikator di capture

Mendeteksi ini butuh menangkap frame manajemen nirkabel, yang memerlukan interface dalam monitor mode. Sinyal kuncinya ditemukan dengan membandingkan **beacon frame**:

```
wlan.fc.type == 00 && wlan.fc.type_subtype == 8
```

Filter ini menampilkan beacon frame (frame manajemen tipe 0, subtype 8) yang disiarkan tiap AP. Saat ada dua BSSID berbeda menyiarkan ESSID yang sama, kecurigaan muncul. Pembeda yang menentukan adalah **informasi keamanan (RSN)** dan **vendor-specific info**: AP palsu sering punya RSN yang berbeda atau hilang (misalnya satu open tanpa enkripsi sementara yang asli WPA2), atau informasi vendor yang tidak konsisten.

Untuk respons insiden, setelah Evil Twin teridentifikasi, catat MAC dan hostname korban yang terhubung kepadanya (terlihat dengan memfilter pada BSSID si Evil Twin), lalu reset kredensial mereka karena bisa jadi sudah terpanen.

### Serangan pendukung: Deauthentication

Evil Twin sering dibantu serangan deauthentication, yaitu penyerang memalsukan frame deauth seolah dari AP sah untuk memutus korban, memaksanya terhubung ulang (idealnya ke Evil Twin) atau untuk menangkap handshake. Cirinya: frame manajemen subtype 12 dalam jumlah banyak. Tool umum memakai reason code 7, walau penyerang canggih mengganti-ganti reason code untuk mengelabui sistem deteksi nirkabel.

### Mitigasi

Untuk rogue AP, deteksi dengan memeriksa daftar perangkat di jaringan dan memindai sinyal Wi-Fi sekitar untuk SSID asing. Untuk Evil Twin dan deauth, pertahanan teknisnya adalah **802.11w (Management Frame Protection)** yang melindungi frame manajemen dari pemalsuan, serta **WPA3-SAE**, dipadu penyetelan sistem deteksi intrusi nirkabel.

---

## Kesalahan Umum

**1. Mengabaikan Layer 2 karena fokus ke layer atas.** Serangan di sini tak terlihat di log aplikasi, padahal bisa membajak semua trafik di atasnya.

**2. Tidak mengenali pola satu-IP-dua-MAC.** Ini indikator ARP spoofing yang paling jelas, tapi mudah terlewat tanpa filter yang tepat.

**3. Menyamakan rogue AP dengan Evil Twin.** Rogue AP terhubung ke jaringan kita (pintu belakang), Evil Twin berdiri sendiri meniru ESSID (jebakan). Responsnya berbeda.

**4. Lupa bahwa monitor mode diperlukan.** Tanpa interface dalam monitor mode, frame manajemen nirkabel tidak akan tertangkap, dan Evil Twin tidak terlihat.

**5. Hanya memblokir, tanpa mitigasi infrastruktur.** ARP spoofing dilawan dengan static ARP dan port security, Evil Twin dengan 802.11w dan WPA3. Tanpa kontrol ini, deteksi saja tidak menutup celah.

---

## Kartu Referensi Cepat

| Serangan | Indikator kunci | Filter Wireshark |
|----------|-----------------|------------------|
| ARP spoofing | Satu IP, dua MAC berbeda | `arp.duplicate-address-detected && arp.opcode == 2` |
| ARP scanning | Request ke IP berurutan, volume tinggi | `arp.opcode == 1` |
| Evil Twin | Dua BSSID, ESSID sama, RSN/vendor beda | `wlan.fc.type==00 && wlan.fc.type_subtype==8` |
| Deauth attack | Banyak frame deauth (reason code 7) | `wlan.fc.type==00 && wlan.fc.type_subtype==12` |

Pegangan akhir: serangan Layer 2 berbahaya karena bekerja di bawah radar layer aplikasi. Korban yakin terhubung ke gateway atau AP yang benar, padahal sedang dibajak. Mendeteksinya berarti turun ke level ARP dan frame nirkabel, mengenali ketidakkonsistenan pemetaan IP ke MAC dan ESSID yang dipalsukan, lalu menutup celahnya dengan kontrol di infrastruktur, bukan sekadar memantau.

---

## Referensi

- [MITRE ATT&CK: Adversary-in-the-Middle: ARP Cache Poisoning (T1557.002)](https://attack.mitre.org/techniques/T1557/002/)
- [MITRE ATT&CK: Adversary-in-the-Middle (T1557)](https://attack.mitre.org/techniques/T1557/)
- [Wireshark: WLAN (IEEE 802.11) capture setup dan monitor mode](https://wiki.wireshark.org/CaptureSetup/WLAN)
- [Cisco: Dynamic ARP Inspection dan Port Security](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-6500-series-switches/72846-layer2-secftrs-catl3fixed.html)
- [Wi-Fi Alliance: WPA3 dan Protected Management Frames](https://www.wi-fi.org/discover-wi-fi/security)
