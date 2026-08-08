# Sigma Rule untuk Analis SOC: Satu Format Deteksi Lintas SIEM

## Kenapa Ini Penting

Setiap SIEM punya bahasa query sendiri. Splunk pakai SPL, Elastic pakai sintaksnya sendiri, QRadar lain lagi. Akibatnya, ketika sebuah teknik serangan baru ditemukan dan komunitas ingin berbagi deteksi, muncul masalah: deteksi yang ditulis untuk satu SIEM tidak bisa langsung dipakai di SIEM lain. Setiap tim harus menulis ulang dari nol.

Sigma menyelesaikan ini. Ia adalah format generik dan vendor-agnostic untuk mendeskripsikan deteksi berbasis log, ditulis dalam YAML, lalu dikonversi ke query SIEM apa pun. Filosofinya sering disebut "tulis sekali, jalankan di mana saja". Bagi analis SOC, Sigma adalah cara berbagi dan menerapkan deteksi tanpa terkunci pada satu vendor, sekaligus pondasi dari pendekatan detection as code. Tulisan ini membahas kenapa Sigma penting, strukturnya, cara mengonversinya, dan kaitannya dengan MITRE ATT&CK.

---

## Posisi Sigma di Antara YARA dan SIEM

Untuk menempatkan Sigma dengan benar: bila YARA mendeteksi pola pada isi file dan memori, Sigma mendeteksi pola pada **event log**. Ia tidak memindai file, melainkan mendeskripsikan seperti apa rupa aktivitas jahat di dalam log, lalu deskripsi itu diterjemahkan menjadi query yang dijalankan SIEM terhadap log yang sudah terkumpul. Keunggulan utamanya adalah portabilitas: satu rule Sigma bisa menjadi query Splunk, query Elastic, atau perintah PowerShell, tergantung backend yang dipilih.

---

## Anatomi Sebuah Rule

Rule Sigma ditulis dalam YAML dan punya struktur yang konsisten. Contoh sederhana:

```yaml
title: Mshta Spawned by Svchost
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
status: test
description: Mendeteksi mshta.exe yang dilahirkan oleh svchost.exe
references:
    - https://attack.mitre.org/techniques/T1218/005/
author: analis
date: 2026/06/27
tags:
    - attack.defense_evasion
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\mshta.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```

Komponen pentingnya:

- **Metadata**: `title`, `id` (UUID unik), `status`, `description`, `references`, `author`, `date`. Bagian ini mendokumentasikan dan melacak rule.
- **logsource**: menentukan sumber log, lewat tiga atribut. `category` (misalnya `process_creation`, `firewall`, `web`), `product` (misalnya `windows`, `apache`), dan `service` (subset yang lebih spesifik seperti `sshd` atau `security`).
- **detection**: jantung rule, berisi satu atau lebih search identifier (sering dinamai `selection`) dan sebuah `condition` yang merangkainya.
- **falsepositives** dan **level**: dokumentasi kemungkinan alarm palsu dan tingkat keparahan, dari informational sampai critical.

---

## Logika Deteksi: Map, List, dan Modifier

Bagian detection punya aturan yang perlu dipahami agar rule berperilaku sesuai harapan.

Sebuah **map** (pasangan field dan value) menggabungkan kondisinya dengan AND, jadi semua harus terpenuhi. Sebuah **list of strings** digabung dengan OR, cukup salah satu cocok. Memahami ini menentukan apakah rule terlalu ketat atau terlalu longgar.

Untuk membuat pencocokan fleksibel, Sigma punya **value modifier** yang ditulis setelah nama field. Yang paling sering dipakai: `contains` membungkus value dengan wildcard di kedua sisi, `startswith` dan `endswith` menempatkan wildcard di satu sisi, `all` mengubah list dari OR menjadi AND, dan `re` memperlakukan value sebagai regex. Modifier seperti `endswith` pada path executable sangat umum, karena memungkinkan mencocokkan nama program tanpa terikat lokasi folder yang persis.

Bagian `condition` lalu merangkai search identifier dengan operator seperti `and`, `or`, `not`, `1 of them`, atau `all of selection*`, memungkinkan logika yang cukup kaya seperti "selection ini dan bukan pengecualian itu".

---

## Konversi ke Backend SIEM

Inilah yang membuat Sigma berharga. Sebuah rule yang ditulis sekali dikonversi ke bahasa SIEM tujuan lewat tool konversi. Secara historis tool ini bernama sigmac, dan kini digantikan oleh pySigma beserta sigma-cli sebagai pilihan utama.

Saat mengonversi, kita menentukan target (misalnya Splunk, Elastic, atau PowerShell) dan sering juga sebuah config pemetaan field. Config ini penting karena nama field di rule Sigma yang generik perlu dipetakan ke nama field sebenarnya di SIEM tujuan, yang bisa berbeda antar lingkungan. Hasil konversinya adalah query siap pakai: SPL untuk Splunk, atau perintah berbasis Get-WinEvent untuk PowerShell yang bisa dijalankan langsung terhadap file event log.

Selain konversi langsung, ada tool hunting yang memahami Sigma secara native. Chainsaw, misalnya, bisa memburu di file event log Windows dengan rule Sigma plus sebuah file mapping, sangat berguna untuk investigasi cepat terhadap artefak yang dikumpulkan.

---

## Kaitan dengan MITRE ATT&CK

Salah satu kekuatan ekosistem Sigma adalah konvensi memetakan tiap rule ke MITRE ATT&CK lewat bagian `tags`. Menandai sebuah rule dengan taktik dan teknik yang relevan (misalnya defense evasion dan teknik spesifiknya) memberi dua manfaat besar.

Pertama, **gap analysis**. Dengan memetakan seluruh rule ke matriks ATT&CK, tim bisa melihat teknik mana yang sudah tercakup deteksi dan mana yang masih buta. Ini mengubah pertanyaan "apakah kita aman" menjadi pertanyaan yang lebih konkret tentang cakupan deteksi.

Kedua, **bahasa bersama**. Saat sebuah alert berbunyi, tag ATT&CK langsung memberi konteks tentang tahap serangan dan niat penyerang, mempercepat triage dan menghubungkan deteksi dengan playbook respons.

---

## Detection as Code

Karena Sigma adalah teks YAML, ia cocok diperlakukan seperti kode: disimpan di version control, ditinjau lewat proses review, diuji, dan di-deploy secara otomatis. Pendekatan detection as code ini membawa disiplin rekayasa perangkat lunak ke dalam detection engineering. Rule punya riwayat perubahan, bisa dikembalikan bila bermasalah, dan perubahannya bisa ditinjau sebelum masuk produksi. Bagi tim yang serius, ini mengubah deteksi dari kumpulan query ad hoc menjadi aset yang dikelola dengan rapi.

---

## Kesalahan Umum

**1. Salah memahami map versus list.** Map digabung AND, list digabung OR. Tertukar membuat rule terlalu ketat atau terlalu longgar.

**2. Lupa config pemetaan field saat konversi.** Nama field generik Sigma harus dipetakan ke nama field SIEM tujuan, kalau tidak query tidak menemukan apa-apa.

**3. Tidak memetakan ke MITRE ATT&CK.** Tanpa tag, sulit melihat cakupan deteksi dan memberi konteks pada alert.

**4. Mengabaikan bagian falsepositives.** Mendokumentasikan kemungkinan alarm palsu membantu analis berikutnya men-triage dengan cepat.

**5. Memperlakukan rule sebagai sekali tulis.** Lingkungan dan teknik berubah. Kelola rule sebagai kode yang ditinjau dan diperbarui.

---

## Kartu Referensi Cepat

| Komponen | Peran |
|----------|-------|
| metadata | title, id (UUID), status, description, tags |
| logsource | category, product, service (sumber log) |
| detection | selection (map=AND, list=OR) + condition |
| value modifier | contains, startswith, endswith, all, re |
| level | informational sampai critical |
| konversi | pySigma / sigma-cli ke Splunk, Elastic, PowerShell |
| tags ATT&CK | pemetaan teknik untuk gap analysis dan konteks |

Pegangan akhir: Sigma adalah cara membebaskan deteksi dari kunci satu vendor. Tulis logika serangan sekali dalam YAML, petakan ke MITRE ATT&CK, lalu konversi ke SIEM apa pun yang dipakai. Diperlakukan sebagai kode, Sigma mengubah deteksi menjadi aset komunitas yang portabel, terlacak, dan terus berkembang.

---

## Referensi

- [SigmaHQ: Sigma rules repository dan spesifikasi](https://github.com/SigmaHQ/sigma)
- [SigmaHQ: pySigma dan sigma-cli](https://github.com/SigmaHQ/pySigma)
- [Sigma: Rule specification](https://sigmahq.io/)
- [MITRE ATT&CK: Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Chainsaw: hunting di event log dengan Sigma](https://github.com/WithSecureLabs/chainsaw)
