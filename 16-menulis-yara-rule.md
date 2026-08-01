# Menulis YARA Rule: Membuat Deteksi Malware dari Hasil Analisis

## Kenapa Ini Penting

Setelah menganalisis sebuah malware, pertanyaan yang sesungguhnya adalah: bagaimana memastikan kita mengenalinya lagi, beserta varian-variannya, di seluruh lingkungan. Di sinilah YARA berperan. YARA adalah bahasa dan tool untuk mendeskripsikan pola pada file dan memori, dan ia menjadi cara standar industri mengubah hasil analisis satu sample menjadi deteksi yang bisa dipakai berulang.

Tapi menulis YARA rule yang baik adalah seni keseimbangan. Rule yang terlalu sempit hanya menangkap satu sample dan langsung usang begitu penyerang mengubah satu byte. Rule yang terlalu lebar membanjiri analis dengan false positive sampai tidak dipercaya lagi. Tulisan ini membahas anatomi rule, cara memilih pola yang tahan banting, dan cara menghindari dua jebakan itu.

---

## Apa yang Dideteksi YARA

Penting memahami posisi YARA dibanding tool deteksi lain. YARA mencocokkan pola di **isi file dan memori**, baik pola tekstual maupun biner. Ini membuatnya berbeda dari Sigma yang mendeteksi pola di log event. YARA dipakai untuk klasifikasi malware, deteksi IOC, rule untuk EDR dan antivirus, incident response, dan threat hunting proaktif. Kemampuannya memindai memori proses, bukan hanya file di disk, membuatnya sangat berharga untuk menangkap malware yang berjalan atau disuntik ke proses lain.

---

## Anatomi Sebuah Rule

Sebuah YARA rule punya tiga bagian. Mengenali ketiganya membuat sintaksnya langsung masuk akal.

```yara
rule Ransomware_Contoh {
    meta:
        author = "analis"
        description = "Deteksi string khas ransomware contoh"
        reference = "internal-IR-2026-001"
    strings:
        $s1 = "tasksche.exe" fullword ascii
        $s2 = "vssadmin delete shadows" ascii nocase
        $h1 = { 4D 5A }
    condition:
        uint16(0) == 0x5A4D and 2 of ($s*)
}
```

- **meta** berisi metadata seperti penulis, deskripsi, dan referensi. Bagian ini tidak memengaruhi pencocokan, tapi penting untuk dokumentasi dan pelacakan.
- **strings** mendefinisikan pola yang dicari. Ada tiga tipe: teks (`"string"`), heksadesimal untuk pola biner (`{ 4D 5A }`, dengan dukungan wildcard dan lompatan), dan regex. Modifier memperhalusnya: `fullword` mencocokkan kata utuh, `ascii` dan `wide` menentukan encoding, `nocase` mengabaikan huruf besar-kecil.
- **condition** adalah logika yang menentukan kapan rule dianggap cocok. Bisa sesederhana `all of them` atau `any of them`, sampai logika yang lebih kaya.

---

## Condition yang Cerdas

Bagian condition adalah tempat rule yang baik menjadi presisi. Dua teknik yang sangat sering dipakai:

- **Pengecekan magic number.** Fungsi seperti `uint16(0) == 0x5A4D` membaca dua byte pertama file untuk memastikan ia benar-benar executable Windows (penanda MZ). Ini menyaring file yang kebetulan mengandung string yang sama tapi bukan executable, menekan false positive drastis.
- **Batasan ukuran.** Menambahkan `filesize < 100KB` membatasi pencocokan pada rentang ukuran yang masuk akal untuk sample tersebut, sehingga rule tidak ikut memindai file besar yang tidak relevan.

Selain itu, YARA punya modul tambahan yang memperluas kemampuannya, seperti modul PE untuk memeriksa import hash atau fungsi yang diimpor, dan modul math untuk menghitung entropy. Menggabungkan beberapa kondisi (misalnya magic number, ditambah ukuran, ditambah beberapa string khas) menghasilkan rule yang jauh lebih presisi daripada sekadar mencocokkan satu string.

---

## Memilih Pola yang Tahan Banting

Inilah inti dari menulis rule yang baik, dan tempat kebanyakan rule pemula gagal. Workflow-nya berawal dari analisis string pada sample, lalu memilih pola yang masuk ke rule. Kuncinya pada pemilihan itu.

Pola yang baik bersifat **unik bagi malware tapi tidak rapuh**. Mari uraikan keduanya:

- **Unik** berarti pola itu khas malware dan jarang muncul di software sah (goodware). Memilih string umum seperti pesan error generik atau nama fungsi Windows biasa menghasilkan rule yang berbunyi pada banyak file bersih. Inilah kenapa tool seperti yarGen membandingkan string sample dengan basis data goodware, untuk membuang yang umum dan menyisakan yang khas. Tapi hasil otomatis tetap wajib ditinjau analis.
- **Tidak rapuh** berarti pola itu tidak mudah diubah penyerang tanpa merombak fungsinya. String acak yang gampang diganti membuat rule cepat usang. Karakteristik struktural, pola perilaku yang melekat pada cara malware bekerja, atau kombinasi beberapa indikator, jauh lebih tahan lama.

Prinsip ini menggemakan Pyramid of Pain: deteksi yang menyasar sesuatu yang sulit diubah penyerang jauh lebih bernilai daripada yang menyasar indikator yang gampang diganti.

---

## Menghindari Terlalu Sempit dan Terlalu Lebar

Dua kegagalan paling umum saling berlawanan, dan keseimbangan di antaranya adalah tujuan.

**Rule terlalu sempit** biasanya mencocokkan satu hash atau satu string yang sangat spesifik dari satu sample. Ia akan menangkap sample itu dengan sempurna dan tidak menangkap apa pun lagi begitu penyerang mengubah sedikit. Tanda rule terlalu sempit: ia bergantung pada satu indikator yang gampang diubah.

**Rule terlalu lebar** mencocokkan pola yang juga ada di banyak file sah. Ia akan menghasilkan false positive yang membanjiri analis. Tanda rule terlalu lebar: ia berbunyi pada goodware saat diuji.

Jalan tengahnya adalah memilih beberapa pola khas dan menggabungkannya dalam condition, misalnya mensyaratkan beberapa string muncul bersamaan ditambah pengecekan tipe file. Dengan begitu rule cukup spesifik untuk menghindari false positive, tapi cukup umum untuk menangkap varian.

Cara memvalidasinya wajib dilakukan: uji rule terhadap koleksi malware (harus menangkap targetnya dan idealnya varian sejenis) dan terhadap koleksi file bersih (tidak boleh berbunyi sama sekali).

---

## Memakai YARA dalam Praktik

Setelah rule jadi, ia bisa dijalankan terhadap file atau direktori, dengan opsi untuk memindai secara rekursif dan menampilkan string mana yang cocok. Yang lebih kuat, YARA bisa memindai **memori proses yang sedang berjalan** dengan menunjuk ke process ID, yang esensial untuk menangkap malware yang hanya hidup di memori atau disuntik ke proses sah. Untuk forensik, YARA terintegrasi dengan framework memori seperti Volatility untuk memindai memory dump dan menemukan proses mana yang mengandung pola tertentu. Untuk threat hunting real-time di Windows, YARA bisa dipadukan dengan penangkapan event ETW.

---

## Kesalahan Umum

**1. Mencocokkan satu hash atau satu string spesifik.** Rule jadi langsung usang begitu satu byte diubah. Sasar pola yang lebih tahan lama.

**2. Memilih string yang umum di goodware.** Pesan error generik atau nama API biasa memicu false positive. Pilih yang khas malware.

**3. Mengandalkan rule otomatis tanpa ditinjau.** Tool seperti yarGen membantu, tapi hasilnya wajib disaring analis sebelum dipakai.

**4. Tidak menguji terhadap file bersih.** Rule yang menangkap malware tapi belum diuji pada goodware sering jadi mesin false positive.

**5. Lupa magic number dan ukuran di condition.** Pengecekan sederhana ini menyaring banyak false positive dengan murah.

---

## Kartu Referensi Cepat

| Bagian | Isi |
|--------|-----|
| meta | Metadata (author, description, reference) |
| strings | Pola: teks, hex `{ }`, regex + modifier (fullword, ascii, wide, nocase) |
| condition | Logika: `all/any of them`, `N of ($s*)`, `uint16(0)==0x5A4D`, `filesize` |
| Pilih pola | Unik bagi malware + sulit diubah penyerang |
| Hindari sempit | Jangan satu hash / satu string rapuh |
| Hindari lebar | Jangan pola yang ada di goodware |
| Validasi | Uji ke koleksi malware (cocok) dan bersih (tidak cocok) |
| Pakai | File, direktori (`-r`), memori (PID), Volatility, ETW |

Pegangan akhir: YARA mengubah satu hasil analisis menjadi deteksi yang melindungi seluruh lingkungan. Rahasianya bukan menulis rule yang rumit, tapi memilih pola yang unik bagi malware sekaligus sulit diubah, lalu menyeimbangkannya agar tidak terlalu sempit maupun terlalu lebar, dan selalu memvalidasinya terhadap data nyata.

---

## Referensi

- [YARA: Writing YARA rules (dokumentasi resmi)](https://yara.readthedocs.io/en/stable/writingrules.html)
- [Florian Roth: yarGen rule generator](https://github.com/Neo23x0/yarGen)
- [Florian Roth: How to write simple but sound YARA rules](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/)
- [SANS: Pyramid of Pain (David Bianco)](https://www.sans.org/tools/the-pyramid-of-pain/)
- [Volatility: yarascan plugin](https://volatility3.readthedocs.io/en/latest/)
