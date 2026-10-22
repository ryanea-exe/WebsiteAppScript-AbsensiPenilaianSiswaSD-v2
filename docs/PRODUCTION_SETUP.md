# Panduan Pemisahan Lingkungan & Persiapan Infrastruktur Produksi (Phase 11.2)
**Sistem Absensi dan Penilaian Siswa SD (Versi 2)**

Dokumen ini merupakan panduan operasional resmi untuk memisahkan lingkungan **TEST** dan **PRODUKSI** secara total, mencegah kontaminasi silang database, serta menyiapkan infrastruktur Google Cloud/Sheets sebelum peluncuran resmi.

---

## 1. Prinsip Isolasi Dua-Project (Two-Project Architecture)

Dalam Google Apps Script, `ScriptProperties` berlaku secara global per script project, bukan per deployment Web App. Oleh karena itu, berbagi satu script project untuk test dan produksi akan memicu konflik `SPREADSHEET_ID` dan risiko kontaminasi data.

Pemisahan wajib dilakukan secara independen pada level project dan database:

| Komponen | Lingkungan TEST (Eksisting) | Lingkungan PRODUKSI (Baru) |
| :--- | :--- | :--- |
| **Google Apps Script** | ID: `17r8cFSyJY0M1EAZwBcsKDhjJq9wRE1hehz3GeU9OWIyYhF7n9GUA5pE3` | **Wajib Project Baru** (`PROD_SCRIPT_ID`) |
| **Google Spreadsheet** | ID: `1tVY7hHpZNTHQ0c_9GEaM2-Gz4fOh8qccsCP0afRLBd8` | **Wajib Spreadsheet Baru** (`PROD_SPREADSHEET_ID`) |
| **Nama Spreadsheet** | `TEST - Absensi SD v2 - Database Setup` | `PROD - Absensi Penilaian SD v2` |
| **Profil Clasp Lokal** | `.clasp.test.json` | `.clasp.prod.json` (dari template) |
| **Hak Akses File** | Terbatas pada Pemilik (`ryanhillfree23@gmail.com`) | **Restricted** (Hanya Pemilik) |
| **Isi Database** | 11 sheet + data dummy/uji coba (28 entitas) | 11 sheet + singleton konfigurasi (0 baris dummy) |

---

## 2. Panduan Langkah Manual di Google Cloud & Sheets

Langkah-langkah berikut dijalankan langsung oleh Pemilik Akun Sah (`ryanhillfree23@gmail.com`) pada browser:

### Langkah A — Membuat Spreadsheet Produksi Baru
1. Buka [Google Sheets](https://sheets.new) menggunakan akun pemilik (`ryanhillfree23@gmail.com`).
2. Beri nama file: `PROD - Absensi Penilaian SD v2`.
3. Salin **Spreadsheet ID** dari URL browser:
   `https://docs.google.com/spreadsheets/d/`**`<PROD_SPREADSHEET_ID>`**`/edit`
4. **PENTING — Verifikasi Pembatasan Akses (Restricted)**:
   - Buka tombol **Share / Bagikan** di kanan atas.
   - Pastikan **General access** berstatus **Restricted** (Hanya pemilik yang dapat membuka).
   - Jangan pernah mengubah ke *"Anyone with the link"*. Data spreadsheet tidak boleh terbuka langsung ke publik; pengguna akhir hanya berinteraksi melalui Web App.

### Langkah B — Membuat Google Apps Script Project Produksi
1. Pada spreadsheet produksi yang baru dibuat, buka menu navigasi: **Extensions (Ekstensi) > Apps Script**.
2. Beri nama project script di kiri atas: `PROD - Absensi SD v2 - Core Engine`.
3. Buka menu **Project Settings** (ikon roda gigi di bilah kiri).
4. Catat **Script ID** pada bagian *IDs*:
   - Simpan ID ini sebagai `<PROD_SCRIPT_ID>`.

### Langkah C — Mengonfigurasi Script Properties Produksi
1. Masih di menu **Project Settings**, gulir ke bawah ke bagian **Script Properties**.
2. Klik **Add script property** (Tambah properti skrip):
   - **Property**: `SPREADSHEET_ID`
   - **Value**: Masukkan `<PROD_SPREADSHEET_ID>` yang diperoleh dari Langkah A.
3. Klik **Save script properties**.
   > *Catatan Keamanan*: Seluruh fungsi baca/tulis Web App (`code.gs`) memvalidasi `SPREADSHEET_ID` ini secara fail-closed. Jika properti tidak ada atau salah, request Web App akan langsung dihentikan dengan error eksplisit tanpa fallback diam-diam.

---

## 3. Konfigurasi Lingkungan Lokal & Mekanisme Anti-Tertukar

Pengelolaan kode multi-lingkungan menggunakan konfigurasi clasp terpisah yang aman dari kebocoran Git.

### A. Menyiapkan Profil Produksi Lokal
Salin template konfigurasi produksi menjadi file aktif lokal:
```bash
cp .clasp.prod.json.template .clasp.prod.json
```
Buka `.clasp.prod.json` dan ganti placeholder dengan ID resmi produksi Anda:
```json
{
  "scriptId": "<PROD_SCRIPT_ID>",
  "rootDir": "",
  "parentId": "<PROD_SPREADSHEET_ID>",
  "scriptExtensions": [".js", ".gs"],
  "htmlExtensions": [".html"],
  "jsonExtensions": [".json"],
  "filePushOrder": [],
  "skipSubdirectories": false
}
```

> **Perlindungan Keamanan**:
> File `.clasp.prod.json` telah didaftarkan dalam `.gitignore` sehingga ID produksi tidak akan pernah ter-commit atau bocor ke repositori publik.

### B. Prosedur Peralihan Target Lingkungan (Eksplisit)
Untuk beralih antar target, lakukan penyalinan file profil ke `.clasp.json`:
- **Beralih ke Lingkungan TEST**:
  ```bash
  cp .clasp.test.json .clasp.json
  ```
- **Beralih ke Lingkungan PRODUKSI**:
  ```bash
  cp .clasp.prod.json .clasp.json
  ```

### C. Verifikasi Wajib Sebelum Aksi Clasp (`check_target.js`)
SEBELUM menjalankan perintah clasp apa pun (`push`, `deploy`), wajib jalankan utilitas inspeksi lokal:
```bash
node scripts/check_target.js
```
Utilitas ini berjalan 100% lokal (read-only, tanpa jaringan) dan memvalidasi:
1. Target ID yang sedang aktif di `.clasp.json`.
2. Mencegah penggunaan ID test pada konfigurasi produksi.
3. Mendeteksi jika ada ketidaksesuaian atau placeholder yang belum terisi.

Contoh output verifikasi target produksi yang benar:
```text
====================================================================
       VERIFIKASI TARGET CLASP AKTIF (READ-ONLY INSPECTION)         
====================================================================

1. Konfigurasi Aktif (.clasp.json):
   - Script ID : <PROD_SCRIPT_ID>
   - Parent ID : <PROD_SPREADSHEET_ID>

2. Status Identifikasi Lingkungan:
   🚀 Target Terdeteksi : PRODUCTION ENVIRONMENT (Lingkungan Operasional Resmi)
...
```

---

## 4. Setup Database Bersih Tanpa Data Dummy (`skipSeed: true`)

Spreadsheet produksi harus dibuat murni dari nol tanpa akun pengujian (`kepsek_test`, `guru_test`) atau data murid contoh.

### Spesifikasi Skema Database Produksi
Sesuai `.docs/.database.md`, sistem akan membuat **11 sheet**:
1. `pengaturan` (Berisi 1 baris konfigurasi singleton default sistem)
2. `tahun_ajaran` (Kosong / 0 data)
3. `kelas` (Kosong / 0 data)
4. `siswa` (Kosong / 0 data)
5. `user` (Kosong / 0 data — akun kepala sekolah dibuat via onboarding)
6. `guru_kelas` (Kosong / 0 data)
7. `mata_pelajaran` (Kosong / 0 data)
8. `presensi` (Kosong / 0 data)
9. `kegiatan` (Kosong / 0 data)
10. `penilaian` (Kosong / 0 data)
11. `riwayat_ekspor` (Kosong / 0 data)

Setiap sheet diformat otomatis: baris header dikunci (frozen row 1), diberi styling header resmi, validasi tipe data, dan format teks pada kolom ID/NIP/NIS/NISN.

### Cara Eksekusi Setup Database Produksi (Phase 11.3)
Setelah kode di-push ke project produksi, buka Spreadsheet produksi dan gunakan menu custom Google Sheets:
- Pilih menu: **Absensi SD v2 > Setup Database (11 Sheet)**.
- Fungsi ini secara otomatis mengeksekusi:
  ```javascript
  runControlledSetupAndSeed_(activeSS, {
    skipSeed: true,
    allowActiveSpreadsheet: true,
    expectedSpreadsheetId: activeSS.getId()
  });
  ```
- **Hasil**: 11 sheet terbentuk dan singleton `pengaturan` terdaftar, **tanpa data dummy sama sekali**.

---

## 5. Alur Onboarding Akun Kepala Sekolah Pertama

Akun administrator utama (Kepala Sekolah) diinisialisasi melalui fungsi backend yang aman: `initKepalaSekolahUser_()`.

### Jaminan Keamanan Fungsi Onboarding:
1. **Otorisasi Pemilik Berlapis (`enforceAuthorizedOwner_`)**:
   Hanya akun Google pemilik sah (`ryanhillfree23@gmail.com`) yang dapat mengeksekusi. Menolak akses jika sesi berasal dari pengguna lain atau anonim.
2. **Penolakan Akun Dummy**:
   Secara eksplisit menolak username pengujian seperti `kepsek_test` atau `guru_test`.
3. **Kekuatan Kredensial**:
   Username minimal 3 karakter, nama minimal 3 karakter, password minimal 8 karakter.
4. **Hashing Kriptografis Kuat**:
   Menggunakan salt acak CSPRNG 64-karakter dan algoritma PBKDF2 (100.000 iterasi, SHA-256). Password plaintext tidak pernah disimpan atau dicatat di log.
5. **Singleton Role Guard**:
   Menolak eksekusi jika role `kepala_sekolah` sudah ada di sheet `user`, mencegah penimpaan atau pembuatan admin ganda yang ambigu.
6. **Preflight Skema**:
   Memvalidasi integritas kolom sheet `user` sebelum menulis.

### Keterbatasan Operasional & Catatan Keamanan Arsitektur:
> **PEMBERITAHUAN PENTING**:
> Saat ini `initKepalaSekolahUser_` adalah fungsi server-side internal (private) dan **belum memiliki dialog antarmuka visual khusus pemilik** di Google Sheets (seperti modal HTML `SecureSeedDialog` yang dipakai saat seed akun test).
> 
> **Kebijakan Arsitektur**:
> - **DILARANG KERAS** membuka endpoint publik pada `doGet` / `doPost` untuk pendaftaran akun awal tanpa autentikasi, karena akan menjadi celah keamanan fatal (memungkinkan siapa saja di internet mendaftarkan akun administrator).
> - Pada Phase 11.3, akun Kepala Sekolah resmi diinisialisasi secara privat dari Apps Script Editor oleh pemilik atau melalui wrapper fungsi owner-only dengan parameter kredensial resmi.

---

## 6. Checklist Kesiapan Sebelum Phase 11.3

Sebelum melangkah ke Phase 11.3 (Push & Eksekusi Setup Produksi), pastikan seluruh poin di bawah telah terpenuhi:

- [ ] Spreadsheet produksi baru telah dibuat dengan hak akses **Restricted**.
- [ ] Apps Script project produksi baru telah dibuat terpisah dari project test.
- [ ] Script Property `SPREADSHEET_ID` pada project produksi telah diisi ID spreadsheet produksi.
- [ ] File `.clasp.prod.json` telah dibuat lokal dan diverifikasi bebas ID test.
- [ ] Perintah `node scripts/check_target.js` berhasil mendeteksi target yang sesuai.
- [ ] Data pengujian dan project test di Google Cloud dipastikan tetap utuh dan tidak tersentuh.
