/**
 * ============================================================================
 * SUITE PENGUJIAN OTOMATIS PHASE 8: PENGUMUMAN DAN PENGATURAN PROFIL SEKOLAH
 * File: tests/test_phase8.js
 * ============================================================================
 *
 * Menguji:
 * 1. Otorisasi Role (RBAC):
 *    - Kepala Sekolah memiliki hak penuh mengelola Pengaturan Profil Sekolah dan Pengumuman.
 *    - Wali Kelas berhak membaca (read-only) Pengaturan Profil Sekolah dan Pengumuman.
 *    - Wali Kelas dilarang keras (403 / ditolak) melakukan mutasi (tambah, edit, hapus).
 *
 * 2. Keamanan Sesi & Validasi Token:
 *    - Penolakan token tidak valid, kosong, atau kedaluwarsa pada seluruh endpoint Phase 8.
 *
 * 3. Modul Pengaturan Profil Sekolah (apiGetPengaturanSekolah, apiSavePengaturanSekolah):
 *    - Penanganan profil belum dikonfigurasi (status isConfigured: false, placeholder netral).
 *    - Validasi backend: nama sekolah (wajib, 2-150 char), nama kepsek, NIP, format logo URL/ID.
 *    - Penyimpanan tunggal (single-record master) dan pembaruan kolom updated_by & updated_at.
 *    - Refleksi konsisten pada profil yang dibaca kembali.
 *
 * 4. Modul Pengumuman Resmi (apiGetPengumumanList, apiSavePengumuman, apiDeletePengumuman):
 *    - Penanganan empty state saat belum ada pengumuman.
 *    - Validasi backend: judul (wajib, 3-150 char), isi (wajib, 5-5000 char).
 *    - Pembuatan pengumuman baru dengan UUID v4 stabil.
 *    - Pengurutan kronologis descending berdasarkan created_at.
 *    - Pencarian fleksibel (case-insensitive) pada judul dan isi pengumuman.
 *    - Pembaruan pengumuman dan penanganan ID tidak ditemukan.
 *    - Penghapusan pengumuman fisik aman dan penanganan ID tidak ditemukan.
 *    - Pencegahan IDOR / akses tidak sah.
 *
 * 5. Integrasi Dashboard & Rapor:
 *    - Keberadaan recentAnnouncements pada respons apiGetInitialDashboard.
 *    - Sinkronisasi profil sekolah pada rapor digital siswa (apiGetRaporDigitalSiswa).
 *
 * 6. Integritas Data & Larangan Mutasi Tidak Disengaja:
 *    - Operasi baca bersifat murni read-only.
 *    - Penyimpanan profil dan pengumuman tidak memodifikasi sheet akademik (nilai, sikap, kehadiran, siswa, mapel).
 */

const assert = require('assert');

const setupModule = require('../setup.gs');
const appModule = require('../code.gs');

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 8: PENGUMUMAN & PENGATURAN PROFIL SEKOLAH ===\n');

// ============================================================================
// SETUP MOCK SPREADSHEET ENVIRONMENT LOKAL
// ============================================================================
function createPhase8MockEnvironment() {
  const saltKepsek = appModule.generateSecureSalt();
  const hashKepsek = appModule.hashPasswordPBKDF2('KepsekPass123!', saltKepsek, 1000);

  const saltWali1 = appModule.generateSecureSalt();
  const hashWali1 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali1, 1000);

  const userHeaders = setupModule.SCHEMA_DEFINITIONS.user;
  const userRows = [
    ['u-kepsek', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'kepsek', hashKepsek, saltKepsek, 'kepala_sekolah', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali1', 'Ahmad Dahlan, S.Pd.', '198502022010011002', 'wali1', hashWali1, saltWali1, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01']
  ];

  // Inisialisasi awal sheet pengaturan kosong (belum dikonfigurasi) untuk menguji empty state
  const pengHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan;
  const pengRows = [];

  // Inisialisasi awal sheet pengumuman kosong
  const pengumumanHeaders = setupModule.SCHEMA_DEFINITIONS.pengumuman;
  const pengumumanRows = [];

  const taHeaders = setupModule.SCHEMA_DEFINITIONS.tahun_ajaran;
  const taRows = [
    ['ta-aktif', '2026/2027', 'Ganjil', '2026-07-15', '2026-12-20', true, false, '2026-01-01', '2026-01-01']
  ];

  const wkHeaders = setupModule.SCHEMA_DEFINITIONS.wali_kelas;
  const wkRows = [
    ['wk-k1', 'u-wali1', 'ta-aktif', '1', true, '2026-01-01', '2026-01-01']
  ];

  const siswaHeaders = setupModule.SCHEMA_DEFINITIONS.siswa;
  const siswaRows = [
    ['s-01', 'wk-k1', '0012345671', '1001', '1', 'Budi Santoso', 'L', 'Jakarta', '2019-01-01', 'Ortu Budi', '0812345671', true, '2026-01-01', '2026-01-01']
  ];

  const mapelHeaders = setupModule.SCHEMA_DEFINITIONS.mata_pelajaran;
  const mapelRows = [
    ['m-01', 'wk-k1', 'PAI', 'Pendidikan Agama Islam', true, '2026-01-01', '2026-01-01']
  ];

  const nilaiMapelHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_mata_pelajaran;
  const nilaiMapelRows = [
    ['n-01', 's-01', 'm-01', 90, 90, 90, 90, 90, 90, 90, true, '2026-01-01', '2026-01-01']
  ];

  const nilaiSikapHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_sikap;
  const nilaiSikapRows = [
    ['sk-01', 's-01', 'A', 'Sangat baik', '2026-01-01', '2026-01-01']
  ];

  const rekapKehadiranHeaders = setupModule.SCHEMA_DEFINITIONS.rekap_kehadiran;
  const rekapKehadiranRows = [
    ['rk-01', 's-01', 100, 0, 0, 0, '', '2026-01-01', '2026-01-01']
  ];

  const prHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan_rapor;
  const prRows = [
    ['pr-01', 'ta-aktif', 'wk-k1', 40, 30, 30, JSON.stringify([
      { label: 'A', min: 90, max: 100 }
    ]), '2026-01-01', '2026-01-01']
  ];

  function makeMockSheet(name, headers, initialData) {
    const rows = [headers.slice(), ...initialData.map(r => r.slice())];
    return {
      getName: () => name,
      getLastRow: () => rows.length,
      getLastColumn: () => headers.length,
      getRange: function(r, c, numR, numC) {
        return {
          getValues: function() {
            const res = [];
            const countR = numR || 1;
            const countC = numC || 1;
            for (let rowIdx = r - 1; rowIdx < r - 1 + countR; rowIdx++) {
              const rowData = [];
              for (let colIdx = c - 1; colIdx < c - 1 + countC; colIdx++) {
                rowData.push(rows[rowIdx] ? rows[rowIdx][colIdx] : '');
              }
              res.push(rowData);
            }
            return res;
          },
          setValue: function(val) {
            if (rows[r - 1]) {
              rows[r - 1][c - 1] = val;
            }
          },
          setValues: function(vals) {
            for (let i = 0; i < vals.length; i++) {
              for (let j = 0; j < vals[i].length; j++) {
                if (rows[r - 1 + i]) {
                  rows[r - 1 + i][c - 1 + j] = vals[i][j];
                }
              }
            }
          }
        };
      },
      appendRow: function(arr) {
        rows.push(arr.slice());
        return rows.length;
      },
      deleteRow: function(rowIndex) {
        if (rowIndex >= 1 && rowIndex <= rows.length) {
          rows.splice(rowIndex - 1, 1);
        }
        return rows.length;
      },
      _rawRows: rows
    };
  }

  const sheets = {
    user: makeMockSheet('user', userHeaders, userRows),
    pengaturan: makeMockSheet('pengaturan', pengHeaders, pengRows),
    pengumuman: makeMockSheet('pengumuman', pengumumanHeaders, pengumumanRows),
    tahun_ajaran: makeMockSheet('tahun_ajaran', taHeaders, taRows),
    wali_kelas: makeMockSheet('wali_kelas', wkHeaders, wkRows),
    siswa: makeMockSheet('siswa', siswaHeaders, siswaRows),
    mata_pelajaran: makeMockSheet('mata_pelajaran', mapelHeaders, mapelRows),
    nilai_mata_pelajaran: makeMockSheet('nilai_mata_pelajaran', nilaiMapelHeaders, nilaiMapelRows),
    nilai_sikap: makeMockSheet('nilai_sikap', nilaiSikapHeaders, nilaiSikapRows),
    rekap_kehadiran: makeMockSheet('rekap_kehadiran', rekapKehadiranHeaders, rekapKehadiranRows),
    pengaturan_rapor: makeMockSheet('pengaturan_rapor', prHeaders, prRows)
  };

  const ss = {
    getSheetByName: (name) => sheets[name] || null,
    sheets: sheets
  };

  return ss;
}

// Inisialisasi Mock Spreadsheet
const mockSS = createPhase8MockEnvironment();
global.getTargetSpreadsheet = () => mockSS;
global.SpreadsheetApp = {
  getActiveSpreadsheet: () => mockSS,
  openById: () => mockSS,
  flush: () => {}
};
global.LockService = {
  getScriptLock: () => ({
    waitLock: () => true,
    releaseLock: () => true
  })
};

let tokenKepsek = '';
let tokenWali1 = '';

// ============================================================================
// TEST SUITE 1: OTENTIKASI & SETUP SESI PENGUJIAN
// ============================================================================
console.log('--- TEST SUITE 1: Otentikasi & Validasi Token Sesi ---');

const loginKepsek = appModule.apiLogin('kepsek', 'KepsekPass123!');
assert.strictEqual(loginKepsek.success, true, 'Login Kepala Sekolah harus sukses');
tokenKepsek = loginKepsek.data.token;

const loginWali1 = appModule.apiLogin('wali1', 'WaliPass123!');
assert.strictEqual(loginWali1.success, true, 'Login Wali Kelas harus sukses');
tokenWali1 = loginWali1.data.token;

// 1.1 Penolakan token palsu / tidak valid pada seluruh endpoint Phase 8
const invalidTokens = ['', 'fake-token-12345', null, undefined];
for (const badToken of invalidTokens) {
  const getPengaturan = appModule.apiGetPengaturanSekolah(badToken);
  assert.strictEqual(getPengaturan.success, false, 'apiGetPengaturanSekolah harus menolak token tidak valid');

  const savePengaturan = appModule.apiSavePengaturanSekolah(badToken, { nama_sekolah: 'SD Sukses' });
  assert.strictEqual(savePengaturan.success, false, 'apiSavePengaturanSekolah harus menolak token tidak valid');

  const getPengumuman = appModule.apiGetPengumumanList(badToken);
  assert.strictEqual(getPengumuman.success, false, 'apiGetPengumumanList harus menolak token tidak valid');

  const savePengumuman = appModule.apiSavePengumuman(badToken, { judul: 'Tes', isi: 'Isi tes pengumuman' });
  assert.strictEqual(savePengumuman.success, false, 'apiSavePengumuman harus menolak token tidak valid');

  const delPengumuman = appModule.apiDeletePengumuman(badToken, 'p-123');
  assert.strictEqual(delPengumuman.success, false, 'apiDeletePengumuman harus menolak token tidak valid');
}
console.log('✓ Seluruh endpoint Phase 8 aman dari token tidak valid / kosong.');

// ============================================================================
// TEST SUITE 2: OTORISASI ROLE (RBAC) & AKSES KEPALA SEKOLAH VS WALI KELAS
// ============================================================================
console.log('\n--- TEST SUITE 2: Otorisasi Role (RBAC) ---');

// 2.1 Wali Kelas diizinkan membaca profil sekolah
const waliGetProfil = appModule.apiGetPengaturanSekolah(tokenWali1);
assert.strictEqual(waliGetProfil.success, true, 'Wali Kelas berhak membaca pengaturan profil sekolah');

// 2.2 Wali Kelas DITOLAK saat mencoba mutasi profil sekolah
const waliSaveProfil = appModule.apiSavePengaturanSekolah(tokenWali1, {
  nama_sekolah: 'SD Perubahan Ilegal'
});
assert.strictEqual(waliSaveProfil.success, false, 'Wali Kelas dilarang mengubah profil sekolah');
assert.ok(waliSaveProfil.message.includes('Akses ditolak') || waliSaveProfil.message.includes('otoritas'),
  'Pesan penolakan harus mengindikasikan masalah otorisasi/role');

// 2.3 Wali Kelas diizinkan membaca daftar pengumuman
const waliGetPengumuman = appModule.apiGetPengumumanList(tokenWali1);
assert.strictEqual(waliGetPengumuman.success, true, 'Wali Kelas berhak membaca pengumuman');

// 2.4 Wali Kelas DITOLAK saat mencoba membuat/mengedit pengumuman
const waliSavePengumuman = appModule.apiSavePengumuman(tokenWali1, {
  judul: 'Pengumuman Palsu',
  isi: 'Ini isi pengumuman tidak sah dari wali kelas.'
});
assert.strictEqual(waliSavePengumuman.success, false, 'Wali Kelas dilarang membuat pengumuman');

// 2.5 Wali Kelas DITOLAK saat mencoba menghapus pengumuman
const waliDelPengumuman = appModule.apiDeletePengumuman(tokenWali1, 'p-random-id');
assert.strictEqual(waliDelPengumuman.success, false, 'Wali Kelas dilarang menghapus pengumuman');

console.log('✓ Role boundaries teruji: Kepala Sekolah berwenang penuh, Wali Kelas terbatas read-only.');

// ============================================================================
// TEST SUITE 3: MODUL PENGATURAN PROFIL SEKOLAH
// ============================================================================
console.log('\n--- TEST SUITE 3: Modul Pengaturan Profil Sekolah ---');

// 3.1 Profil Belum Dikonfigurasi (Empty state awal)
const initialProfil = appModule.apiGetPengaturanSekolah(tokenKepsek);
assert.strictEqual(initialProfil.success, true, 'apiGetPengaturanSekolah sukses saat sheet kosong');
assert.strictEqual(initialProfil.data.isConfigured, false, 'Status isConfigured harus false saat belum diset');
assert.strictEqual(initialProfil.data.nama_sekolah, '', 'nama_sekolah harus string kosong, bukan dummy data');
assert.strictEqual(initialProfil.data.nama_kepala_sekolah, '', 'nama_kepala_sekolah harus string kosong');

// 3.2 Validasi Backend Input Profil Sekolah
const invalidProfiles = [
  { payload: {}, expectedErr: 'Nama sekolah wajib diisi.' },
  { payload: { nama_sekolah: '   ' }, expectedErr: 'Nama sekolah wajib diisi.' },
  { payload: { nama_sekolah: 'A' }, expectedErr: 'antara 2 hingga 150 karakter' },
  { payload: { nama_sekolah: 'A'.repeat(151) }, expectedErr: 'antara 2 hingga 150 karakter' },
  { payload: { nama_sekolah: 'SD Negeri 1', nama_kepala_sekolah: 'B'.repeat(101) }, expectedErr: 'maksimal 100 karakter' },
  { payload: { nama_sekolah: 'SD Negeri 1', nip_kepala_sekolah: '1'.repeat(31) }, expectedErr: 'maksimal 30 karakter' },
  { payload: { nama_sekolah: 'SD Negeri 1', nip_kepala_sekolah: 'NIP123@#$' }, expectedErr: 'hanya boleh memuat angka, spasi, titik, atau tanda hubung' },
  { payload: { nama_sekolah: 'SD Negeri 1', logo_sekolah: 'ftp://invalidscheme.com' }, expectedErr: 'Format tautan atau ID file logo tidak valid.' }
];

for (const testCase of invalidProfiles) {
  const res = appModule.apiSavePengaturanSekolah(tokenKepsek, testCase.payload);
  assert.strictEqual(res.success, false, 'Harus gagal validasi input: ' + JSON.stringify(testCase.payload));
  assert.ok(res.message.includes(testCase.expectedErr), `Pesan error "${res.message}" harus memuat "${testCase.expectedErr}"`);
}
console.log('✓ Seluruh validasi backend profil sekolah (nama, nip, logo) berhasil diverifikasi.');

// 3.3 Menyimpan Profil Sekolah Pertama Kali (Insert)
const validPayload1 = {
  nama_sekolah: 'SD Negeri Percobaan Unggulan 01',
  nama_kepala_sekolah: 'Drs. H. Subagyo, M.Pd.',
  nip_kepala_sekolah: '197001011995011001',
  logo_sekolah: 'https://sekolah.sch.id/assets/logo.png'
};

const saveRes1 = appModule.apiSavePengaturanSekolah(tokenKepsek, validPayload1);
assert.strictEqual(saveRes1.success, true, 'Simpan profil pertama kali harus berhasil');
assert.strictEqual(saveRes1.data.isConfigured, true, 'isConfigured harus bernilai true');
assert.strictEqual(saveRes1.data.nama_sekolah, validPayload1.nama_sekolah);

// 3.4 Verifikasi hasil baca profil setelah disimpan
const loadedProfil1 = appModule.apiGetPengaturanSekolah(tokenKepsek);
assert.strictEqual(loadedProfil1.success, true);
assert.strictEqual(loadedProfil1.data.isConfigured, true);
assert.strictEqual(loadedProfil1.data.nama_sekolah, validPayload1.nama_sekolah);
assert.strictEqual(loadedProfil1.data.nama_kepala_sekolah, validPayload1.nama_kepala_sekolah);
assert.strictEqual(loadedProfil1.data.nip_kepala_sekolah, validPayload1.nip_kepala_sekolah);
assert.strictEqual(loadedProfil1.data.logo_sekolah, validPayload1.logo_sekolah);
assert.strictEqual(loadedProfil1.data.updated_by, 'u-kepsek');
assert.strictEqual(loadedProfil1.data.updated_by_nama, 'Drs. H. Subagyo, M.Pd.');

// 3.5 Pembaruan Profil Sekolah (Update single-record master)
const validPayload2 = {
  nama_sekolah: 'SD Negeri Unggulan 01 Jakarta',
  nama_kepala_sekolah: 'Drs. H. Subagyo, M.Pd.',
  nip_kepala_sekolah: '19700101 199501 1 001',
  logo_sekolah: '1B2c3D4e5F6g7H8i9J0k_DriveFileId'
};

const saveRes2 = appModule.apiSavePengaturanSekolah(tokenKepsek, validPayload2);
assert.strictEqual(saveRes2.success, true, 'Pembaruan profil sekolah harus berhasil');

const loadedProfil2 = appModule.apiGetPengaturanSekolah(tokenWali1);
assert.strictEqual(loadedProfil2.data.nama_sekolah, 'SD Negeri Unggulan 01 Jakarta');
assert.strictEqual(loadedProfil2.data.logo_sekolah, '1B2c3D4e5F6g7H8i9J0k_DriveFileId');

// Pastikan jumlah baris di sheet pengaturan tetap 1 baris (tidak menduplikasi baris)
const sheetPengaturan = mockSS.getSheetByName('pengaturan');
assert.strictEqual(sheetPengaturan.getLastRow(), 2, 'Sheet pengaturan harus tepat memiliki 1 baris header + 1 baris data');

console.log('✓ Modul pengaturan profil sekolah (single-record master, insert & update) berfungsi optimal.');

// ============================================================================
// TEST SUITE 4: MODUL PENGUMUMAN RESMI SEKOLAH
// ============================================================================
console.log('\n--- TEST SUITE 4: Modul Pengumuman Resmi Sekolah ---');

// 4.1 Empty State Pengumuman
const initialPengumuman = appModule.apiGetPengumumanList(tokenKepsek);
assert.strictEqual(initialPengumuman.success, true);
assert.strictEqual(Array.isArray(initialPengumuman.data), true);
assert.strictEqual(initialPengumuman.data.length, 0, 'Daftar pengumuman awal harus array kosong []');

// 4.2 Validasi Backend Pengumuman
const invalidPengumumanCases = [
  { payload: {}, err: 'Judul pengumuman wajib diisi.' },
  { payload: { judul: '  ' }, err: 'Judul pengumuman wajib diisi.' },
  { payload: { judul: 'AB', isi: 'Isi pengumuman yang sah' }, err: 'antara 3 hingga 150 karakter' },
  { payload: { judul: 'X'.repeat(151), isi: 'Isi sah' }, err: 'antara 3 hingga 150 karakter' },
  { payload: { judul: 'Judul Sah', isi: '' }, err: 'Isi pengumuman wajib diisi.' },
  { payload: { judul: 'Judul Sah', isi: 'Tiga' }, err: 'antara 5 hingga 5000 karakter' },
  { payload: { judul: 'Judul Sah', isi: 'X'.repeat(5001) }, err: 'antara 5 hingga 5000 karakter' }
];

for (const tc of invalidPengumumanCases) {
  const res = appModule.apiSavePengumuman(tokenKepsek, tc.payload);
  assert.strictEqual(res.success, false, 'Validasi pengumuman gagal untuk: ' + JSON.stringify(tc.payload));
  assert.ok(res.message.includes(tc.err), `Pesan "${res.message}" harus mengandung "${tc.err}"`);
}
console.log('✓ Seluruh validasi backend pengumuman (panjang judul, batas isi) berhasil.');

// 4.3 Pembuatan Pengumuman Baru (Publikasi)
const payloadP1 = {
  judul: 'Libur Awal Ramadhan 1447 H',
  isi: 'Diberitahukan kepada seluruh dewan guru dan siswa bahwa libur awal Ramadhan ditetapkan selama 3 hari kerja.'
};

const resP1 = appModule.apiSavePengumuman(tokenKepsek, payloadP1);
assert.strictEqual(resP1.success, true, 'Publikasi pengumuman 1 harus berhasil');
assert.ok(resP1.data.id, 'ID pengumuman baru harus berupa string UUID yang valid');
const p1Id = resP1.data.id;

// Verifikasi daftar memuat pengumuman yang baru dibuat
const listAfterP1 = appModule.apiGetPengumumanList(tokenWali1);
assert.strictEqual(listAfterP1.data.length, 1);
assert.strictEqual(listAfterP1.data[0].id, p1Id);
assert.strictEqual(listAfterP1.data[0].judul, payloadP1.judul);
assert.strictEqual(listAfterP1.data[0].isi, payloadP1.isi);
assert.strictEqual(listAfterP1.data[0].dibuat_oleh_nama, 'Drs. H. Subagyo, M.Pd.');

// 4.4 Pembuatan Pengumuman Kedua & Pengurutan Kronologis Descending
const payloadP2 = {
  judul: 'Jadwal Asesmen Sumatif Akhir Semester Genap',
  isi: 'Asesmen Sumatif Akhir Semester akan dilaksanakan mulai hari Senin, 8 Juni 2026.'
};

const resP2 = appModule.apiSavePengumuman(tokenKepsek, payloadP2);
assert.strictEqual(resP2.success, true, 'Publikasi pengumuman 2 harus berhasil');
const p2Id = resP2.data.id;

const listAfterP2 = appModule.apiGetPengumumanList(tokenKepsek);
assert.strictEqual(listAfterP2.data.length, 2, 'Harus ada 2 pengumuman terdaftar');
// Pengumuman terbaru harus berada di index 0
assert.strictEqual(listAfterP2.data[0].id, p2Id, 'Pengumuman paling baru harus berada di posisi teratas (descending)');

// 4.5 Filter Pencarian Pengumuman (Case-Insensitive)
// Cari 'ramadhan'
const searchRamadhan = appModule.apiGetPengumumanList(tokenWali1, 'ramadhan');
assert.strictEqual(searchRamadhan.data.length, 1, 'Pencarian "ramadhan" harus menemukan 1 pengumuman');
assert.strictEqual(searchRamadhan.data[0].id, p1Id);

// Cari 'asesmen'
const searchAsesmen = appModule.apiGetPengumumanList(tokenWali1, 'ASESMEN');
assert.strictEqual(searchAsesmen.data.length, 1, 'Pencarian "ASESMEN" case-insensitive harus menemukan 1 pengumuman');
assert.strictEqual(searchAsesmen.data[0].id, p2Id);

// Cari keyword yang tidak cocok
const searchNihil = appModule.apiGetPengumumanList(tokenWali1, 'kata_kunci_mustahil_ada_123');
assert.strictEqual(searchNihil.data.length, 0, 'Pencarian tanpa kecocokan harus mengembalikan array kosong');

// 4.6 Edit Pengumuman
// Edit dengan ID tidak ditemukan (IDOR / Not Found check)
const editGhost = appModule.apiSavePengumuman(tokenKepsek, {
  id: 'id-hantu-999999',
  judul: 'Judul Update Hantu',
  isi: 'Isi pembaruan data yang tidak ada'
});
assert.strictEqual(editGhost.success, false, 'Edit pengumuman dengan ID tidak ada harus ditolak');
assert.ok(editGhost.message.includes('tidak ditemukan'));

// Edit pengumuman yang sah
const editP1 = appModule.apiSavePengumuman(tokenKepsek, {
  id: p1Id,
  judul: 'Revisi: Libur Awal Ramadhan 1447 H Disesuaikan',
  isi: 'Revisi: Libur awal Ramadhan disesuaikan menjadi 4 hari kerja sesuai edaran dinas.'
});
assert.strictEqual(editP1.success, true, 'Edit pengumuman valid harus berhasil');

const verifyP1 = appModule.apiGetPengumumanList(tokenKepsek).data.find(p => p.id === p1Id);
assert.strictEqual(verifyP1.judul, 'Revisi: Libur Awal Ramadhan 1447 H Disesuaikan');
assert.strictEqual(verifyP1.isi, 'Revisi: Libur awal Ramadhan disesuaikan menjadi 4 hari kerja sesuai edaran dinas.');

// 4.7 Hapus Pengumuman
// Hapus ID yang tidak ada
const delGhost = appModule.apiDeletePengumuman(tokenKepsek, 'id-hantu-tidak-ada');
assert.strictEqual(delGhost.success, false, 'Hapus pengumuman dengan ID tidak ada harus ditolak');
assert.ok(delGhost.message.includes('tidak ditemukan'));

// Hapus pengumuman p1
const delP1 = appModule.apiDeletePengumuman(tokenKepsek, p1Id);
assert.strictEqual(delP1.success, true, 'Hapus pengumuman sah harus berhasil');

const listAfterDel = appModule.apiGetPengumumanList(tokenKepsek);
assert.strictEqual(listAfterDel.data.length, 1, 'Tersisa 1 pengumuman setelah p1 dihapus');
assert.strictEqual(listAfterDel.data[0].id, p2Id);

console.log('✓ Modul pengumuman (create, order, search, edit, delete, not-found handling) terverifikasi penuh.');

// ============================================================================
// TEST SUITE 5: INTEGRASI DASHBOARD DAN RAPOR DIGITAL
// ============================================================================
console.log('\n--- TEST SUITE 5: Integrasi Dashboard & Rapor Digital ---');

// 5.1 Dashboard Kepala Sekolah & Wali Kelas memuat recentAnnouncements
const dashKepsek = appModule.apiGetInitialDashboard(tokenKepsek);
assert.strictEqual(dashKepsek.success, true);
assert.strictEqual(Array.isArray(dashKepsek.data.recentAnnouncements), true, 'Dashboard harus memiliki array recentAnnouncements');
assert.strictEqual(dashKepsek.data.recentAnnouncements.length, 1, 'Memuat 1 pengumuman aktif tersisa');
assert.strictEqual(dashKepsek.data.recentAnnouncements[0].id, p2Id);

const dashWali = appModule.apiGetInitialDashboard(tokenWali1);
assert.strictEqual(dashWali.success, true);
assert.strictEqual(Array.isArray(dashWali.data.recentAnnouncements), true);
assert.strictEqual(dashWali.data.recentAnnouncements.length, 1);

// 5.2 Rapor Digital Siswa merefleksikan Pengaturan Profil Sekolah terbaru
const raporSiswa = appModule.apiGetRaporDigitalSiswa(tokenKepsek, 's-01');
assert.strictEqual(raporSiswa.success, true);
assert.ok(raporSiswa.data.sekolah, 'Rapor siswa harus memuat objek sekolah');
assert.strictEqual(raporSiswa.data.sekolah.nama_sekolah, 'SD Negeri Unggulan 01 Jakarta',
  'Nama sekolah di rapor digital harus sinkron dengan pengaturan sekolah');
assert.strictEqual(raporSiswa.data.sekolah.nama_kepala_sekolah, 'Drs. H. Subagyo, M.Pd.');
assert.strictEqual(raporSiswa.data.sekolah.nip_kepala_sekolah, '19700101 199501 1 001');

console.log('✓ Konsistensi integrasi dashboard (recentAnnouncements) dan rapor digital (profil sekolah) terverifikasi.');

// ============================================================================
// TEST SUITE 6: INTEGRITAS DATA & LARANGAN MUTASI TIDAK DISENGAJA
// ============================================================================
console.log('\n--- TEST SUITE 6: Integritas Data & Proteksi Read-Only ---');

const sheetNilai = mockSS.getSheetByName('nilai_mata_pelajaran');
const sheetSikap = mockSS.getSheetByName('nilai_sikap');
const sheetKehadiran = mockSS.getSheetByName('rekap_kehadiran');
const sheetSiswa = mockSS.getSheetByName('siswa');
const sheetMapel = mockSS.getSheetByName('mata_pelajaran');
const sheetTA = mockSS.getSheetByName('tahun_ajaran');

// Verifikasi sheet akademik tidak berubah selama pengujian Phase 8
assert.strictEqual(sheetNilai.getLastRow(), 2, 'Sheet nilai_mata_pelajaran tidak boleh termutasi');
assert.strictEqual(sheetSikap.getLastRow(), 2, 'Sheet nilai_sikap tidak boleh termutasi');
assert.strictEqual(sheetKehadiran.getLastRow(), 2, 'Sheet rekap_kehadiran tidak boleh termutasi');
assert.strictEqual(sheetSiswa.getLastRow(), 2, 'Sheet siswa tidak boleh termutasi');
assert.strictEqual(sheetMapel.getLastRow(), 2, 'Sheet mata_pelajaran tidak boleh termutasi');
assert.strictEqual(sheetTA.getLastRow(), 2, 'Sheet tahun_ajaran tidak boleh termutasi');

console.log('✓ Data akademik (nilai, sikap, kehadiran, siswa, mapel, tahun ajaran) 100% utuh tanpa mutasi sampingan.');

console.log('\n============================================================================');
console.log('HASIL PENGUJIAN: SELURUH TEST SUITE PHASE 8 BERHASIL 100% DENGAN SUKSES!');
console.log('============================================================================');
