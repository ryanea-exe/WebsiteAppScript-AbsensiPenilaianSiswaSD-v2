/**
 * ============================================================================
 * SUITE PENGUJIAN OTOMATIS PHASE 5: USER, SISWA, DAN MATA PELAJARAN
 * File: tests/test_phase5.js
 * ============================================================================
 *
 * Menguji:
 * 1. Pengelolaan Akun Pengguna (User Management - Khusus Kepala Sekolah):
 *    - Listing pengguna (apiGetUsersList) & fitur pencarian (nama, username, NIP).
 *    - Keamanan kredensial: password_hash dan password_salt TIDAK bocor ke frontend.
 *    - Validasi username: wajib, minimal 3 karakter, format regex [a-z0-9_.], case-insensitive uniqueness.
 *    - Validasi NIP unik jika diisi.
 *    - Validasi role yang diizinkan (hanya kepala_sekolah atau wali_kelas).
 *    - Pembangkitan salt acak unik dan PBKDF2-HMAC-SHA256 untuk password baru.
 *    - Update profil pengguna dengan/tanpa perubahan password.
 *    - Proteksi self-lockout Kepala Sekolah: tidak bisa menonaktifkan diri sendiri,
 *      tidak bisa menurunkan role diri sendiri, dan tidak bisa menghapus diri sendiri.
 *    - Proteksi integritas relasional: tidak bisa menghapus user yang sudah memiliki penugasan
 *      (wali_kelas) atau terhubung dengan profil pengaturan sekolah.
 *    - Otorisasi: Wali Kelas ditolak mengakses seluruh endpoint manajemen user.
 *
 * 2. Pengelolaan Data Siswa (CRUD Siswa & Pencegahan IDOR):
 *    - Pengambilan daftar siswa (apiGetSiswaList) terurut berdasarkan nomor absen.
 *    - Pembatasan cakupan wali kelas: hanya melihat siswa pada rombel miliknya.
 *    - Validasi field: nama wajib, nomor absen bulat positif, jenis kelamin L/P, format NISN.
 *    - Validasi keunikan nomor absen dalam lingkup rombel kelas.
 *    - Validasi keunikan NISN dan NIS di lingkup sekolah.
 *    - Proteksi Periode Terkunci: menolak tambah/edit siswa pada tahun ajaran yang dikunci.
 *    - Proteksi IDOR: Wali kelas dilarang menambah, mengedit, mengubah status, atau menghapus
 *      siswa dari kelas/penugasan guru lain.
 *    - Proteksi Data Historis: menolak penghapusan permanen siswa yang telah memiliki nilai
 *      mata pelajaran, nilai sikap, atau rekap kehadiran.
 *
 * 3. Pengelolaan Mata Pelajaran (CRUD Mapel & Pencegahan IDOR):
 *    - Pengambilan daftar mata pelajaran (apiGetMataPelajaranList) sesuai penugasan.
 *    - Validasi kode mapel (uppercase) dan nama mata pelajaran wajib diisi.
 *    - Validasi keunikan kode mapel dan keunikan nama mapel dalam rombel penugasan.
 *    - Proteksi Periode Terkunci: menolak tambah/edit mapel pada tahun ajaran terkunci.
 *    - Proteksi IDOR: Wali kelas dilarang mengubah atau menghapus mapel kelas lain.
 *    - Proteksi Data Historis: menolak penghapusan mata pelajaran yang sudah memiliki riwayat nilai.
 *
 * 4. Pengujian Sesi & Least Privilege:
 *    - Penolakan token tidak valid atau token palsu pada semua endpoint.
 */

const assert = require('assert');
const path = require('path');

const setupModule = require('../setup.gs');
const appModule = require('../code.gs');

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 5: USER, SISWA & MAPEL ===\n');

// ============================================================================
// SETUP MOCK SPREADSHEET ENVIRONMENT LOKAL
// ============================================================================
function createPhase5MockEnvironment() {
  const saltKepsek = appModule.generateSecureSalt();
  const hashKepsek = appModule.hashPasswordPBKDF2('KepsekPass123!', saltKepsek, 1000);

  const saltWali1 = appModule.generateSecureSalt();
  const hashWali1 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali1, 1000);

  const saltWali2 = appModule.generateSecureSalt();
  const hashWali2 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali2, 1000);

  const saltWaliFree = appModule.generateSecureSalt();
  const hashWaliFree = appModule.hashPasswordPBKDF2('WaliPass123!', saltWaliFree, 1000);

  const userHeaders = setupModule.SCHEMA_DEFINITIONS.user;
  const userRows = [
    ['u-kepsek', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'kepsek', hashKepsek, saltKepsek, 'kepala_sekolah', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali1', 'Ahmad Dahlan, S.Pd.', '198502022010011002', 'wali1', hashWali1, saltWali1, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali2', 'Siti Fatimah, S.Pd.', '198803032011012003', 'wali2', hashWali2, saltWali2, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-walifree', 'Guru Belum Bertugas, S.Pd.', '199205052015011005', 'walifree', hashWaliFree, saltWaliFree, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01']
  ];

  const pengHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan;
  const pengRows = [
    ['1', '', 'SD Negeri Percobaan 01', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'u-kepsek', '2026-01-01', '2026-01-01']
  ];

  const taHeaders = setupModule.SCHEMA_DEFINITIONS.tahun_ajaran;
  const taRows = [
    ['ta-locked', '2025/2026', 'Genap', '2026-01-05', '2026-06-20', false, true, '2026-01-01', '2026-01-01'],
    ['ta-aktif', '2026/2027', 'Ganjil', '2026-07-15', '2026-12-20', true, false, '2026-01-01', '2026-01-01']
  ];

  const wkHeaders = setupModule.SCHEMA_DEFINITIONS.wali_kelas;
  const wkRows = [
    ['wk-k1-aktif', 'u-wali1', 'ta-aktif', '1', true, '2026-01-01', '2026-01-01'],
    ['wk-k2-aktif', 'u-wali2', 'ta-aktif', '2', true, '2026-01-01', '2026-01-01'],
    ['wk-k1-locked', 'u-wali1', 'ta-locked', '1', false, '2026-01-01', '2026-01-01']
  ];

  const siswaHeaders = setupModule.SCHEMA_DEFINITIONS.siswa;
  const siswaRows = [
    ['s-01', 'wk-k1-aktif', '0012345678', '1001', '1', 'Budi Cilik', 'L', 'Jakarta', '2019-01-01', 'Ortu Budi', '0812345678', true, '2026-01-01', '2026-01-01'],
    ['s-02', 'wk-k1-aktif', '0012345679', '1002', '2', 'Ani Cantika', 'P', 'Jakarta', '2019-02-02', 'Ortu Ani', '0812345679', true, '2026-01-01', '2026-01-01'],
    ['s-03', 'wk-k2-aktif', '0012345680', '1003', '1', 'Doni Santoso', 'L', 'Bandung', '2018-05-05', 'Ortu Doni', '0812345680', true, '2026-01-01', '2026-01-01'],
    ['s-locked', 'wk-k1-locked', '0012345699', '1099', '1', 'Siswa Masa Lalu', 'L', 'Jakarta', '2018-01-01', 'Ortu Masa Lalu', '0812999999', true, '2026-01-01', '2026-01-01']
  ];

  const mapelHeaders = setupModule.SCHEMA_DEFINITIONS.mata_pelajaran;
  const mapelRows = [
    ['m-01', 'wk-k1-aktif', 'PAI', 'Pendidikan Agama Islam', true, '2026-01-01', '2026-01-01'],
    ['m-02', 'wk-k1-aktif', 'MTK', 'Matematika', true, '2026-01-01', '2026-01-01'],
    ['m-03', 'wk-k2-aktif', 'MTK', 'Matematika', true, '2026-01-01', '2026-01-01'],
    ['m-locked', 'wk-k1-locked', 'IPA', 'Ilmu Pengetahuan Alam', true, '2026-01-01', '2026-01-01']
  ];

  const nilaiMapelHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_mata_pelajaran;
  const nilaiMapelRows = [
    // s-01 dan m-01 memiliki data nilai
    ['nm-01', 's-01', 'm-01', 85, 80, 85, 90, 85, 88, 86, '2026-01-01', '2026-01-01']
  ];

  const nilaiSikapHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_sikap;
  const nilaiSikapRows = [];

  const rekapKehadiranHeaders = setupModule.SCHEMA_DEFINITIONS.rekap_kehadiran;
  const rekapKehadiranRows = [];

  const prHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan_rapor;
  const prRows = [];

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
const mockSS = createPhase5MockEnvironment();
global.getTargetSpreadsheet = () => mockSS;
global.SpreadsheetApp = {
  getActiveSpreadsheet: () => mockSS,
  flush: () => {}
};
global.LockService = {
  getScriptLock: () => ({
    waitLock: () => true,
    releaseLock: () => true
  })
};

// Login user untuk sesi pengujian
const kepsekLogin = appModule.apiLogin('kepsek', 'KepsekPass123!');
assert.strictEqual(kepsekLogin.success, true, 'Login kepala sekolah harus sukses');
const kepsekToken = kepsekLogin.data.token;

const wali1Login = appModule.apiLogin('wali1', 'WaliPass123!');
assert.strictEqual(wali1Login.success, true, 'Login wali kelas 1 harus sukses');
const wali1Token = wali1Login.data.token;

const wali2Login = appModule.apiLogin('wali2', 'WaliPass123!');
assert.strictEqual(wali2Login.success, true, 'Login wali kelas 2 harus sukses');
const wali2Token = wali2Login.data.token;

// ============================================================================
// 1. PENGUJIAN USER MANAGEMENT (KHUSUS KEPALA SEKOLAH)
// ============================================================================
console.log('1. Menguji Modul Pengelolaan User (Kepala Sekolah)...');

// 1A. Wali kelas ditolak mengakses apiGetUsersList
const listByWali = appModule.apiGetUsersList(wali1Token);
assert.strictEqual(listByWali.success, false, 'Wali kelas dilarang mengakses daftar pengguna');
assert.ok(listByWali.message.includes('Akses ditolak') || listByWali.message.includes('izin'));

// 1B. Kepala sekolah memuat daftar user (Verifikasi sanitasi password_hash & salt)
const listByKepsek = appModule.apiGetUsersList(kepsekToken);
assert.strictEqual(listByKepsek.success, true, 'Kepala sekolah berhak memuat daftar pengguna');
assert.ok(Array.isArray(listByKepsek.data));
assert.strictEqual(listByKepsek.data.length, 4);

// Verifikasi TIDAK ADA kebocoran hash dan salt
listByKepsek.data.forEach(u => {
  assert.strictEqual(u.password_hash, undefined, 'password_hash tidak boleh bocor');
  assert.strictEqual(u.password_salt, undefined, 'password_salt tidak boleh bocor');
  assert.ok(u.id && u.nama && u.username && u.role);
});

// 1C. Filter pencarian user (nama / username / NIP)
const searchRes = appModule.apiGetUsersList(kepsekToken, 'Dahlan');
assert.strictEqual(searchRes.success, true);
assert.strictEqual(searchRes.data.length, 1);
assert.strictEqual(searchRes.data[0].username, 'wali1');

// 1D. Validasi Input apiSaveUser (Field Wajib & Format Username)
const saveEmptyNama = appModule.apiSaveUser(kepsekToken, { nama: '', username: 'user_baru', role: 'wali_kelas', password: 'Password123!' });
assert.strictEqual(saveEmptyNama.success, false);
assert.ok(saveEmptyNama.message.includes('Nama lengkap wajib diisi'));

const saveShortUser = appModule.apiSaveUser(kepsekToken, { nama: 'Test User', username: 'ab', role: 'wali_kelas', password: 'Password123!' });
assert.strictEqual(saveShortUser.success, false);
assert.ok(saveShortUser.message.includes('minimal 3 karakter'));

const saveBadRegex = appModule.apiSaveUser(kepsekToken, { nama: 'Test User', username: 'user spasi', role: 'wali_kelas', password: 'Password123!' });
assert.strictEqual(saveBadRegex.success, false);
assert.ok(saveBadRegex.message.includes('huruf kecil'));

const saveBadRole = appModule.apiSaveUser(kepsekToken, { nama: 'Test User', username: 'user_valid', role: 'superadmin', password: 'Password123!' });
assert.strictEqual(saveBadRole.success, false);
assert.ok(saveBadRole.message.includes('Role harus salah satu dari'));

const saveNoPassNew = appModule.apiSaveUser(kepsekToken, { nama: 'Test User', username: 'user_valid', role: 'wali_kelas', password: '' });
assert.strictEqual(saveNoPassNew.success, false);
assert.ok(saveNoPassNew.message.includes('Password wajib diisi'));

// 1E. Validasi Keunikan Username (Case-Insensitive)
const saveDupUser = appModule.apiSaveUser(kepsekToken, { nama: 'Wali Klon', username: 'WALI1', role: 'wali_kelas', password: 'Password123!' });
assert.strictEqual(saveDupUser.success, false);
assert.ok(saveDupUser.message.includes('sudah digunakan'));

// 1F. Validasi Keunikan NIP
const saveDupNip = appModule.apiSaveUser(kepsekToken, { nama: 'Wali NIP Kembar', username: 'wali_baru_nip', nip: '198502022010011002', role: 'wali_kelas', password: 'Password123!' });
assert.strictEqual(saveDupNip.success, false);
assert.ok(saveDupNip.message.includes('NIP') && saveDupNip.message.includes('sudah terdaftar'));

// 1G. Tambah User Baru Sukses (Verifikasi PBKDF2 hash terdaftar di sheet)
const saveNewOk = appModule.apiSaveUser(kepsekToken, {
  nama: 'Guru Baru, S.Pd.',
  nip: '199307072018011007',
  username: 'guru_baru',
  role: 'wali_kelas',
  password: 'RahasiaBaru123!'
});
assert.strictEqual(saveNewOk.success, true);
assert.ok(saveNewOk.data.id);
const newUserId = saveNewOk.data.id;

// Verifikasi akun baru dapat login menggunakan password baru
const newLogin = appModule.apiLogin('guru_baru', 'RahasiaBaru123!');
assert.strictEqual(newLogin.success, true, 'User baru harus dapat login');
assert.strictEqual(newLogin.data.user.role, 'wali_kelas');

// 1H. Edit User yang Ada (Update nama, dan ganti password)
const editUserOk = appModule.apiSaveUser(kepsekToken, {
  id: newUserId,
  nama: 'Guru Baru Sukses, M.Pd.',
  nip: '199307072018011007',
  username: 'guru_baru',
  role: 'wali_kelas',
  password: 'PasswordGanti456!'
});
assert.strictEqual(editUserOk.success, true);

// Verifikasi password lama ditolak, password baru diterima
const loginOldPass = appModule.apiLogin('guru_baru', 'RahasiaBaru123!');
assert.strictEqual(loginOldPass.success, false);
const loginNewPass = appModule.apiLogin('guru_baru', 'PasswordGanti456!');
assert.strictEqual(loginNewPass.success, true);

// 1I. Proteksi Self-Lockout Kepala Sekolah (Tidak boleh menonaktifkan diri sendiri / ganti role)
const editSelfDeactivate = appModule.apiSaveUser(kepsekToken, {
  id: 'u-kepsek',
  nama: 'Drs. H. Subagyo, M.Pd.',
  username: 'kepsek',
  role: 'kepala_sekolah',
  is_active: false
});
assert.strictEqual(editSelfDeactivate.success, false);
assert.ok(editSelfDeactivate.message.includes('tidak dapat menonaktifkan akun Anda sendiri'));

const editSelfDemote = appModule.apiSaveUser(kepsekToken, {
  id: 'u-kepsek',
  nama: 'Drs. H. Subagyo, M.Pd.',
  username: 'kepsek',
  role: 'wali_kelas',
  is_active: true
});
assert.strictEqual(editSelfDemote.success, false);
assert.ok(editSelfDemote.message.includes('tidak dapat mengubah role akun Anda sendiri'));

// 1J. Toggle Status Pengguna
const toggleOff = appModule.apiToggleUserStatus(kepsekToken, newUserId, false);
assert.strictEqual(toggleOff.success, true);
assert.strictEqual(toggleOff.data.is_active, false);

// Login harus ditolak jika akun dinonaktifkan
const loginDisabled = appModule.apiLogin('guru_baru', 'PasswordGanti456!');
assert.strictEqual(loginDisabled.success, false);
assert.ok(loginDisabled.message.includes('dinonaktifkan'));

// Re-aktifkan
const toggleOn = appModule.apiToggleUserStatus(kepsekToken, newUserId, true);
assert.strictEqual(toggleOn.success, true);
assert.strictEqual(toggleOn.data.is_active, true);

// 1K. Proteksi Penghapusan User Relasional & Self-Delete
const delSelf = appModule.apiDeleteUser(kepsekToken, 'u-kepsek');
assert.strictEqual(delSelf.success, false);
assert.ok(delSelf.message.includes('tidak dapat menghapus akun Anda sendiri'));

const delWali1 = appModule.apiDeleteUser(kepsekToken, 'u-wali1'); // u-wali1 punya penugasan di wk-k1-aktif
assert.strictEqual(delWali1.success, false);
assert.ok(delWali1.message.includes('riwayat penugasan kelas') || delWali1.message.includes('tidak dapat dihapus'));

// Hapus user yang belum punya relasi penugasan berhasil
const delNewUser = appModule.apiDeleteUser(kepsekToken, newUserId);
assert.strictEqual(delNewUser.success, true);

console.log('   ✓ Seluruh pengujian User Management (Kepala Sekolah) berhasil lolos 100%.\n');

// ============================================================================
// 2. PENGUJIAN SISWA MANAGEMENT (CRUD, VALIDASI, PERIODE & IDOR)
// ============================================================================
console.log('2. Menguji Modul Pengelolaan Siswa (CRUD, Validasi & IDOR Protection)...');

// 2A. Listing Siswa oleh Wali Kelas 1 (Hanya melihat siswa kelas 1 miliknya)
const siswaListW1 = appModule.apiGetSiswaList(wali1Token);
assert.strictEqual(siswaListW1.success, true);
assert.strictEqual(siswaListW1.data.siswa.length, 2, 'Wali kelas 1 harus melihat 2 siswa di kelasnya');
assert.strictEqual(siswaListW1.data.siswa[0].nama, 'Budi Cilik');
assert.strictEqual(siswaListW1.data.siswa[0].hasGrades, true, 'Budi Cilik memiliki nilai_mata_pelajaran');
assert.strictEqual(siswaListW1.data.siswa[1].nama, 'Ani Cantika');
assert.strictEqual(siswaListW1.data.siswa[1].hasGrades, false);

// 2B. Listing Siswa oleh Wali Kelas 2 (Hanya melihat siswa kelas 2 miliknya)
const siswaListW2 = appModule.apiGetSiswaList(wali2Token);
assert.strictEqual(siswaListW2.success, true);
assert.strictEqual(siswaListW2.data.siswa.length, 1);
assert.strictEqual(siswaListW2.data.siswa[0].nama, 'Doni Santoso');

// 2C. Pencegahan IDOR pada apiGetSiswaList: Wali Kelas 1 mencoba request wali_kelas_id milik Kelas 2
const idorGetSiswa = appModule.apiGetSiswaList(wali1Token, 'wk-k2-aktif');
assert.strictEqual(idorGetSiswa.success, false, 'Wali kelas 1 tidak boleh membaca siswa rombel wali kelas 2');
assert.ok(idorGetSiswa.message.includes('Akses ditolak'));

// 2D. Kepala Sekolah dapat melihat siswa kelas manapun
const siswaKepsekK2 = appModule.apiGetSiswaList(kepsekToken, 'wk-k2-aktif');
assert.strictEqual(siswaKepsekK2.success, true);
assert.strictEqual(siswaKepsekK2.data.siswa.length, 1);
assert.strictEqual(siswaKepsekK2.data.siswa[0].nama, 'Doni Santoso');

// 2E. Validasi Input Tambah Siswa (Field Wajib, No Absen, Jenis Kelamin, NISN)
const addSiswaEmptyNama = appModule.apiSaveSiswa(wali1Token, { nama: '', no_absen: 3, jenis_kelamin: 'L' });
assert.strictEqual(addSiswaEmptyNama.success, false);
assert.ok(addSiswaEmptyNama.message.includes('Nama lengkap siswa wajib diisi'));

const addSiswaBadAbsen = appModule.apiSaveSiswa(wali1Token, { nama: 'Rico', no_absen: 0, jenis_kelamin: 'L' });
assert.strictEqual(addSiswaBadAbsen.success, false);
assert.ok(addSiswaBadAbsen.message.includes('Nomor absen wajib berupa bilangan bulat positif'));

const addSiswaBadJk = appModule.apiSaveSiswa(wali1Token, { nama: 'Rico', no_absen: 3, jenis_kelamin: 'X' });
assert.strictEqual(addSiswaBadJk.success, false);
assert.ok(addSiswaBadJk.message.includes('Jenis kelamin harus salah satu dari: L'));

const addSiswaBadNisn = appModule.apiSaveSiswa(wali1Token, { nama: 'Rico', no_absen: 3, jenis_kelamin: 'L', nisn: 'abc' });
assert.strictEqual(addSiswaBadNisn.success, false);
assert.ok(addSiswaBadNisn.message.includes('Format NISN'));

// 2F. Validasi Keunikan Nomor Absen dalam Rombel Kelas
const addSiswaDupAbsen = appModule.apiSaveSiswa(wali1Token, { nama: 'Rico', no_absen: 1, jenis_kelamin: 'L' });
assert.strictEqual(addSiswaDupAbsen.success, false);
assert.ok(addSiswaDupAbsen.message.includes('sudah digunakan oleh siswa Budi Cilik'));

// 2G. Validasi Keunikan NISN dan NIS di Lingkup Sekolah
const addSiswaDupNisn = appModule.apiSaveSiswa(wali1Token, { nama: 'Rico', no_absen: 3, jenis_kelamin: 'L', nisn: '0012345680' }); // NISN Doni di Kelas 2
assert.strictEqual(addSiswaDupNisn.success, false);
assert.ok(addSiswaDupNisn.message.includes('NISN "0012345680" sudah terdaftar'));

const addSiswaDupNis = appModule.apiSaveSiswa(wali1Token, { nama: 'Rico', no_absen: 3, jenis_kelamin: 'L', nis: '1003' }); // NIS Doni di Kelas 2
assert.strictEqual(addSiswaDupNis.success, false);
assert.ok(addSiswaDupNis.message.includes('NIS "1003" sudah terdaftar'));

// 2H. Tambah Siswa Sukses pada Kelas 1
const addSiswaOk = appModule.apiSaveSiswa(wali1Token, {
  nama: 'Rico Pratama',
  no_absen: 3,
  jenis_kelamin: 'L',
  nisn: '0012345690',
  nis: '1005',
  tempat_lahir: 'Jakarta',
  tanggal_lahir: '2019-03-03',
  wali_murid: 'Hendra Pratama',
  nomor_telepon: '0812345600'
});
assert.strictEqual(addSiswaOk.success, true);
assert.ok(addSiswaOk.data.id);
const newSiswaId = addSiswaOk.data.id;

// 2I. Pencegahan IDOR pada Edit Siswa: Wali Kelas 2 mencoba edit siswa Kelas 1 (s-01)
const editSiswaIdor = appModule.apiSaveSiswa(wali2Token, {
  id: 's-01',
  nama: 'Budi Dibajak',
  no_absen: 1,
  jenis_kelamin: 'L'
});
assert.strictEqual(editSiswaIdor.success, false);
assert.ok(editSiswaIdor.message.includes('Akses ditolak') || editSiswaIdor.message.includes('izin'));

// 2J. Edit Siswa Sah oleh Wali Kelas 1
const editSiswaOk = appModule.apiSaveSiswa(wali1Token, {
  id: newSiswaId,
  nama: 'Rico Pratama, Jr.',
  no_absen: 3,
  jenis_kelamin: 'L',
  nisn: '0012345690',
  nis: '1005'
});
assert.strictEqual(editSiswaOk.success, true);

// 2K. Proteksi Periode Terkunci: Menolak tambah atau edit siswa pada penugasan periode terkunci
const saveSiswaLockedPeriod = appModule.apiSaveSiswa(kepsekToken, {
  wali_kelas_id: 'wk-k1-locked',
  nama: 'Siswa Baru Periode Lama',
  no_absen: 2,
  jenis_kelamin: 'L'
});
assert.strictEqual(saveSiswaLockedPeriod.success, false);
assert.ok(saveSiswaLockedPeriod.message.includes('Periode akademik telah dikunci'));

// 2L. Toggle Status Siswa & Pencegahan IDOR
const toggleSiswaIdor = appModule.apiToggleSiswaStatus(wali2Token, 's-02', false); // Wali 2 coba nonaktifkan siswa Wali 1
assert.strictEqual(toggleSiswaIdor.success, false);
assert.ok(toggleSiswaIdor.message.includes('Akses ditolak') || toggleSiswaIdor.message.includes('wewenang'));

const toggleSiswaOk = appModule.apiToggleSiswaStatus(wali1Token, newSiswaId, false);
assert.strictEqual(toggleSiswaOk.success, true);
assert.strictEqual(toggleSiswaOk.data.is_active, false);

// 2M. Proteksi Integritas Penghapusan Siswa (Data Historis Nilai & IDOR)
// IDOR check: Wali 2 coba hapus siswa Wali 1
const delSiswaIdor = appModule.apiDeleteSiswa(wali2Token, newSiswaId);
assert.strictEqual(delSiswaIdor.success, false);
assert.ok(delSiswaIdor.message.includes('Akses ditolak') || delSiswaIdor.message.includes('wewenang'));

// Proteksi Nilai: Budi Cilik (s-01) memiliki nilai_mata_pelajaran
const delSiswaWithGrades = appModule.apiDeleteSiswa(wali1Token, 's-01');
assert.strictEqual(delSiswaWithGrades.success, false);
assert.ok(delSiswaWithGrades.message.includes('riwayat nilai') && delSiswaWithGrades.message.includes('tidak boleh dihapus permanen'));

// Hapus siswa tanpa riwayat nilai (newSiswaId) berhasil
const delSiswaOk = appModule.apiDeleteSiswa(wali1Token, newSiswaId);
assert.strictEqual(delSiswaOk.success, true);

console.log('   ✓ Seluruh pengujian Siswa Management (CRUD, Validasi & IDOR) berhasil lolos 100%.\n');

// ============================================================================
// 3. PENGUJIAN MATA PELAJARAN MANAGEMENT (CRUD, VALIDASI, PERIODE & IDOR)
// ============================================================================
console.log('3. Menguji Modul Mata Pelajaran (CRUD, Validasi & IDOR Protection)...');

// 3A. Listing Mapel oleh Wali Kelas 1
const mapelListW1 = appModule.apiGetMataPelajaranList(wali1Token);
assert.strictEqual(mapelListW1.success, true);
assert.strictEqual(mapelListW1.data.mataPelajaran.length, 2);
const paiItem = mapelListW1.data.mataPelajaran.find(m => m.kode_mata_pelajaran === 'PAI');
assert.ok(paiItem);
assert.strictEqual(paiItem.hasGrades, true, 'PAI memiliki nilai_mata_pelajaran');
const mtkItem = mapelListW1.data.mataPelajaran.find(m => m.kode_mata_pelajaran === 'MTK');
assert.ok(mtkItem);
assert.strictEqual(mtkItem.hasGrades, false);

// 3B. Validasi Input Mapel (Kode & Nama)
const addMapelEmptyKode = appModule.apiSaveMataPelajaran(wali1Token, { kode_mata_pelajaran: '', mata_pelajaran: 'Bahasa Indonesia' });
assert.strictEqual(addMapelEmptyKode.success, false);
assert.ok(addMapelEmptyKode.message.includes('Kode mata pelajaran wajib diisi'));

const addMapelEmptyNama = appModule.apiSaveMataPelajaran(wali1Token, { kode_mata_pelajaran: 'BIN', mata_pelajaran: '' });
assert.strictEqual(addMapelEmptyNama.success, false);
assert.ok(addMapelEmptyNama.message.includes('Nama mata pelajaran wajib diisi'));

// 3C. Validasi Keunikan Kode Mapel dalam Penugasan Kelas
const addMapelDupKode = appModule.apiSaveMataPelajaran(wali1Token, { kode_mata_pelajaran: 'mtk', mata_pelajaran: 'Matematika Lanjutan' });
assert.strictEqual(addMapelDupKode.success, false);
assert.ok(addMapelDupKode.message.includes('sudah digunakan pada kelas ini'));

// 3D. Validasi Keunikan Nama Mapel dalam Penugasan Kelas
const addMapelDupNama = appModule.apiSaveMataPelajaran(wali1Token, { kode_mata_pelajaran: 'MAT', mata_pelajaran: 'Matematika' });
assert.strictEqual(addMapelDupNama.success, false);
assert.ok(addMapelDupNama.message.includes('sudah terdaftar pada kelas ini'));

// 3E. Tambah Mata Pelajaran Baru Sukses
const addMapelOk = appModule.apiSaveMataPelajaran(wali1Token, {
  kode_mata_pelajaran: 'BIN',
  mata_pelajaran: 'Bahasa Indonesia'
});
assert.strictEqual(addMapelOk.success, true);
assert.ok(addMapelOk.data.id);
const newMapelId = addMapelOk.data.id;

// 3F. Pencegahan IDOR pada Edit Mapel: Wali Kelas 2 dilarang mengedit mapel Kelas 1
const editMapelIdor = appModule.apiSaveMataPelajaran(wali2Token, {
  id: 'm-01',
  kode_mata_pelajaran: 'PAI',
  mata_pelajaran: 'Agama Islam Mod'
});
assert.strictEqual(editMapelIdor.success, false);
assert.ok(editMapelIdor.message.includes('Akses ditolak') || editMapelIdor.message.includes('wewenang'));

// 3G. Edit Mapel Sah oleh Wali Kelas 1
const editMapelOk = appModule.apiSaveMataPelajaran(wali1Token, {
  id: newMapelId,
  kode_mata_pelajaran: 'BIND',
  mata_pelajaran: 'Bahasa Indonesia & Sastra'
});
assert.strictEqual(editMapelOk.success, true);

// 3H. Proteksi Periode Terkunci pada Mapel
const saveMapelLocked = appModule.apiSaveMataPelajaran(kepsekToken, {
  wali_kelas_id: 'wk-k1-locked',
  kode_mata_pelajaran: 'IPS',
  mata_pelajaran: 'Ilmu Pengetahuan Sosial'
});
assert.strictEqual(saveMapelLocked.success, false);
assert.ok(saveMapelLocked.message.includes('Periode akademik telah dikunci'));

// 3I. Toggle Status Mapel & Pencegahan IDOR
const toggleMapelIdor = appModule.apiToggleMataPelajaranStatus(wali2Token, 'm-01', false);
assert.strictEqual(toggleMapelIdor.success, false);
assert.ok(toggleMapelIdor.message.includes('Akses ditolak') || toggleMapelIdor.message.includes('wewenang'));

const toggleMapelOk = appModule.apiToggleMataPelajaranStatus(wali1Token, newMapelId, false);
assert.strictEqual(toggleMapelOk.success, true);
assert.strictEqual(toggleMapelOk.data.is_active, false);

// 3J. Proteksi Integritas Penghapusan Mapel (Riwayat Nilai & IDOR)
// IDOR check
const delMapelIdor = appModule.apiDeleteMataPelajaran(wali2Token, newMapelId);
assert.strictEqual(delMapelIdor.success, false);
assert.ok(delMapelIdor.message.includes('Akses ditolak') || delMapelIdor.message.includes('wewenang'));

// Proteksi Nilai: PAI (m-01) memiliki nilai_mata_pelajaran
const delMapelWithGrades = appModule.apiDeleteMataPelajaran(wali1Token, 'm-01');
assert.strictEqual(delMapelWithGrades.success, false);
assert.ok(delMapelWithGrades.message.includes('riwayat nilai') && delMapelWithGrades.message.includes('tidak dapat dihapus permanen'));

// Hapus mapel tanpa riwayat nilai (newMapelId) berhasil
const delMapelOk = appModule.apiDeleteMataPelajaran(wali1Token, newMapelId);
assert.strictEqual(delMapelOk.success, true);

console.log('   ✓ Seluruh pengujian Mata Pelajaran (CRUD, Validasi & IDOR) berhasil lolos 100%.\n');

// ============================================================================
// 4. PENGUJIAN OTORISASI SESI DAN LEAST PRIVILEGE
// ============================================================================
console.log('4. Menguji Otorisasi Sesi & Akses Tertolak (Security Guards)...');

const badToken = 'token_palsu_random_xyz';

assert.strictEqual(appModule.apiGetUsersList(badToken).success, false);
assert.strictEqual(appModule.apiSaveUser(badToken, {}).success, false);
assert.strictEqual(appModule.apiToggleUserStatus(badToken, 'u-wali1', false).success, false);
assert.strictEqual(appModule.apiDeleteUser(badToken, 'u-wali1').success, false);

assert.strictEqual(appModule.apiGetSiswaList(badToken).success, false);
assert.strictEqual(appModule.apiSaveSiswa(badToken, {}).success, false);
assert.strictEqual(appModule.apiToggleSiswaStatus(badToken, 's-01', false).success, false);
assert.strictEqual(appModule.apiDeleteSiswa(badToken, 's-01').success, false);

assert.strictEqual(appModule.apiGetMataPelajaranList(badToken).success, false);
assert.strictEqual(appModule.apiSaveMataPelajaran(badToken, {}).success, false);
assert.strictEqual(appModule.apiToggleMataPelajaranStatus(badToken, 'm-01', false).success, false);
assert.strictEqual(appModule.apiDeleteMataPelajaran(badToken, 'm-01').success, false);

console.log('   ✓ Seluruh endpoint tertolak secara aman saat sesi tidak valid.\n');

console.log('======================================================');
console.log('SELURUH PENGUJIAN OTOMATIS PHASE 5 BERHASIL LULUS (100% PASS)');
console.log('======================================================\n');
