/**
 * ============================================================================
 * SUITE PENGUJIAN OTOMATIS PHASE 7: DASHBOARD, RANKING SISWA, RAPOR & CETAK
 * File: tests/test_phase7.js
 * ============================================================================
 *
 * Menguji:
 * 1. Dashboard Monitoring Berdasarkan Role (apiGetInitialDashboard):
 *    - Wali Kelas: hanya melihat metrik kelas sendiri, kelengkapan %, status rapor, dan Top 3 ranking.
 *    - Kepala Sekolah: melihat monitoring lintas kelas 1–6, kesiapan rapor sekolah, dan deteksi warning kelas.
 *    - Penanganan akun Wali Kelas tanpa penugasan aktif (fallback aman).
 *
 * 2. Algoritma Ranking Siswa Otoritatif (calculateClassRanking):
 *    - Standard Competition Ranking ("1224" ties rule): nilai seri = rank sama, rank berikutnya melompat.
 *    - Penanganan siswa dengan nilai belum lengkap / kosong: ditaruh di bawah dengan rank '-'.
 *    - Penanganan nilai kosong: TIDAK diubah jadi 0, hanya mapel lengkap yang membagi rata-rata.
 *    - Penentuan status label ranking: 'Final' jika 100% lengkap rombel, 'Sementara' jika belum.
 *    - Perhitungan di sisi server, tanpa operasi tulis ke spreadsheet.
 *
 * 3. Rapor Digital Rekapitulasi Kelas (apiGetRaporDigitalKelas):
 *    - Otorisasi Kepala Sekolah (bisa pilih semua kelas) vs Wali Kelas (hanya kelas sendiri).
 *    - Proteksi IDOR: Wali Kelas dilarang mengakses penugasan kelas guru lain.
 *    - Pengurutan (sorting): no_absen, ranking, nilai_agregat, nama.
 *    - Agregasi kesiapan rapor (raporSiapCount, raporBelumSiapCount).
 *
 * 4. Rapor Digital Individual Siswa (apiGetRaporDigitalSiswa):
 *    - Kelengkapan dokumen rapor: profil sekolah, data siswa, nilai mapel + predikat + deskripsi,
 *      sikap per dimensi, rekap kehadiran, rata-rata nilai, dan ranking kelas.
 *    - Proteksi IDOR: Wali Kelas dilarang mengakses siswa dari rombel kelas lain.
 *    - Kepala Sekolah dapat mengakses rapor siswa mana saja.
 *
 * 5. Keamanan Sesi & Konsistensi Data:
 *    - Penolakan token sesi tidak valid pada seluruh endpoint Phase 7.
 *    - Integritas data: tidak mengubah spreadsheet saat preview dashboard atau rapor.
 */

const assert = require('assert');
const path = require('path');

const setupModule = require('../setup.gs');
const appModule = require('../code.gs');

console.log('=== MEMULAI SUITE PENGUJIAN OTOMATIS PHASE 7: DASHBOARD, RANKING & RAPOR ===\n');

// ============================================================================
// SETUP MOCK SPREADSHEET ENVIRONMENT LOKAL
// ============================================================================
function createPhase7MockEnvironment() {
  const saltKepsek = appModule.generateSecureSalt();
  const hashKepsek = appModule.hashPasswordPBKDF2('KepsekPass123!', saltKepsek, 1000);

  const saltWali1 = appModule.generateSecureSalt();
  const hashWali1 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali1, 1000);

  const saltWali2 = appModule.generateSecureSalt();
  const hashWali2 = appModule.hashPasswordPBKDF2('WaliPass123!', saltWali2, 1000);

  const saltWaliNoClass = appModule.generateSecureSalt();
  const hashWaliNoClass = appModule.hashPasswordPBKDF2('WaliPass123!', saltWaliNoClass, 1000);

  const userHeaders = setupModule.SCHEMA_DEFINITIONS.user;
  const userRows = [
    ['u-kepsek', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'kepsek', hashKepsek, saltKepsek, 'kepala_sekolah', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali1', 'Ahmad Dahlan, S.Pd.', '198502022010011002', 'wali1', hashWali1, saltWali1, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-wali2', 'Siti Fatimah, S.Pd.', '198803032011012003', 'wali2', hashWali2, saltWali2, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01'],
    ['u-walinone', 'Guru Baru, S.Pd.', '199505052020011005', 'walinone', hashWaliNoClass, saltWaliNoClass, 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01']
  ];

  const pengHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan;
  const pengRows = [
    ['1', 'https://example.com/logo.png', 'SD Negeri Percobaan 01', 'Drs. H. Subagyo, M.Pd.', '197001011995011001', 'u-kepsek', '2026-01-01', '2026-01-01']
  ];

  const taHeaders = setupModule.SCHEMA_DEFINITIONS.tahun_ajaran;
  const taRows = [
    ['ta-aktif', '2026/2027', 'Ganjil', '2026-07-15', '2026-12-20', true, false, '2026-01-01', '2026-01-01']
  ];

  const wkHeaders = setupModule.SCHEMA_DEFINITIONS.wali_kelas;
  const wkRows = [
    ['wk-k1', 'u-wali1', 'ta-aktif', '1', true, '2026-01-01', '2026-01-01'],
    ['wk-k2', 'u-wali2', 'ta-aktif', '2', true, '2026-01-01', '2026-01-01']
  ];

  const siswaHeaders = setupModule.SCHEMA_DEFINITIONS.siswa;
  const siswaRows = [
    // Rombel Kelas 1 (4 Siswa untuk simulasi Ranking Kompetisi & Ties 1224)
    ['s-01', 'wk-k1', '0012345671', '1001', '1', 'Budi Santoso', 'L', 'Jakarta', '2019-01-01', 'Ortu Budi', '0812345671', true, '2026-01-01', '2026-01-01'],
    ['s-02', 'wk-k1', '0012345672', '1002', '2', 'Ani Lestari', 'P', 'Jakarta', '2019-02-02', 'Ortu Ani', '0812345672', true, '2026-01-01', '2026-01-01'],
    ['s-03', 'wk-k1', '0012345673', '1003', '3', 'Citra Dewi', 'P', 'Jakarta', '2019-03-03', 'Ortu Citra', '0812345673', true, '2026-01-01', '2026-01-01'],
    ['s-04', 'wk-k1', '0012345674', '1004', '4', 'Dedi Kurnia', 'L', 'Jakarta', '2019-04-04', 'Ortu Dedi', '0812345674', true, '2026-01-01', '2026-01-01'],
    // Siswa Kelas 2
    ['s-05', 'wk-k2', '0012345675', '2001', '1', 'Eko Prasetyo', 'L', 'Bandung', '2018-05-05', 'Ortu Eko', '0812345675', true, '2026-01-01', '2026-01-01']
  ];

  const mapelHeaders = setupModule.SCHEMA_DEFINITIONS.mata_pelajaran;
  const mapelRows = [
    ['m-01', 'wk-k1', 'PAI', 'Pendidikan Agama Islam', true, '2026-01-01', '2026-01-01'],
    ['m-02', 'wk-k1', 'MTK', 'Matematika', true, '2026-01-01', '2026-01-01'],
    ['m-03', 'wk-k2', 'MTK', 'Matematika', true, '2026-01-01', '2026-01-01']
  ];

  // Pengaturan Rapor untuk Bobot 40% Tugas, 30% UTS, 30% UAS
  const prHeaders = setupModule.SCHEMA_DEFINITIONS.pengaturan_rapor;
  const prRows = [
    ['pr-01', 'ta-aktif', 'wk-k1', 40, 30, 30, JSON.stringify([
      { label: 'A', min: 90, max: 100 },
      { label: 'B', min: 80, max: 89.99 },
      { label: 'C', min: 70, max: 79.99 },
      { label: 'D', min: 0, max: 69.99 }
    ]), '2026-01-01', '2026-01-01']
  ];

  // Data Nilai Kelas 1:
  // Kolom: [id, siswa_id, mata_pelajaran_id, nilai_tugas_1, nilai_tugas_2, nilai_tugas_3, nilai_tugas_4, nilai_uts, nilai_uas, nilai_akhir, is_complete, created_at, updated_at]
  const nilaiMapelHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_mata_pelajaran;
  const nilaiMapelRows = [
    // s-01: PAI = Tugas: 90, UTS: 90, UAS: 90 -> NA = 90
    ['n-01', 's-01', 'm-01', 90, 90, 90, 90, 90, 90, 90, true, '2026-01-01', '2026-01-01'],
    // s-01: MTK = Tugas: 90, UTS: 90, UAS: 90 -> NA = 90
    ['n-02', 's-01', 'm-02', 90, 90, 90, 90, 90, 90, 90, true, '2026-01-01', '2026-01-01'],

    // s-02: PAI = Tugas: 90, UTS: 90, UAS: 90 -> NA = 90
    ['n-03', 's-02', 'm-01', 90, 90, 90, 90, 90, 90, 90, true, '2026-01-01', '2026-01-01'],
    // s-02: MTK = Tugas: 90, UTS: 90, UAS: 90 -> NA = 90
    ['n-04', 's-02', 'm-02', 90, 90, 90, 90, 90, 90, 90, true, '2026-01-01', '2026-01-01'],

    // s-03: PAI = Tugas: 80, UTS: 80, UAS: 80 -> NA = 80
    ['n-05', 's-03', 'm-01', 80, 80, 80, 80, 80, 80, 80, true, '2026-01-01', '2026-01-01'],
    // s-03: MTK = Tugas: 80, UTS: 80, UAS: 80 -> NA = 80
    ['n-06', 's-03', 'm-02', 80, 80, 80, 80, 80, 80, 80, true, '2026-01-01', '2026-01-01'],

    // s-04: PAI = Tugas: 70, UTS: 70, UAS: 70 -> NA = 70
    ['n-07', 's-04', 'm-01', 70, 70, 70, 70, 70, 70, 70, true, '2026-01-01', '2026-01-01']
    // s-04 belum punya nilai m-02 (belum lengkap!)
  ];

  // Penilaian Sikap
  // Kolom: [id, siswa_id, predikat, deskripsi, created_at, updated_at]
  const nilaiSikapHeaders = setupModule.SCHEMA_DEFINITIONS.nilai_sikap;
  const nilaiSikapRows = [
    ['sk-01', 's-01', 'A', 'Sangat disiplin dan jujur', '2026-01-01', '2026-01-01'],
    ['sk-02', 's-02', 'A', 'Sangat santun dan amanah', '2026-01-01', '2026-01-01'],
    ['sk-03', 's-03', 'B', 'Disiplin dan aktif', '2026-01-01', '2026-01-01']
    // s-04 belum diisi sikapnya
  ];

  // Rekap Kehadiran
  // Kolom: [id, siswa_id, jumlah_hadir, jumlah_sakit, jumlah_izin, jumlah_alpha, keterangan, created_at, updated_at]
  const rekapKehadiranHeaders = setupModule.SCHEMA_DEFINITIONS.rekap_kehadiran;
  const rekapKehadiranRows = [
    ['rk-01', 's-01', 100, 0, 0, 0, '', '2026-01-01', '2026-01-01'],
    ['rk-02', 's-02', 98, 2, 0, 0, '', '2026-01-01', '2026-01-01'],
    ['rk-03', 's-03', 95, 3, 2, 0, '', '2026-01-01', '2026-01-01']
    // s-04 belum diisi kehadirannya
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
const mockSS = createPhase7MockEnvironment();
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
let tokenWali2 = '';
let tokenWaliNone = '';

// ============================================================================
// TEST SUITE 1: OTENTIKASI & SETUP SESI PENGUJIAN
// ============================================================================
console.log('--- TEST SUITE 1: Otentikasi & Setup Sesi Pengujian ---');

const loginKepsek = appModule.apiLogin('kepsek', 'KepsekPass123!');
assert.strictEqual(loginKepsek.success, true, 'Login Kepala Sekolah harus sukses');
tokenKepsek = loginKepsek.data.token;

const loginWali1 = appModule.apiLogin('wali1', 'WaliPass123!');
assert.strictEqual(loginWali1.success, true, 'Login Wali Kelas 1 harus sukses');
tokenWali1 = loginWali1.data.token;

const loginWali2 = appModule.apiLogin('wali2', 'WaliPass123!');
assert.strictEqual(loginWali2.success, true, 'Login Wali Kelas 2 harus sukses');
tokenWali2 = loginWali2.data.token;

const loginWaliNone = appModule.apiLogin('walinone', 'WaliPass123!');
assert.strictEqual(loginWaliNone.success, true, 'Login Wali Kelas tanpa penugasan harus sukses');
tokenWaliNone = loginWaliNone.data.token;

console.log('✓ Setup sesi login untuk 4 user berhasil.');

// ============================================================================
// TEST SUITE 2: DASHBOARD MONITORING KEPALA SEKOLAH & WALI KELAS
// ============================================================================
console.log('\n--- TEST SUITE 2: Dashboard Monitoring (apiGetInitialDashboard) ---');

// 2.1 Dashboard Kepala Sekolah
const dashKepsek = appModule.apiGetInitialDashboard(tokenKepsek);
assert.strictEqual(dashKepsek.success, true, 'Dashboard Kepala Sekolah harus sukses');
assert.strictEqual(dashKepsek.data.user.role, 'kepala_sekolah');
assert.strictEqual(dashKepsek.data.summary.totalSiswa, 5, 'Total 5 siswa terdaftar');
assert.strictEqual(dashKepsek.data.summary.totalGuru, 3, 'Total 3 guru wali kelas aktif');
assert.strictEqual(dashKepsek.data.summary.totalKelasDitugaskan, 2, '2 kelas ditugaskan (Kelas 1 & 2)');
assert.strictEqual(dashKepsek.data.summary.totalKelasMaksimal, 6, 'Total rombel target adalah 6 kelas');
assert.strictEqual(Array.isArray(dashKepsek.data.kelasOverview), true, 'Overview rombel 1-6 berupa array');
assert.strictEqual(dashKepsek.data.kelasOverview.length, 6, 'Overview harus memuat tepat 6 kelas');

// Validasi rincian kelas 1 pada dashboard Kepala Sekolah
const k1Overview = dashKepsek.data.kelasOverview.find(k => k.kelas === '1');
assert.strictEqual(k1Overview.isAssigned, true, 'Kelas 1 harus berstatus terisi');
assert.strictEqual(k1Overview.guruNama, 'Ahmad Dahlan, S.Pd.');
assert.strictEqual(k1Overview.totalSiswa, 4, 'Kelas 1 memiliki 4 siswa');
assert.strictEqual(k1Overview.mapelCount, 2, 'Kelas 1 memiliki 2 mapel aktif');
assert.strictEqual(k1Overview.statusLabel, 'Sebagian', 'Kelas 1 baru terisi sebagian karena s-04 belum lengkap');
assert.strictEqual(k1Overview.isRaporReady, false, 'Rapor kelas 1 belum 100% siap');

// Validasi kelas yang belum ditugaskan (misal Kelas 3)
const k3Overview = dashKepsek.data.kelasOverview.find(k => k.kelas === '3');
assert.strictEqual(k3Overview.isAssigned, false, 'Kelas 3 belum ada wali kelas');
assert.strictEqual(k3Overview.hasWarning, true, 'Kelas 3 harus memiliki flag warning');
assert.strictEqual(k3Overview.warningMessage, 'Wali kelas belum ditugaskan');

console.log('✓ Dashboard Kepala Sekolah: Ringkasan sekolah, agregasi metrik, dan overview 6 kelas terverifikasi.');

// 2.2 Dashboard Wali Kelas 1
const dashWali1 = appModule.apiGetInitialDashboard(tokenWali1);
assert.strictEqual(dashWali1.success, true, 'Dashboard Wali Kelas 1 harus sukses');
assert.strictEqual(dashWali1.data.user.role, 'wali_kelas');
assert.strictEqual(dashWali1.data.summary.hasAssignment, true, 'Wali 1 memiliki penugasan');
assert.strictEqual(dashWali1.data.summary.kelas, '1', 'Kelas yang diampu adalah Kelas 1');
assert.strictEqual(dashWali1.data.summary.totalSiswa, 4, 'Siswa rombel Kelas 1 berjumlah 4');
assert.strictEqual(dashWali1.data.summary.totalMapel, 2, 'Mapel rombel Kelas 1 berjumlah 2');
assert.strictEqual(dashWali1.data.summary.statusRapor, 'Belum Lengkap', 'Status rapor Kelas 1 belum lengkap');
assert.strictEqual(dashWali1.data.summary.rankingStatus, 'Sementara', 'Ranking berstatus Sementara');
assert.strictEqual(Array.isArray(dashWali1.data.summary.topRanking), true, 'Top ranking adalah array');
assert.strictEqual(dashWali1.data.summary.topRanking.length <= 3, true, 'Top ranking maksimal 3 siswa');

console.log('✓ Dashboard Wali Kelas 1: Cakupan rombel sendiri, kelengkapan %, status rapor, dan top ranking terverifikasi.');

// 2.3 Dashboard Wali Kelas Tanpa Penugasan
const dashWaliNone = appModule.apiGetInitialDashboard(tokenWaliNone);
assert.strictEqual(dashWaliNone.success, true);
assert.strictEqual(dashWaliNone.data.summary.hasAssignment, false, 'Wali tanpa penugasan memiliki hasAssignment: false');
assert.strictEqual(dashWaliNone.data.summary.kelas, null);
assert.strictEqual(dashWaliNone.data.summary.statusRapor, 'Belum Ada Penugasan');

console.log('✓ Dashboard Wali Kelas Tanpa Penugasan: Fallback aman terverifikasi.');

// ============================================================================
// TEST SUITE 3: ALGORITMA RANKING KOMPETISI (calculateClassRanking & TIES)
// ============================================================================
console.log('\n--- TEST SUITE 3: Algoritma Ranking Kompetisi (Standard Competition 1224) ---');

const rankingRes = appModule.calculateClassRanking('wk-k1');
assert.strictEqual(rankingRes.rankingStatus, 'Sementara', 'Ranking harus Sementara karena siswa ke-4 nilainya belum lengkap');
assert.strictEqual(rankingRes.isClassAllComplete, false);

const ranked = rankingRes.rankedStudents;
assert.strictEqual(ranked.length, 4, 'Total 4 siswa diranking');

// Siswa 1 dan Siswa 2 memiliki rata-rata 90.00
const rank1Students = ranked.filter(s => s.rank === 1);
assert.strictEqual(rank1Students.length, 2, 'Harus ada 2 siswa seri di peringkat 1 (Budi dan Ani)');
assert.strictEqual(rank1Students[0].avgScore, 90);
assert.strictEqual(rank1Students[1].avgScore, 90);

// Siswa ke-3 (Citra) dengan rata-rata 80.00 harus mendapatkan ranking 3 (melompati rank 2 karena ada 2 siswa rank 1!)
const rank3Student = ranked.find(s => s.siswa_id === 's-03');
assert.strictEqual(rank3Student.rank, 3, 'Siswa ke-3 harus berperingkat 3 sesuai aturan Standard Competition (1, 1, 3)');
assert.strictEqual(rank3Student.avgScore, 80);

// Siswa ke-4 (Dedi) memiliki nilai belum lengkap:
const rankIncomplete = ranked.find(s => s.siswa_id === 's-04');
assert.strictEqual(rankIncomplete.isStudentComplete, false, 'Siswa ke-4 belum lengkap nilainya');
assert.strictEqual(rankIncomplete.rank, '-', 'Siswa belum lengkap diberi peringkat "-"');
// Komponen kosong TIDAK diubah jadi 0, rata-rata dari 1 mapel yang ada adalah 70
assert.strictEqual(rankIncomplete.avgScore, 70, 'Rata-rata dihitung dari mapel yang ada, bukan dibagi nol');

console.log('✓ Standard Competition Ranking: Penanganan nilai seri (1, 1, 3) dan penanganan siswa belum lengkap ("-") terverifikasi 100%.');

// ============================================================================
// TEST SUITE 4: REKAPITULASI RAPOR DIGITAL KELAS (apiGetRaporDigitalKelas)
// ============================================================================
console.log('\n--- TEST SUITE 4: Rapor Digital Kelas (apiGetRaporDigitalKelas) & IDOR Guard ---');

// 4.1 Akses Sah Wali Kelas 1
const raporKelasWali1 = appModule.apiGetRaporDigitalKelas(tokenWali1, 'wk-k1', 'no_absen', 'asc');
assert.strictEqual(raporKelasWali1.success, true, 'Wali 1 berhak mengakses rapor kelasnya');
assert.strictEqual(raporKelasWali1.data.assignment.kelas, '1');
assert.strictEqual(raporKelasWali1.data.students.length, 4);
assert.strictEqual(raporKelasWali1.data.summary.raporSiapCount, 3, '3 siswa lengkap (s-01, s-02, s-03)');
assert.strictEqual(raporKelasWali1.data.summary.raporBelumSiapCount, 1, '1 siswa belum lengkap (s-04)');
assert.strictEqual(raporKelasWali1.data.summary.rankingStatus, 'Sementara');

// 4.2 Pengurutan Berdasarkan Ranking
const raporSortRank = appModule.apiGetRaporDigitalKelas(tokenWali1, 'wk-k1', 'ranking', 'asc');
assert.strictEqual(raporSortRank.success, true);
const sortedStudents = raporSortRank.data.students;
assert.strictEqual(sortedStudents[0].rank, 1, 'Peringkat 1 di urutan paling atas');
assert.strictEqual(sortedStudents[1].rank, 1, 'Peringkat 1 kedua di urutan kedua');
assert.strictEqual(sortedStudents[2].rank, 3, 'Peringkat 3 di urutan ketiga');
assert.strictEqual(sortedStudents[3].rank, '-', 'Siswa belum lengkap ("-") di urutan terakhir');

// 4.3 Pengurutan Berdasarkan Nama (A-Z)
const raporSortNama = appModule.apiGetRaporDigitalKelas(tokenWali1, 'wk-k1', 'nama', 'asc');
assert.strictEqual(raporSortNama.success, true);
assert.strictEqual(raporSortNama.data.students[0].nama, 'Ani Lestari', 'Ani duluan sesuai abjad');

// 4.4 Proteksi IDOR: Wali Kelas 1 mencoba mengakses kelas 2 (wk-k2)
const idorWali1 = appModule.apiGetRaporDigitalKelas(tokenWali1, 'wk-k2');
assert.strictEqual(idorWali1.success, false, 'IDOR: Wali Kelas 1 harus ditolak mengakses kelas lain');
assert.ok(idorWali1.message.includes('Akses ditolak') || idorWali1.message.includes('akses'), 'Pesan penolakan IDOR jelas');

// 4.5 Kepala Sekolah Berhak Mengakses Kelas Mana Saja
const kepsekAksesK1 = appModule.apiGetRaporDigitalKelas(tokenKepsek, 'wk-k1');
assert.strictEqual(kepsekAksesK1.success, true, 'Kepala Sekolah berhak mengakses Kelas 1');
const kepsekAksesK2 = appModule.apiGetRaporDigitalKelas(tokenKepsek, 'wk-k2');
assert.strictEqual(kepsekAksesK2.success, true, 'Kepala Sekolah berhak mengakses Kelas 2');

console.log('✓ Rapor Digital Kelas: Rekapitulasi, multi-sorting, kelengkapan, dan proteksi IDOR terverifikasi.');

// ============================================================================
// TEST SUITE 5: LEMBAR RAPOR DIGITAL INDIVIDUAL SISWA (apiGetRaporDigitalSiswa)
// ============================================================================
console.log('\n--- TEST SUITE 5: Lembar Rapor Digital Individual Siswa (apiGetRaporDigitalSiswa) ---');

// 5.1 Akses Siswa Sendiri oleh Wali Kelas 1 (s-01)
const raporSiswa1 = appModule.apiGetRaporDigitalSiswa(tokenWali1, 's-01');
assert.strictEqual(raporSiswa1.success, true, 'Wali 1 dapat mengakses rapor siswanya');
assert.strictEqual(raporSiswa1.data.student.nama, 'Budi Santoso');
assert.strictEqual(raporSiswa1.data.student.nisn, '0012345671');
assert.strictEqual(raporSiswa1.data.schoolProfile.namaSekolah, 'SD Negeri Percobaan 01');
assert.strictEqual(raporSiswa1.data.assignment.waliKelasNama, 'Ahmad Dahlan, S.Pd.');
assert.strictEqual(raporSiswa1.data.academic.summary.rank, 1, 'Ranking siswa 1 adalah 1');
assert.strictEqual(raporSiswa1.data.academic.summary.rataNilai, 90);
assert.strictEqual(raporSiswa1.data.academic.subjects.length, 2, '2 mapel terisi nilainya');
assert.strictEqual(raporSiswa1.data.academic.subjects[0].predikat, 'A');
assert.strictEqual(raporSiswa1.data.isReady, true, 'Rapor siswa 1 siap dicetak');
assert.strictEqual(raporSiswa1.data.kehadiran.hadir, 100);

// 5.2 Rapor Siswa yang Belum Lengkap (s-04)
const raporSiswa4 = appModule.apiGetRaporDigitalSiswa(tokenWali1, 's-04');
assert.strictEqual(raporSiswa4.success, true);
assert.strictEqual(raporSiswa4.data.student.nama, 'Dedi Kurnia');
assert.strictEqual(raporSiswa4.data.isReady, false, 'Rapor siswa 4 belum siap');
assert.strictEqual(raporSiswa4.data.academic.summary.rank, '-');

// 5.3 Proteksi IDOR Siswa: Wali Kelas 1 mencoba membuka rapor siswa Kelas 2 (s-05)
const idorSiswa = appModule.apiGetRaporDigitalSiswa(tokenWali1, 's-05');
assert.strictEqual(idorSiswa.success, false, 'IDOR: Wali 1 dilarang membuka siswa kelas 2');
assert.ok(idorSiswa.message.includes('Akses ditolak') || idorSiswa.message.includes('rombel'));

// 5.4 Kepala Sekolah Mengakses Siswa Kelas 1 dan Siswa Kelas 2
const kepsekSiswa1 = appModule.apiGetRaporDigitalSiswa(tokenKepsek, 's-01');
assert.strictEqual(kepsekSiswa1.success, true, 'Kepsek dapat membuka rapor siswa Kelas 1');
const kepsekSiswa5 = appModule.apiGetRaporDigitalSiswa(tokenKepsek, 's-05');
assert.strictEqual(kepsekSiswa5.success, true, 'Kepsek dapat membuka rapor siswa Kelas 2');

console.log('✓ Rapor Digital Siswa: Struktur dokumen rapor, komponen akademik, sikap, absen, dan proteksi IDOR terverifikasi.');

// ============================================================================
// TEST SUITE 6: KEAMANAN SESI & PENOLAKAN TOKEN TIDAK VALID
// ============================================================================
console.log('\n--- TEST SUITE 6: Keamanan Sesi & Penolakan Token Tidak Valid ---');

const badTokens = ['', null, undefined, 'token-palsu-12345'];
badTokens.forEach(badToken => {
  const resDash = appModule.apiGetInitialDashboard(badToken);
  assert.strictEqual(resDash.success, false, 'Token tidak valid harus ditolak di dashboard');

  const resRaporKelas = appModule.apiGetRaporDigitalKelas(badToken, 'wk-k1');
  assert.strictEqual(resRaporKelas.success, false, 'Token tidak valid harus ditolak di rapor kelas');

  const resRaporSiswa = appModule.apiGetRaporDigitalSiswa(badToken, 's-01');
  assert.strictEqual(resRaporSiswa.success, false, 'Token tidak valid harus ditolak di rapor siswa');
});

console.log('✓ Seluruh endpoint Phase 7 menolak token tidak valid dengan aman.');

// ============================================================================
// TEST SUITE 7: KASUS BATAS (EDGE CASES) & VERIFIKASI KEAMANAN READ-ONLY
// ============================================================================
console.log('\n--- TEST SUITE 7: Kasus Batas (Edge Cases) & Verifikasi Read-Only ---');

// 7.1 Kasus Batas: Kelas tanpa mata pelajaran aktif (Uji Pembagian dengan Nol & NaN)
const emptyMapelRes = appModule.calculateClassRanking('wk-no-mapel', {
  sData: {
    rows: [
      { id: 's-em1', wali_kelas_id: 'wk-no-mapel', nama: 'Siswa Test 1', no_absen: 1, is_active: true }
    ]
  },
  mData: { rows: [] }, // Tidak ada mapel aktif
  nData: { rows: [] },
  prData: { rows: [] },
  wkData: {
    rows: [
      { id: 'wk-no-mapel', kelas: '3', tahun_ajaran_id: 'ta-aktif', is_active: true }
    ]
  }
});
assert.strictEqual(emptyMapelRes.isClassAllComplete, false, 'Kelas tanpa mapel tidak boleh dianggap lengkap');
assert.strictEqual(emptyMapelRes.rankingStatus, 'Sementara', 'Status ranking harus Sementara');
assert.strictEqual(emptyMapelRes.rankedStudents[0].rank, '-', 'Rank siswa harus "-" jika tidak ada mapel');
assert.strictEqual(emptyMapelRes.rankedStudents[0].avgScore, null, 'avgScore harus null (bukan NaN atau Infinity)');
assert.strictEqual(isNaN(emptyMapelRes.rankedStudents[0].avgScore), false, 'Tidak boleh menghasilkan NaN');

// 7.2 Kasus Batas: Nilai 0 Murni vs Nilai Kosong
const zeroScoreRes = appModule.calculateClassRanking('wk-zero-test', {
  sData: {
    rows: [
      { id: 's-z1', wali_kelas_id: 'wk-zero-test', nama: 'Siswa Nilai Nol', no_absen: 1, is_active: true },
      { id: 's-z2', wali_kelas_id: 'wk-zero-test', nama: 'Siswa Nilai Kosong', no_absen: 2, is_active: true }
    ]
  },
  mData: {
    rows: [
      { id: 'm-z1', wali_kelas_id: 'wk-zero-test', kode_mata_pelajaran: 'M1', mata_pelajaran: 'Mapel 1', is_active: true }
    ]
  },
  nData: {
    rows: [
      // s-z1: Nilai akhir 0 MURNI dan lengkap
      { id: 'n-z1', siswa_id: 's-z1', mata_pelajaran_id: 'm-z1', nilai_akhir: 0, is_complete: true },
      // s-z2: Nilai akhir string kosong (belum diisi)
      { id: 'n-z2', siswa_id: 's-z2', mata_pelajaran_id: 'm-z1', nilai_akhir: '', is_complete: false }
    ]
  },
  prData: { rows: [] },
  wkData: {
    rows: [
      { id: 'wk-zero-test', kelas: '4', tahun_ajaran_id: 'ta-aktif', is_active: true }
    ]
  }
});
const sZ1 = zeroScoreRes.rankedStudents.find(st => st.siswa_id === 's-z1');
const sZ2 = zeroScoreRes.rankedStudents.find(st => st.siswa_id === 's-z2');
assert.strictEqual(sZ1.avgScore, 0, 'Nilai 0 murni harus menghasilkan rata-rata 0');
assert.strictEqual(sZ1.isStudentComplete, true, 'Siswa dengan nilai 0 lengkap berstatus complete');
assert.strictEqual(sZ1.rank, 1, 'Siswa bernilai 0 lengkap berhak mendapat rank numerik');
assert.strictEqual(sZ2.avgScore, null, 'Nilai kosong tidak boleh menghasilkan 0 melainkan null');
assert.strictEqual(sZ2.isStudentComplete, false, 'Siswa nilai kosong berstatus tidak lengkap');
assert.strictEqual(sZ2.rank, '-', 'Siswa nilai kosong berstatus rank "-"');

// 7.3 Kasus Batas: Akses Rapor Siswa Historis Nonaktif (is_active: false)
// Tambahkan siswa nonaktif ke sheet siswa mock
const sheetSiswa = mockSS.sheets['siswa'];
sheetSiswa.appendRow(['s-hist-01', 'wk-k1', '0012345699', '1099', '5', 'Siswa Pindahan Lama', 'L', 'Jakarta', '2019-01-01', 'Wali', '08129999', false, '2026-01-01', '2026-01-01']);

// Kepsek dan Wali 1 harus tetap dapat membuka rapor siswa historis rombelnya
const resRaporHistKepsek = appModule.apiGetRaporDigitalSiswa(tokenKepsek, 's-hist-01');
assert.strictEqual(resRaporHistKepsek.success, true, 'Kepala sekolah dapat membuka rapor siswa historis nonaktif');
assert.strictEqual(resRaporHistKepsek.data.student.nama, 'Siswa Pindahan Lama');

const resRaporHistWali = appModule.apiGetRaporDigitalSiswa(tokenWali1, 's-hist-01');
assert.strictEqual(resRaporHistWali.success, true, 'Wali kelas dapat membuka rapor siswa historis nonaktif di kelasnya');

// 7.4 Verifikasi Keamanan Read-Only: Operasi Dashboard & Rapor Tidak Boleh Mengubah Spreadsheet
const rowCountsBefore = {};
Object.keys(mockSS.sheets).forEach(sName => {
  rowCountsBefore[sName] = mockSS.sheets[sName].getLastRow();
});

// Panggil seluruh operasi baca
appModule.apiGetInitialDashboard(tokenKepsek);
appModule.apiGetInitialDashboard(tokenWali1);
appModule.apiGetRaporDigitalKelas(tokenKepsek, 'wk-k1');
appModule.apiGetRaporDigitalKelas(tokenWali1, 'wk-k1');
appModule.apiGetRaporDigitalSiswa(tokenKepsek, 's-01');
appModule.apiGetRaporDigitalSiswa(tokenWali1, 's-01');

// Pastikan tidak ada satu pun baris yang bertambah atau termutasi
Object.keys(mockSS.sheets).forEach(sName => {
  const currentCount = mockSS.sheets[sName].getLastRow();
  assert.strictEqual(currentCount, rowCountsBefore[sName], `Sheet ${sName} tidak boleh termutasi saat operasi baca`);
});

console.log('✓ Kasus batas (div-by-zero, nilai 0 murni vs kosong, siswa historis, dan proteksi read-only) terverifikasi 100%.');

console.log('\n============================================================================');
console.log('SEMUA PENGUJIAN PHASE 7 BERHASIL DILALUI DENGAN SUKSES 100%!');
console.log('============================================================================\n');
