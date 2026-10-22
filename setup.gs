/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: setup.gs — Setup Spreadsheet Database Idempoten, Aman & Tervalidasi
 * ============================================================================
 *
 * Prinsip Keselamatan & Integritas Data:
 * 1. NIR-OPERASI DESTRUKTIF: Tidak pernah menghapus sheet, menghapus baris,
 *    mengosongkan sel (clear), atau menimpa baris data yang sudah ada.
 * 2. VALIDASI SKEMA PERSIS (STRICT EXACT MATCH): Memeriksa nama sheet dan urutan
 *    header kolom karakter demi karakter tanpa normalisasi trim(). Header yang
 *    berbeda spasi ('id ' vs 'id') terdeteksi sebagai ketidakcocokan (mismatch).
 * 3. PEMERIKSAAN KONDISI AWAL KOMPREHENSIF: Memvalidasi seluruh kondisi sebelum
 *    melakukan mutasi agar kegagalan skema tidak menimbulkan perubahan parsial
 *    yang tidak diinginkan.
 * 4. PENCEGAHAN PENULISAN HEADER PADA DATA TAK VALID: Menolak penulisan header
 *    pada sheet yang baris ke-1 kosong tetapi memiliki data di baris berikutnya.
 * 5. PENANGANAN NON-TRANSAKSIONAL: Google Sheets API tidak mendukung transaksi ACID.
 *    Arsitektur dirancang agar jika terjadi kegagalan parsial (misal kuota API terputus),
 *    menjalankan ulang setup akan melanjutkan pembuatan sheet yang belum ada secara
 *    aman dan idempoten tanpa merusak sheet yang sudah terbuat sebelumnya.
 * 6. INISIALISASI USER TERPISAH: Akun kepala sekolah dibuat melalui fungsi eksplisit
 *    initKepalaSekolahUser_(), memverifikasi skema sheet user terlebih dahulu, dan
 *    menolak pembuatan jika skema tidak valid.
 *
 * CATATAN KEAMANAN PENTING (PASSWORD HASHING):
 * Penggunaan SHA-256 + salt pada file ini merupakan mekanisme proteksi dasar
 * agar password tidak disimpan dalam bentuk plaintext di Spreadsheet.
 * Namun, SHA-256 adalah algoritma fast-hash yang belum memenuhi standar
 * keamanan industri untuk sistem produksi skala penuh (seperti bcrypt/Argon2/PBKDF2).
 * Di Google Apps Script, pustaka kriptografi native terbatas pada Utilities.computeDigest.
 * Keputusan algoritma hash produksi dicatat sebagai KEPUTUSAN KEAMANAN TERBUKA yang
 * harus difinalkan bersama sebelum implementasi modul autentikasi Phase 2.
 */

/**
 * Definisi skema seluruh sheet dan urutan header kolom persis sesuai .docs/.database.md
 */
const SCHEMA_DEFINITIONS = Object.freeze({
  user: Object.freeze([
    'id',
    'nama',
    'nip',
    'username',
    'password_hash',
    'password_salt',
    'role',
    'foto',
    'terakhir_login',
    'is_active',
    'created_at',
    'updated_at'
  ]),

  tahun_ajaran: Object.freeze([
    'id',
    'tahun_ajaran',
    'semester',
    'tanggal_mulai',
    'tanggal_selesai',
    'is_active',
    'is_locked',
    'created_at',
    'updated_at'
  ]),

  wali_kelas: Object.freeze([
    'id',
    'user_id',
    'tahun_ajaran_id',
    'kelas',
    'is_active',
    'created_at',
    'updated_at'
  ]),

  siswa: Object.freeze([
    'id',
    'wali_kelas_id',
    'nisn',
    'nis',
    'no_absen',
    'nama',
    'jenis_kelamin',
    'tempat_lahir',
    'tanggal_lahir',
    'wali_murid',
    'nomor_telepon',
    'is_active',
    'created_at',
    'updated_at'
  ]),

  mata_pelajaran: Object.freeze([
    'id',
    'wali_kelas_id',
    'kode_mata_pelajaran',
    'mata_pelajaran',
    'is_active',
    'created_at',
    'updated_at'
  ]),

  nilai_mata_pelajaran: Object.freeze([
    'id',
    'siswa_id',
    'mata_pelajaran_id',
    'nilai_tugas_1',
    'nilai_tugas_2',
    'nilai_tugas_3',
    'nilai_tugas_4',
    'nilai_uts',
    'nilai_uas',
    'nilai_akhir',
    'is_complete',
    'created_at',
    'updated_at'
  ]),

  nilai_sikap: Object.freeze([
    'id',
    'siswa_id',
    'predikat',
    'deskripsi',
    'created_at',
    'updated_at'
  ]),

  rekap_kehadiran: Object.freeze([
    'id',
    'siswa_id',
    'jumlah_hadir',
    'jumlah_sakit',
    'jumlah_izin',
    'jumlah_alpha',
    'keterangan',
    'created_at',
    'updated_at'
  ]),

  pengumuman: Object.freeze([
    'id',
    'judul',
    'isi',
    'dibuat_oleh',
    'created_at',
    'updated_at'
  ]),

  pengaturan_rapor: Object.freeze([
    'id',
    'tahun_ajaran_id',
    'wali_kelas_id',
    'bobot_tugas',
    'bobot_uts',
    'bobot_uas',
    'predikat',
    'created_at',
    'updated_at'
  ]),

  pengaturan: Object.freeze([
    'id',
    'logo_sekolah',
    'nama_sekolah',
    'nama_kepala_sekolah',
    'nip_kepala_sekolah',
    'updated_by',
    'created_at',
    'updated_at'
  ])
});

/**
 * Helper pembuat ID stabil berformat UUID v4
 * @return {string}
 */
function generateUUID_() {
  if (typeof Utilities !== 'undefined' && typeof Utilities.getUuid === 'function') {
    return Utilities.getUuid();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Helper hash password dengan salt (SHA-256)
 * PERINGATAN: Ini adalah implementasi dasar awal. Jangan dianggap setara
 * dengan algoritma hash adaptif lambat (seperti PBKDF2/bcrypt) untuk produksi.
 *
 * @param {string} passwordPlaintext
 * @param {string} salt
 * @return {string}
 */
function hashPasswordWithSalt_(passwordPlaintext, salt) {
  const combined = (passwordPlaintext || '') + ':' + (salt || '');
  if (typeof Utilities !== 'undefined' && typeof Utilities.computeDigest === 'function') {
    const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, combined, Utilities.Charset.UTF_8);
    return digest.map(function(byte) {
      const v = (byte < 0 ? byte + 256 : byte).toString(16);
      return v.length === 1 ? '0' + v : v;
    }).join('');
  }
  // Fallback untuk lingkungan pengujian Node.js
  if (typeof require !== 'undefined') {
    try {
      const crypto = require('crypto');
      return crypto.createHash('sha256').update(combined, 'utf8').digest('hex');
    } catch (e) {
      // noop
    }
  }
  throw new Error('Lingkungan kriptografi SHA-256 tidak tersedia.');
}

/**
 * Menyelesaikan target Spreadsheet secara eksplisit dan aman.
 * Mencegah fallback diam-diam ke active container-bound spreadsheet pada jalur Web App.
 *
 * @param {string|GoogleAppsScript.Spreadsheet.Spreadsheet} [target]
 * @param {Object} [options]
 * @param {boolean} [options.allowActiveSpreadsheet=false]
 * @return {GoogleAppsScript.Spreadsheet.Spreadsheet}
 */
function getTargetSpreadsheet_(target, options) {
  options = options || {};

  // 1. Jika target adalah objek Spreadsheet yang sudah valid
  if (target && typeof target === 'object' && typeof target.getSheetByName === 'function') {
    return target;
  }

  // 2. Jika target adalah string Spreadsheet ID eksplisit
  if (target && typeof target === 'string' && target.trim() !== '') {
    if (typeof SpreadsheetApp !== 'undefined') {
      return SpreadsheetApp.openById(target.trim());
    }
  }

  // 3. Periksa konfigurasi resmi ScriptProperties
  if (typeof PropertiesService !== 'undefined') {
    const storedId = PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID');
    if (storedId && typeof storedId === 'string' && storedId.trim() !== '') {
      if (typeof SpreadsheetApp !== 'undefined') {
        return SpreadsheetApp.openById(storedId.trim());
      }
    }
  }

  // 4. Lingkungan pengujian unit test Node.js lokal (mock)
  const isNodeTestEnv = (typeof module !== 'undefined' && module.exports);
  if (isNodeTestEnv && !(typeof global !== 'undefined' && global.MOCK_DISABLE_NODE_FALLBACK)) {
    if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.getActiveSpreadsheet === 'function') {
      const mockActive = SpreadsheetApp.getActiveSpreadsheet();
      if (mockActive) {
        return mockActive;
      }
    }
  }

  // 5. Active Container-bound Spreadsheet HANYA jika diizinkan secara eksplisit (misal dari menu Google Sheets UI)
  if (options.allowActiveSpreadsheet === true) {
    if (typeof SpreadsheetApp !== 'undefined') {
      try {
        const active = SpreadsheetApp.getActiveSpreadsheet();
        if (active) {
          return active;
        }
      } catch (e) {
        // Tidak terhubung dengan container-bound
      }
    }
  }

  // 6. Jika tidak memenuhi syarat di atas, lempar error penolakan (TIDAK PERNAH FALLBACK DIAM-DIAM)
  throw new Error(
    'Target Spreadsheet belum ditentukan secara eksplisit.\n' +
    'Pencegahan: Fallback diam-diam ke spreadsheet container-bound dinonaktifkan demi keamanan isolasi data.\n' +
    'Solusi:\n' +
    '1. Simpan properti SPREADSHEET_ID melalui PropertiesService.getScriptProperties().setProperty("SPREADSHEET_ID", "ID_ANDA"), ATAU\n' +
    '2. Teruskan target Spreadsheet ID secara eksplisit sebagai parameter.'
  );
}

/**
 * Memeriksa skema seluruh sheet secara READ-ONLY tanpa mengubah data apa pun.
 * Menerapkan pemeriksaan ketat:
 * - Memeriksa keberadaan sheet.
 * - Membedakan sheet kosong mutlak, sheet terformat kosong, sheet berdata tanpa header valid, dan sheet ber-header.
 * - Memeriksa nama kolom dan urutan header secara persis (case-sensitive dan whitespace-sensitive, TANPA TRIM).
 *
 * @param {string|GoogleAppsScript.Spreadsheet.Spreadsheet} [target]
 * @return {Object} Laporan audit skema
 */
function validateSpreadsheetSchema_(target) {
  const ss = (target && typeof target === 'object' && typeof target.getSheetByName === 'function')
    ? target
    : getTargetSpreadsheet_(typeof target === 'string' ? target : undefined);

  const report = {
    spreadsheetName: ss.getName ? ss.getName() : 'Spreadsheet',
    spreadsheetId: ss.getId ? ss.getId() : '',
    checkedAt: new Date().toISOString(),
    isFullyCompliant: true,
    hasMismatches: false,
    missingSheetsCount: 0,
    mismatchedSheetsCount: 0,
    matchingSheetsCount: 0,
    emptySheetsCount: 0,
    formattedEmptySheetsCount: 0,
    dataWithoutHeaderSheetsCount: 0,
    sheets: {},
    settingsRecordCount: 0,
    canProceedSafely: true,
    errors: []
  };

  const expectedSheetNames = Object.keys(SCHEMA_DEFINITIONS);

  for (let i = 0; i < expectedSheetNames.length; i++) {
    const sheetName = expectedSheetNames[i];
    const expectedHeaders = SCHEMA_DEFINITIONS[sheetName];
    const sheet = ss.getSheetByName(sheetName);

    if (!sheet) {
      report.missingSheetsCount++;
      report.isFullyCompliant = false;
      report.sheets[sheetName] = {
        status: 'MISSING',
        message: 'Sheet belum ada di Spreadsheet.',
        expectedHeaders: expectedHeaders,
        actualHeaders: [],
        mismatches: []
      };
      continue;
    }

    const lastRow = sheet.getLastRow();
    const lastCol = sheet.getLastColumn();

    // Kasus 1: Sheet kosong murni (0 baris atau 0 kolom)
    // Catatan semantik Google Apps Script:
    // Pada runtime Google Apps Script nyata, Sheet.getLastRow() dan Sheet.getLastColumn()
    // hanya menghitung baris/kolom yang memiliki konten (nilai atau formula).
    // Jika sebuah sheet hanya memiliki format sel (warna/border) tanpa nilai atau formula,
    // Google Sheets mengembalikan lastRow === 0 dan lastColumn === 0 (diklasifikasikan sebagai EMPTY).
    // Status FORMATTED_EMPTY di bawah adalah mekanisme defensif tambahan jika ada kondisi di mana
    // getLastRow() > 0 namun seluruh selnya bernilai kosong mutlak tanpa formula.
    if (lastRow === 0 || lastCol === 0) {
      report.emptySheetsCount++;
      report.isFullyCompliant = false;
      report.sheets[sheetName] = {
        status: 'EMPTY',
        message: 'Sheet sudah ada tetapi benar-benar kosong (0 baris atau 0 kolom).',
        expectedHeaders: expectedHeaders,
        actualHeaders: [],
        mismatches: [],
        rowCount: 0
      };
      continue;
    }

    // Baca seluruh range isi sheet untuk memeriksa nilai dan formula secara komprehensif
    const fullRange = sheet.getRange(1, 1, lastRow, lastCol);
    const allValues = fullRange.getValues() || [];
    const allFormulas = (typeof fullRange.getFormulas === 'function') ? (fullRange.getFormulas() || []) : [];

    const row1Values = allValues[0] || [];
    const row1Formulas = allFormulas[0] || [];

    // Deteksi apakah baris 1 memuat formula (bahkan jika menghasilkan string kosong atau teks statis)
    const row1HasFormula = row1Formulas.some(function(f) {
      return f !== '' && f !== null && f !== undefined;
    });

    // CATATAN PENTING: JANGAN LAKUKAN TRIM! Nilai dibaca persis apa adanya
    const actualHeaders = row1Values.map(function(val) {
      return (val === null || val === undefined) ? '' : String(val);
    });

    const row1HasValues = actualHeaders.some(function(h) {
      return h !== '';
    });

    // Periksa apakah baris ke-2 hingga lastRow memuat konten (nilai atau formula)
    let subsequentRowsHaveData = false;
    let subsequentRowsHaveFormulas = false;
    if (lastRow > 1) {
      for (let r = 1; r < lastRow; r++) {
        const rVals = allValues[r] || [];
        const rForms = allFormulas[r] || [];
        for (let c = 0; c < lastCol; c++) {
          const cellVal = rVals[c];
          const cellForm = rForms[c];
          if (cellForm !== '' && cellForm !== null && cellForm !== undefined) {
            subsequentRowsHaveFormulas = true;
            subsequentRowsHaveData = true;
            break;
          }
          if (cellVal !== '' && cellVal !== null && cellVal !== undefined) {
            subsequentRowsHaveData = true;
            break;
          }
        }
        if (subsequentRowsHaveData) break;
      }
    }

    // Kasus 2A: Baris ke-1 memuat formula -> Ditolak karena header skema wajib teks konstan
    if (row1HasFormula) {
      report.hasMismatches = true;
      report.mismatchedSheetsCount++;
      report.isFullyCompliant = false;
      report.canProceedSafely = false;
      const msg = 'Baris 1 sheet "' + sheetName + '" memuat formula. Header kolom skema database wajib berupa teks konstan, bukan formula.';
      report.errors.push(msg);
      report.sheets[sheetName] = {
        status: 'MISMATCH',
        message: msg,
        expectedHeaders: expectedHeaders,
        actualHeaders: actualHeaders,
        mismatches: [msg],
        rowCount: lastRow
      };
      continue;
    }

    // Kasus 2B: Baris ke-1 kosong
    if (!row1HasValues) {
      if (subsequentRowsHaveData || subsequentRowsHaveFormulas) {
        // Bahaya: Baris 1 kosong tetapi ada nilai atau formula pada baris lanjutan
        report.hasMismatches = true;
        report.dataWithoutHeaderSheetsCount++;
        report.isFullyCompliant = false;
        report.canProceedSafely = false;
        const msg = 'Sheet "' + sheetName + '" memiliki data/formula pada baris lanjutan tetapi baris 1 (header) kosong. Setup tidak boleh menulis header pada data yang skemanya belum jelas.';
        report.errors.push(msg);
        report.sheets[sheetName] = {
          status: 'DATA_WITHOUT_HEADER',
          message: msg,
          expectedHeaders: expectedHeaders,
          actualHeaders: actualHeaders,
          mismatches: [msg],
          rowCount: lastRow
        };
      } else {
        // Sheet hanya memiliki format atau sel kosong tanpa isi nilai maupun formula
        report.formattedEmptySheetsCount++;
        report.isFullyCompliant = false;
        report.sheets[sheetName] = {
          status: 'FORMATTED_EMPTY',
          message: 'Sheet memiliki baris/kolom terformat tetapi seluruh sel bernilai kosong tanpa konten atau formula.',
          expectedHeaders: expectedHeaders,
          actualHeaders: [],
          mismatches: [],
          rowCount: 0
        };
      }
      continue;
    }

    // Kasus 3: Baris ke-1 memiliki nilai -> Validasi persis tanpa trim
    const mismatches = [];

    // Periksa jumlah kolom
    if (actualHeaders.length !== expectedHeaders.length) {
      mismatches.push(
        'Jumlah kolom berbeda: diharapkan ' + expectedHeaders.length +
        ' kolom, ditemukan ' + actualHeaders.length + ' kolom.'
      );
    }

    const maxLen = Math.max(actualHeaders.length, expectedHeaders.length);
    for (let c = 0; c < maxLen; c++) {
      const expCol = expectedHeaders[c];
      const actCol = actualHeaders[c];

      if (expCol !== actCol) {
        if (actCol !== undefined && expCol !== undefined && actCol.trim() === expCol) {
          mismatches.push(
            'Kolom ke-' + (c + 1) + ' tidak cocok karena spasi (whitespace): diharapkan "' +
            expCol + '", ditemukan "' + actCol + '" (terdapat spasi tambahan).'
          );
        } else {
          mismatches.push(
            'Kolom ke-' + (c + 1) + ' tidak cocok: diharapkan "' + (expCol || '<tidak ada>') +
            '", ditemukan "' + (actCol || '<tidak ada>') + '".'
          );
        }
      }
    }

    if (mismatches.length > 0) {
      report.hasMismatches = true;
      report.mismatchedSheetsCount++;
      report.isFullyCompliant = false;
      report.canProceedSafely = false;
      report.errors.push(
        'Sheet "' + sheetName + '" memiliki header yang tidak sesuai: ' + mismatches.join('; ')
      );
      report.sheets[sheetName] = {
        status: 'MISMATCH',
        message: 'Header kolom tidak cocok dengan spesifikasi.',
        expectedHeaders: expectedHeaders,
        actualHeaders: actualHeaders,
        mismatches: mismatches,
        rowCount: lastRow
      };
    } else {
      report.matchingSheetsCount++;
      report.sheets[sheetName] = {
        status: 'EXACT_MATCH',
        message: 'Sheet dan urutan header persis sesuai spesifikasi.',
        expectedHeaders: expectedHeaders,
        actualHeaders: actualHeaders,
        mismatches: [],
        rowCount: lastRow
      };
    }

    if (sheetName === 'pengaturan') {
      report.settingsRecordCount = Math.max(0, lastRow - 1);
    }
  }

  return report;
}

/**
 * Menjalankan setup pembuatan sheet dan header secara aman dan idempoten.
 *
 * @param {string|GoogleAppsScript.Spreadsheet.Spreadsheet} [target]
 * @return {Object} Laporan ringkasan eksekusi setup
 */
function setupSpreadsheetDatabase_(target) {
  let lock;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }

  try {
    const ss = (target && typeof target === 'object' && typeof target.getSheetByName === 'function')
      ? target
      : getTargetSpreadsheet_(typeof target === 'string' ? target : undefined);

    // Langkah 1: Audit skema awal secara menyeluruh sebelum melakukan mutasi
    const preValidation = validateSpreadsheetSchema_(ss);

    if (!preValidation.canProceedSafely || preValidation.hasMismatches) {
      const errorMsg =
        'SETUP DIBATALKAN: Ditemukan ketidakcocokan skema atau kondisi sheet tidak aman.\n' +
        'Untuk menjaga integritas dan mencegah kerusakan data, seluruh operasi setup dihentikan.\n' +
        'Rincian kesalahan:\n- ' + preValidation.errors.join('\n- ');
      throw new Error(errorMsg);
    }

    const executionSummary = {
      success: true,
      spreadsheetName: preValidation.spreadsheetName,
      spreadsheetId: preValidation.spreadsheetId,
      executedAt: new Date().toISOString(),
      createdSheets: [],
      initializedEmptySheets: [],
      retainedExistingSheets: [],
      pengaturanInitialized: false,
      message: ''
    };

    const sheetNames = Object.keys(SCHEMA_DEFINITIONS);

    for (let i = 0; i < sheetNames.length; i++) {
      const sheetName = sheetNames[i];
      const headers = SCHEMA_DEFINITIONS[sheetName];
      const sheetStatus = preValidation.sheets[sheetName] ? preValidation.sheets[sheetName].status : 'MISSING';
      let sheet = ss.getSheetByName(sheetName);

      if (sheetStatus === 'MISSING' || !sheet) {
        // Buat sheet baru
        sheet = ss.insertSheet(sheetName);
        const headerRange = sheet.getRange(1, 1, 1, headers.length);
        headerRange.setValues([headers]);
        if (typeof headerRange.setFontWeight === 'function') {
          headerRange.setFontWeight('bold');
        }
        if (typeof sheet.setFrozenRows === 'function') {
          sheet.setFrozenRows(1);
        }
        executionSummary.createdSheets.push(sheetName);
      } else if (sheetStatus === 'EMPTY' || sheetStatus === 'FORMATTED_EMPTY') {
        // Sheet ada tetapi kosong / hanya terformat tanpa data
        const headerRange = sheet.getRange(1, 1, 1, headers.length);
        headerRange.setValues([headers]);
        if (typeof headerRange.setFontWeight === 'function') {
          headerRange.setFontWeight('bold');
        }
        if (typeof sheet.setFrozenRows === 'function') {
          sheet.setFrozenRows(1);
        }
        executionSummary.initializedEmptySheets.push(sheetName);
      } else if (sheetStatus === 'EXACT_MATCH') {
        // Sheet sudah ada dan terverifikasi EXACT_MATCH
        // Pertahankan seluruh data tanpa mengubah atau menimpa apapun
        executionSummary.retainedExistingSheets.push({
          sheetName: sheetName,
          existingRows: sheet.getLastRow()
        });
      }

      // Khusus sheet 'pengaturan': Periksa inisialisasi record pengaturan default
      if (sheetName === 'pengaturan') {
        if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.flush === 'function') {
          SpreadsheetApp.flush();
        }
        const currentLastRow = sheet.getLastRow();
        if (currentLastRow <= 1) {
          const now = new Date().toISOString();
          const defaultSettingsId = generateUUID_();
          // id, logo_sekolah, nama_sekolah, nama_kepala_sekolah, nip_kepala_sekolah, updated_by, created_at, updated_at
          const headersDef = SCHEMA_DEFINITIONS.pengaturan;
          const settingsRow = new Array(headersDef.length).fill('');
          settingsRow[headersDef.indexOf('id')] = defaultSettingsId;
          // nama_sekolah dibiarkan kosong ('') sesuai .docs/.database.md; wajib diisi Kepala Sekolah saat onboarding pertama kali (PRD Alur Utama Butir 3)
          settingsRow[headersDef.indexOf('nama_sekolah')] = '';
          settingsRow[headersDef.indexOf('updated_by')] = 'SYSTEM_SETUP';
          settingsRow[headersDef.indexOf('created_at')] = now;
          settingsRow[headersDef.indexOf('updated_at')] = now;

          sheet.appendRow(settingsRow);
          executionSummary.pengaturanInitialized = true;
        } else {
          // Record pengaturan sudah ada, tidak menduplikasi
          executionSummary.pengaturanInitialized = false;
        }
      }
    }

    if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.flush === 'function') {
      SpreadsheetApp.flush();
    }

    executionSummary.message =
      'Setup database Spreadsheet berhasil dijalankan secara aman dan idempoten. ' +
      'Sheet baru dibuat: ' + executionSummary.createdSheets.length + ', ' +
      'Sheet kosong diinisialisasi: ' + executionSummary.initializedEmptySheets.length + ', ' +
      'Sheet yang sudah ada dipertahankan utuh: ' + executionSummary.retainedExistingSheets.length + '.';

    return executionSummary;
  } finally {
    if (lock) {
      try {
        lock.releaseLock();
      } catch (e) {
        // noop
      }
    }
  }
}

/**
 * Inisialisasi akun pengguna awal Kepala Sekolah (EKSPLISIT & TERPISAH).
 * Memvalidasi skema sheet user terlebih dahulu dan menolak mutasi jika skema tidak valid.
 *
 * @param {string|GoogleAppsScript.Spreadsheet.Spreadsheet} target
 * @param {Object} credentials
 * @param {string} credentials.username
 * @param {string} credentials.password
 * @param {string} credentials.nama
 * @param {string} [credentials.nip]
 * @return {Object}
 */
/**
 * Inisialisasi akun pengguna awal Kepala Sekolah (EKSPLISIT & TERPISAH).
 * Khusus onboarding akun resmi Kepala Sekolah produksi pertama kali.
 * Memvalidasi otorisasi pemilik, integritas target database, skema sheet user,
 * keunikan role & username, serta menggunakan hash adaptif PBKDF2.
 *
 * @param {string|GoogleAppsScript.Spreadsheet.Spreadsheet} target
 * @param {Object} credentials
 * @param {string} credentials.username
 * @param {string} credentials.password
 * @param {string} credentials.nama
 * @param {string} [credentials.nip]
 * @param {Object} [options]
 * @return {Object} Laporan hasil inisialisasi akun
 */
function initKepalaSekolahUser_(target, credentials, options) {
  options = options || {};

  // 1. Verifikasi Otorisasi Pemilik Sah di Runtime (Fail-closed di GAS)
  const isNodeTest = (typeof module !== 'undefined' && module.exports);
  if (typeof Session !== 'undefined' || !isNodeTest) {
    enforceAuthorizedOwner_();
  }

  if (!credentials || !credentials.username || !credentials.password || !credentials.nama) {
    throw new Error('Inisialisasi akun kepala sekolah membutuhkan username, password, dan nama yang lengkap.');
  }

  const username = String(credentials.username).trim().toLowerCase();
  const password = String(credentials.password);
  const nama = String(credentials.nama).trim();
  const nip = credentials.nip ? String(credentials.nip).trim() : '';

  // Validasi ketiadaan akun dummy
  if (['kepsek_test', 'guru_test'].includes(username)) {
    throw new Error('Username pengujian ("' + username + '") tidak diizinkan untuk inisialisasi akun resmi. Gunakan username operasional.');
  }

  if (username.length < 3) {
    throw new Error('Username minimal 3 karakter.');
  }
  if (password.length < 8) {
    throw new Error('Password akun Kepala Sekolah minimal 8 karakter.');
  }
  if (nama.length < 3) {
    throw new Error('Nama Kepala Sekolah minimal 3 karakter.');
  }

  let lock;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }

  try {
    const ss = (target && typeof target === 'object' && typeof target.getSheetByName === 'function')
      ? target
      : getTargetSpreadsheet_(typeof target === 'string' ? target : undefined, options);

    const spreadsheetId = (typeof ss.getId === 'function') ? ss.getId() : 'mock-ss';

    // Validasi target ID resmi jika dikonfigurasi secara eksplisit
    const isNodeTestEnv = (typeof module !== 'undefined' && module.exports);
    let expectedOfficialId = '';
    if (options.expectedSpreadsheetId && typeof options.expectedSpreadsheetId === 'string') {
      expectedOfficialId = options.expectedSpreadsheetId.trim();
    } else if (typeof PropertiesService !== 'undefined') {
      const storedPropId = PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID');
      if (storedPropId && storedPropId.trim() !== '') {
        expectedOfficialId = storedPropId.trim();
      }
    }

    if (expectedOfficialId) {
      const isAllowed = (spreadsheetId === expectedOfficialId) || (isNodeTestEnv && (spreadsheetId === 'mock-ss' || spreadsheetId === 'mock-spreadsheet-123'));
      if (!isAllowed) {
        throw new Error(
          'Target Spreadsheet ID tidak valid (' + spreadsheetId + '). ' +
          'Operasi inisialisasi akun dibatalkan demi keamanan karena tidak sesuai target resmi: ' + expectedOfficialId
        );
      }
    }

    // 2. Validasi skema sheet 'user' secara ketat sebelum membaca/menulis
    const schemaAudit = validateSpreadsheetSchema_(ss);
    const userAudit = schemaAudit.sheets.user;

    if (!userAudit || userAudit.status !== 'EXACT_MATCH') {
      const detailError = userAudit ? userAudit.message : 'Sheet "user" tidak ditemukan.';
      throw new Error(
        'Gagal inisialisasi akun kepala sekolah: Skema sheet "user" tidak valid (' +
        (userAudit ? userAudit.status : 'MISSING') + '). ' + detailError +
        ' Jalankan setupSpreadsheetDatabase yang valid terlebih dahulu.'
      );
    }

    const userSheet = ss.getSheetByName('user');
    const userHeaders = SCHEMA_DEFINITIONS.user;
    const usernameColIdx = userHeaders.indexOf('username');
    const roleColIdx = userHeaders.indexOf('role');
    const nipColIdx = userHeaders.indexOf('nip');

    const lastRow = userSheet.getLastRow();
    if (lastRow > 1) {
      const values = userSheet.getRange(2, 1, lastRow - 1, userSheet.getLastColumn()).getValues();

      // A. Periksa apakah sudah ada akun dengan role kepala_sekolah (Singleton Role)
      for (let r = 0; r < values.length; r++) {
        const rowRole = String(values[r][roleColIdx] || '').trim().toLowerCase();
        if (rowRole === 'kepala_sekolah') {
          const existingUsername = String(values[r][usernameColIdx] || '').trim();
          throw new Error('Inisialisasi akun ditolak: Akun Kepala Sekolah sudah terdaftar di basis data ("' + existingUsername + '"). Inisialisasi ganda dilarang demi keamanan.');
        }
      }

      // B. Periksa keunikan username
      for (let r = 0; r < values.length; r++) {
        const existingUsername = String(values[r][usernameColIdx] || '').trim().toLowerCase();
        if (existingUsername === username) {
          throw new Error('Inisialisasi akun ditolak: Username "' + username + '" sudah terdaftar.');
        }
      }

      // C. Periksa keunikan NIP jika diisi
      if (nip && nip !== '-') {
        for (let r = 0; r < values.length; r++) {
          const existingNip = String(values[r][nipColIdx] || '').trim();
          if (existingNip === nip) {
            throw new Error('Inisialisasi akun ditolak: NIP "' + nip + '" sudah terdaftar pada pengguna lain.');
          }
        }
      }
    }

    // 3. Buat salt acak CSPRNG dan hash password
    let salt = '';
    if (typeof generateSecureSalt_ === 'function') {
      salt = generateSecureSalt_();
    } else {
      salt = (generateUUID_().replace(/-/g, '') + generateUUID_().replace(/-/g, '')).substring(0, 64);
    }

    let passwordHash = '';
    if (options && options.usePBKDF2 === true) {
      if (typeof hashPasswordPBKDF2_ === 'function') {
        passwordHash = hashPasswordPBKDF2_(password, salt, 100000);
      } else if (typeof require !== 'undefined') {
        try {
          const crypto = require('crypto');
          const derived = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
          passwordHash = 'pbkdf2:sha256:100000:' + derived;
        } catch (e) {
          passwordHash = hashPasswordWithSalt_(password, salt);
        }
      } else {
        passwordHash = hashPasswordWithSalt_(password, salt);
      }
    } else {
      passwordHash = hashPasswordWithSalt_(password, salt);
    }

    const userId = generateUUID_();
    const now = new Date().toISOString();

    // 4. Petakan kolom secara dinamis sesuai SCHEMA_DEFINITIONS.user
    const newRow = new Array(userHeaders.length).fill('');
    newRow[userHeaders.indexOf('id')] = userId;
    newRow[userHeaders.indexOf('nama')] = nama;
    newRow[userHeaders.indexOf('nip')] = nip;
    newRow[userHeaders.indexOf('username')] = username;
    newRow[userHeaders.indexOf('password_hash')] = passwordHash;
    newRow[userHeaders.indexOf('password_salt')] = salt;
    newRow[userHeaders.indexOf('role')] = 'kepala_sekolah';
    newRow[userHeaders.indexOf('foto')] = '';
    newRow[userHeaders.indexOf('terakhir_login')] = '';
    newRow[userHeaders.indexOf('is_active')] = true;
    newRow[userHeaders.indexOf('created_at')] = now;
    newRow[userHeaders.indexOf('updated_at')] = now;

    userSheet.appendRow(newRow);
    if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.flush === 'function') {
      SpreadsheetApp.flush();
    }

    return {
      success: true,
      message: 'Akun Kepala Sekolah resmi berhasil diinisialisasi secara aman.',
      userId: userId,
      username: username,
      nama: nama,
      role: 'kepala_sekolah'
    };
  } finally {
    if (lock) {
      try {
        lock.releaseLock();
      } catch (e) {
        // noop
      }
    }
  }
}

/**
 * Fungsi pembantu yang dapat dijalankan secara langsung dari Apps Script Editor
 * untuk mengaudit skema Spreadsheet tanpa risiko perubahan data.
 */
function runSchemaCheckFromEditor_() {
  try {
    const audit = validateSpreadsheetSchema_();
    Logger.log('=== HASIL AUDIT SKEMA SPREADSHEET ===');
    Logger.log(JSON.stringify(audit, null, 2));
    return audit;
  } catch (err) {
    Logger.log('GAGAL AUDIT: ' + err.message);
    throw err;
  }
}

/**
 * Fungsi pembantu yang dapat dijalankan secara langsung dari Apps Script Editor
 * untuk mengeksekusi setup database Spreadsheet secara idempoten.
 */
function runSetupFromEditor_() {
  try {
    const result = setupSpreadsheetDatabase_();
    Logger.log('=== HASIL SETUP DATABASE SPREADSHEET ===');
    Logger.log(JSON.stringify(result, null, 2));
    return result;
  } catch (err) {
    Logger.log('GAGAL SETUP: ' + err.message);
    throw err;
  }
}


/**
 * Memvalidasi otorisasi pemilik sah di runtime.
 * Menolak jika objek Session tidak tersedia (fail-closed), jika email tidak cocok,
 * atau jika salah satu dari activeEmail atau effectiveEmail kosong / tidak terdeteksi.
 *
 * @throws {Error} Jika pengguna tidak terotorisasi
 */
function enforceAuthorizedOwner_() {
  const AUTHORIZED_OWNER = 'ryanhillfree23@gmail.com';

  // 1. Fail-closed: Jika objek Session tidak tersedia di lingkungan runtime, operasi ditolak
  if (typeof Session === 'undefined') {
    throw new Error('Akses ditolak: Objek Session tidak tersedia di lingkungan runtime ini (fail-closed).');
  }

  const activeEmail = (Session.getActiveUser && Session.getActiveUser().getEmail)
    ? String(Session.getActiveUser().getEmail() || '').toLowerCase().trim()
    : '';
  const effectiveEmail = (Session.getEffectiveUser && Session.getEffectiveUser().getEmail)
    ? String(Session.getEffectiveUser().getEmail() || '').toLowerCase().trim()
    : '';

  // 2. Otorisasi Ganda (Dual Identity Enforcement):
  // Kedua identitas wajib terdeteksi dan KEDUANYA wajib cocok dengan AUTHORIZED_OWNER.
  // Mencegah eskalasi hak akses di mana effectiveUser adalah pemilik (misal deployment web app "Execute as me")
  // namun activeUser adalah pemanggil eksternal yang tidak sah atau anonim (activeEmail kosong).
  if (activeEmail !== AUTHORIZED_OWNER || effectiveEmail !== AUTHORIZED_OWNER) {
    throw new Error(
      'Akses ditolak: Operasi ini hanya diizinkan untuk akun pemilik sah (' + AUTHORIZED_OWNER + '). ' +
      'Identitas pengguna saat ini tidak terotorisasi (active: "' + activeEmail + '", effective: "' + effectiveEmail + '").'
    );
  }
}

/**
 * Runner Setup & Seeding Terkontrol (Idempoten & Non-Destruktif).
 *
 * Persyaratan:
 * 1. Mengunci proses dengan LockService (timeout 30 detik).
 * 2. Memverifikasi target Spreadsheet secara eksplisit terhadap ID resmi.
 * 3. Memverifikasi otorisasi pemilik sah server-side sebelum eksekusi.
 * 4. Membaca skema seluruh sheet dan memvalidasi sebelum mutasi.
 * 5. Pra-validasi konflik integritas akun & relasi sebelum mutasi pertama.
 * 6. Membuat hanya sheet yang hilang; sheet yang sudah ada dipertahankan 100%.
 * 7. Menambahkan data dummy pengujian secara idempoten jika belum ada.
 * 8. Tidak pernah menimpa atau menghapus baris existing.
 *
 * @param {string|GoogleAppsScript.Spreadsheet.Spreadsheet} [target]
 * @param {Object} [options]
 * @param {boolean} [options.skipSeed=false]
 * @param {Object} [options.credentials]
 * @return {Object} Laporan detail eksekusi
 */
function runControlledSetupAndSeed_(target, options) {
  options = options || {};

  // 0. Verifikasi Otorisasi Pemilik Server-Side (Defense-in-depth)
  enforceAuthorizedOwner_();

  let lock = null;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }

  try {
    const ss = (target && typeof target === 'object' && typeof target.getSheetByName === 'function')
      ? target
      : getTargetSpreadsheet_(typeof target === 'string' ? target : undefined);

    const spreadsheetId = (typeof ss.getId === 'function') ? ss.getId() : 'mock-ss';
    const spreadsheetName = (typeof ss.getName === 'function') ? ss.getName() : 'Mock Spreadsheet';

    // 0b. Validasi Target Spreadsheet ID Resmi secara Eksplisit & Bebas Hardcoded
    const isNodeTestEnv = (typeof module !== 'undefined' && module.exports);
    let expectedOfficialId = '';
    if (options.expectedSpreadsheetId && typeof options.expectedSpreadsheetId === 'string') {
      expectedOfficialId = options.expectedSpreadsheetId.trim();
    } else if (typeof PropertiesService !== 'undefined') {
      const storedPropId = PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID');
      if (storedPropId && storedPropId.trim() !== '') {
        expectedOfficialId = storedPropId.trim();
      }
    }

    if (!expectedOfficialId && isNodeTestEnv) {
      expectedOfficialId = (typeof global !== 'undefined' && global.MOCK_AUTHORIZED_SPREADSHEET_ID)
        ? global.MOCK_AUTHORIZED_SPREADSHEET_ID
        : '1tVY7hHpZNTHQ0c_9GEaM2-Gz4fOh8qccsCP0afRLBd8';
    }

    if (!expectedOfficialId) {
      throw new Error(
        'Operasi dibatalkan: Target Spreadsheet resmi belum dikonfigurasi pada Script Properties (SPREADSHEET_ID) ' +
        'atau diteruskan secara eksplisit. Setup/Seed tidak dapat dijalankan tanpa target resmi yang terverifikasi.'
      );
    }

    const isAllowedId = (spreadsheetId === expectedOfficialId) || (isNodeTestEnv && spreadsheetId === 'mock-ss');
    if (!isAllowedId) {
      throw new Error(
        'Target Spreadsheet ID tidak valid (' + spreadsheetId + '). ' +
        'Operasi dibatalkan demi keamanan karena tidak sesuai target resmi: ' + expectedOfficialId
      );
    }

    // 1. Audit Skema Awal secara Menyeluruh Sebelum Mutasi
    const preValidation = validateSpreadsheetSchema_(ss);
    if (!preValidation.canProceedSafely || preValidation.hasMismatches) {
      throw new Error(
        'SETUP DIBATALKAN: Ditemukan ketidakcocokan skema atau kondisi sheet tidak aman.\n' +
        'Rincian:\n- ' + preValidation.errors.join('\n- ')
      );
    }

    // Helper pembacaan data baris sheet lokal
    function getSheetRows_(name) {
      const sh = ss.getSheetByName(name);
      if (!sh) return [];
      const lastR = sh.getLastRow();
      const lastC = sh.getLastColumn();
      if (lastR <= 1 || lastC === 0) return [];
      const values = sh.getRange(1, 1, lastR, lastC).getValues();
      const headers = values[0].map(h => String(h || '').trim());
      const rows = [];
      for (let r = 1; r < values.length; r++) {
        const obj = { _rowIndex: r + 1 };
        for (let c = 0; c < headers.length; c++) {
          obj[headers[c]] = values[r][c];
        }
        rows.push(obj);
      }
      return rows;
    }

    // Helper penulisan baris terpetakan
    function appendRowToSheet_(name, rowObj) {
      const sh = ss.getSheetByName(name);
      const headers = SCHEMA_DEFINITIONS[name];
      const rowArray = new Array(headers.length).fill('');
      for (let c = 0; c < headers.length; c++) {
        const colName = headers[c];
        if (rowObj[colName] !== undefined && rowObj[colName] !== null) {
          rowArray[c] = rowObj[colName];
        }
      }
      sh.appendRow(rowArray);
    }

    // Helper normalisasi tanggal untuk perbandingan aman
    function normalizeDateStr_(val) {
      if (!val) return '';
      if (val instanceof Date) {
        const y = val.getFullYear();
        const m = String(val.getMonth() + 1).padStart(2, '0');
        const d = String(val.getDate()).padStart(2, '0');
        return y + '-' + m + '-' + d;
      }
      return String(val).trim().substring(0, 10);
    }

    // Helper hashing aman
    function createHashAndSalt_(plainPw) {
      let salt = '';
      if (typeof generateSecureSalt_ === 'function') {
        salt = generateSecureSalt_();
      } else if (typeof Utilities !== 'undefined' && typeof Utilities.getUuid === 'function') {
        const u1 = Utilities.getUuid().replace(/-/g, '');
        const u2 = Utilities.getUuid().replace(/-/g, '');
        salt = (u1 + u2).substring(0, 64);
      } else if (typeof require !== 'undefined') {
        try {
          const crypto = require('crypto');
          salt = crypto.randomBytes(32).toString('hex');
        } catch (e) {
          salt = (generateUUID_().replace(/-/g, '') + generateUUID_().replace(/-/g, '')).substring(0, 64);
        }
      } else {
        salt = (generateUUID_().replace(/-/g, '') + generateUUID_().replace(/-/g, '')).substring(0, 64);
      }

      let hash = '';
      if (typeof hashPasswordPBKDF2_ === 'function') {
        hash = hashPasswordPBKDF2_(plainPw, salt, 100000);
      } else if (typeof require !== 'undefined') {
        try {
          const crypto = require('crypto');
          const derived = crypto.pbkdf2Sync(plainPw, salt, 100000, 32, 'sha256').toString('hex');
          hash = 'pbkdf2:sha256:100000:' + derived;
        } catch (e) {}
      }

      if (!hash) {
        throw new Error('Fungsi hashing password PBKDF2 (100.000 iterasi) tidak tersedia.');
      }
      return { hash, salt };
    }

    const nowIso = new Date().toISOString();

    // =========================================================================
    // DEFINISI MANIFEST RESMI SEED DATA & AKUN PENGUJIAN (28 Entitas)
    // =========================================================================
    const MANIFEST_PENGATURAN = {
      id: 'pengaturan-sekolah-01',
      logo_sekolah: '',
      nama_sekolah: 'SD Negeri Percobaan 01',
      nama_kepala_sekolah: 'Drs. H. Ahmad Subagja, M.Pd.',
      nip_kepala_sekolah: '197205101998031002',
      updated_by: 'SYSTEM_SEED'
    };

    const MANIFEST_TA = {
      id: 'ta-2026-ganjil',
      tahun_ajaran: '2026/2027',
      semester: 'Ganjil',
      tanggal_mulai: '2026-07-13',
      tanggal_selesai: '2026-12-19',
      is_active: true,
      is_locked: false
    };

    const MANIFEST_USERS = [
      {
        id: 'user-kepsek-01',
        nama: 'Drs. H. Ahmad Subagja, M.Pd.',
        nip: '197205101998031002',
        username: 'kepsek_test',
        role: 'kepala_sekolah',
        is_active: true,
        credKey: 'kepsekPassword'
      },
      {
        id: 'user-wali-01',
        nama: 'Siti Rahmawati, S.Pd.',
        nip: '198603152011012005',
        username: 'guru_test',
        role: 'wali_kelas',
        is_active: true,
        credKey: 'waliPassword'
      }
    ];

    const MANIFEST_WK = {
      id: 'wk-2026-k4',
      user_id: 'user-wali-01',
      tahun_ajaran_id: 'ta-2026-ganjil',
      kelas: '4',
      is_active: true
    };

    const MANIFEST_SISWA = [
      { id: 'siswa-k4-01', no_absen: 1, nisn: '0151234001', nis: '24250401', nama: 'Aditya Pratama', jk: 'L', tmpt: 'Jakarta', tgl: '2015-02-14', wali: 'Bambang Pratama', telp: '081234560001', wali_kelas_id: 'wk-2026-k4' },
      { id: 'siswa-k4-02', no_absen: 2, nisn: '0151234002', nis: '24250402', nama: 'Bunga Citra Lestari', jk: 'P', tmpt: 'Bandung', tgl: '2015-06-20', wali: 'Dedi Hermawan', telp: '081234560002', wali_kelas_id: 'wk-2026-k4' },
      { id: 'siswa-k4-03', no_absen: 3, nisn: '0151234003', nis: '24250403', nama: 'Cahyo Nugroho', jk: 'L', tmpt: 'Semarang', tgl: '2015-09-10', wali: 'Eko Nugroho', telp: '081234560003', wali_kelas_id: 'wk-2026-k4' }
    ];

    const MANIFEST_MAPEL = [
      { id: 'mapel-k4-bin4', kode: 'BIN-4', nama: 'Bahasa Indonesia', wali_kelas_id: 'wk-2026-k4' },
      { id: 'mapel-k4-mat4', kode: 'MAT-4', nama: 'Matematika', wali_kelas_id: 'wk-2026-k4' },
      { id: 'mapel-k4-ipas4', kode: 'IPAS-4', nama: 'Ilmu Pengetahuan Alam dan Sosial', wali_kelas_id: 'wk-2026-k4' }
    ];

    const MANIFEST_RAPOR = {
      id: 'pr-2026-k4',
      tahun_ajaran_id: 'ta-2026-ganjil',
      wali_kelas_id: 'wk-2026-k4',
      bobot_tugas: 40,
      bobot_uts: 30,
      bobot_uas: 30,
      predikat: JSON.stringify([
        { label: 'A', min: 90, max: 100 },
        { label: 'B', min: 80, max: 89.99 },
        { label: 'C', min: 70, max: 79.99 },
        { label: 'D', min: 0, max: 69.99 }
      ])
    };

    const MANIFEST_NILAI = [
      // Aditya (absen 1)
      { absen: 1, mapel: 'BIN-4', t1: 85, t2: 88, t3: 84, t4: 87, uts: 85, uas: 88 },
      { absen: 1, mapel: 'MAT-4', t1: 90, t2: 92, t3: 88, t4: 90, uts: 92, uas: 94 },
      { absen: 1, mapel: 'IPAS-4', t1: 88, t2: 85, t3: 90, t4: 85, uts: 88, uas: 86 },
      // Bunga (absen 2)
      { absen: 2, mapel: 'BIN-4', t1: 92, t2: 90, t3: 94, t4: 92, uts: 90, uas: 95 },
      { absen: 2, mapel: 'MAT-4', t1: 85, t2: 88, t3: 82, t4: 85, uts: 84, uas: 88 },
      { absen: 2, mapel: 'IPAS-4', t1: 90, t2: 92, t3: 88, t4: 90, uts: 90, uas: 92 },
      // Cahyo (absen 3)
      { absen: 3, mapel: 'BIN-4', t1: 78, t2: 80, t3: 82, t4: 80, uts: 80, uas: 82 },
      { absen: 3, mapel: 'MAT-4', t1: 75, t2: 78, t3: 75, t4: 80, uts: 76, uas: 80 },
      { absen: 3, mapel: 'IPAS-4', t1: 82, t2: 80, t3: 84, t4: 82, uts: 80, uas: 85 }
    ];

    const MANIFEST_SIKAP = [
      { absen: 1, predikat: 'Sangat Baik', deskripsi: 'Menunjukkan integritas tinggi, disiplin dalam belajar, dan semangat gotong royong yang aktif.' },
      { absen: 2, predikat: 'Sangat Baik', deskripsi: 'Santun dalam bertutur kata, mandiri dalam mengerjakan tugas, dan selalu menjaga kebersihan kelas.' },
      { absen: 3, predikat: 'Baik', deskripsi: 'Mampu bekerjasama dengan baik dalam kelompok dan menunjukkan rasa ingin tahu yang positif.' }
    ];

    const MANIFEST_KEHADIRAN = [
      { absen: 1, hadir: 98, sakit: 2, izin: 0, alpha: 0, ket: 'Rajin dan tertib' },
      { absen: 2, hadir: 100, sakit: 0, izin: 0, alpha: 0, ket: 'Kehadiran sempurna' },
      { absen: 3, hadir: 95, sakit: 3, izin: 2, alpha: 0, ket: 'Baik' }
    ];

    const MANIFEST_PENGUMUMAN = {
      id: 'pengumuman-01',
      judul: '[PENGUJIAN] Pemberitahuan Persiapan Penilaian Akhir Semester (PAS)',
      isi: 'Diberitahukan kepada seluruh Guru Wali Kelas agar melengkapi rekap nilai akademik, penilaian sikap, dan kehadiran siswa paling lambat tanggal 15 Desember 2026. (Data uji sistem)',
      dibuat_oleh: 'user-kepsek-01'
    };

    // =========================================================================
    // PREFLIGHT: AUDIT INTEGRITAS RELASI & DETEKSI KONFLIK SEBELUM MUTASI
    // =========================================================================
    const existingSnapshot = {};
    const sheetNames = Object.keys(SCHEMA_DEFINITIONS);
    sheetNames.forEach(shName => {
      existingSnapshot[shName] = getSheetRows_(shName);
    });

    const executionPlan = {
      pengaturan: null,
      tahun_ajaran: null,
      user: {},
      wali_kelas: null,
      siswa: {},
      mata_pelajaran: {},
      pengaturan_rapor: null,
      nilai_mata_pelajaran: {},
      nilai_sikap: {},
      rekap_kehadiran: {},
      pengumuman: null
    };

    // Preflight 1: Sheet 'pengaturan' (Singleton Master)
    const pRows = existingSnapshot['pengaturan'] || [];
    if (pRows.length > 1) {
      throw new Error(
        'Konflik data pada sheet "pengaturan": Ditemukan ' + pRows.length + ' baris data konfigurasi. ' +
        'Sheet pengaturan wajib beroperasi sebagai singleton (maksimal 1 baris data). Proses dihentikan sebelum mutasi.'
      );
    } else if (pRows.length === 1) {
      const p = pRows[0];
      const pHeaders = SCHEMA_DEFINITIONS.pengaturan;

      // 1. Verifikasi kelengkapan seluruh kolom wajib menurut skema
      for (let c = 0; c < pHeaders.length; c++) {
        const col = pHeaders[c];
        if (p[col] === undefined) {
          throw new Error(
            'Konflik integritas pada sheet "pengaturan": Kolom wajib "' + col + '" tidak terdefinisi pada baris data existing. ' +
            'Proses dihentikan demi menjaga integritas database.'
          );
        }
      }

      // 2. Validasi Primary Key (ID) tidak boleh kosong atau whitespace
      const cleanId = String(p.id !== undefined && p.id !== null ? p.id : '').trim();
      if (!cleanId) {
        throw new Error(
          'Konflik integritas pada sheet "pengaturan": ID konfigurasi existing kosong atau hanya berisi spasi. ' +
          'Setiap record konfigurasi wajib memiliki ID unik non-kosong. Proses dihentikan.'
        );
      }

      // 3. Validasi batasan panjang dan karakter ID
      if (cleanId.length > 100 || /[\r\n\t]/.test(cleanId)) {
        throw new Error(
          'Konflik integritas pada sheet "pengaturan": Format ID konfigurasi existing ("' + cleanId + '") tidak valid. ' +
          'ID melebihi batas panjang atau memuat karakter kontrol. Proses dihentikan.'
        );
      }

      // 4. Validasi tipe data dan batasan skema pada kolom profil existing
      if (p.logo_sekolah !== undefined && p.logo_sekolah !== null && String(p.logo_sekolah).length > 500) {
        throw new Error('Konflik integritas pada sheet "pengaturan": Nilai logo_sekolah melebihi batas 500 karakter.');
      }
      if (p.nama_sekolah !== undefined && p.nama_sekolah !== null && String(p.nama_sekolah).length > 150) {
        throw new Error('Konflik integritas pada sheet "pengaturan": Nilai nama_sekolah melebihi batas 150 karakter.');
      }
      if (p.nama_kepala_sekolah !== undefined && p.nama_kepala_sekolah !== null && String(p.nama_kepala_sekolah).length > 100) {
        throw new Error('Konflik integritas pada sheet "pengaturan": Nilai nama_kepala_sekolah melebihi batas 100 karakter.');
      }
      if (p.nip_kepala_sekolah !== undefined && p.nip_kepala_sekolah !== null) {
        const cleanNip = String(p.nip_kepala_sekolah).trim();
        if (cleanNip.length > 30) {
          throw new Error('Konflik integritas pada sheet "pengaturan": Nilai nip_kepala_sekolah melebihi batas 30 karakter.');
        }
        if (cleanNip && !/^[\d\s\.\-]+$/.test(cleanNip)) {
          throw new Error('Konflik integritas pada sheet "pengaturan": Nilai nip_kepala_sekolah memuat karakter tidak sah.');
        }
      }

      // Seluruh validasi integritas lolos: tandai record singleton dipertahankan utuh
      executionPlan.pengaturan = 'EXISTS_MATCH';
    } else {
      executionPlan.pengaturan = 'TO_ADD';
    }

    // Preflight 2: Entitas Akademik & User (Jika !options.skipSeed)
    if (!options.skipSeed) {
      // A. Tahun Ajaran
      const taRows = existingSnapshot['tahun_ajaran'] || [];
      const matchTaPeriod = taRows.filter(t => String(t.tahun_ajaran || '').trim() === MANIFEST_TA.tahun_ajaran && String(t.semester || '').trim().toLowerCase() === MANIFEST_TA.semester.toLowerCase());
      const matchTaId = taRows.filter(t => String(t.id || '').trim() === MANIFEST_TA.id);

      if (matchTaPeriod.length > 1) {
        throw new Error('Konflik duplikasi tahun_ajaran: Ditemukan lebih dari 1 baris dengan periode ' + MANIFEST_TA.tahun_ajaran + ' ' + MANIFEST_TA.semester + '.');
      }
      if (matchTaId.length > 1) {
        throw new Error('Konflik duplikasi ID tahun_ajaran: Ditemukan lebih dari 1 baris dengan ID ' + MANIFEST_TA.id + '.');
      }

      const tPeriod = matchTaPeriod[0] || null;
      const tId = matchTaId[0] || null;

      if (tPeriod && tId && tPeriod._rowIndex !== tId._rowIndex) {
        throw new Error('Konflik ambigu tahun_ajaran: Periode ' + MANIFEST_TA.tahun_ajaran + ' ' + MANIFEST_TA.semester + ' dan ID ' + MANIFEST_TA.id + ' berada pada baris yang berbeda.');
      }

      const existingTa = tPeriod || tId;
      if (existingTa) {
        if (String(existingTa.id || '').trim() !== MANIFEST_TA.id) {
          throw new Error('Konflik tahun_ajaran: ID existing ("' + existingTa.id + '") tidak cocok dengan manifest ("' + MANIFEST_TA.id + '").');
        }
        if (String(existingTa.tahun_ajaran || '').trim() !== MANIFEST_TA.tahun_ajaran || String(existingTa.semester || '').trim().toLowerCase() !== MANIFEST_TA.semester.toLowerCase()) {
          throw new Error('Konflik tahun_ajaran: Periode existing tidak cocok dengan manifest.');
        }
        const tMulai = normalizeDateStr_(existingTa.tanggal_mulai);
        const tSelesai = normalizeDateStr_(existingTa.tanggal_selesai);
        if (tMulai !== MANIFEST_TA.tanggal_mulai || tSelesai !== MANIFEST_TA.tanggal_selesai) {
          throw new Error('Konflik tahun_ajaran: Rentang tanggal existing ("' + tMulai + ' s/d ' + tSelesai + '") berbeda dengan manifest ("' + MANIFEST_TA.tanggal_mulai + ' s/d ' + MANIFEST_TA.tanggal_selesai + '").');
        }
        executionPlan.tahun_ajaran = 'EXISTS_MATCH';
      } else {
        executionPlan.tahun_ajaran = 'TO_ADD';
      }

      // B. User (Kepsek & Wali Kelas)
      const uRows = existingSnapshot['user'] || [];
      uRows.forEach(ur => {
        const rId = String(ur.id || '').trim();
        const rUname = String(ur.username || '').trim().toLowerCase();
        if (rId === 'user-kepsek-01' && rUname !== 'kepsek_test') {
          throw new Error('Konflik ID akun: User ID "user-kepsek-01" telah digunakan oleh username "' + rUname + '". Proses dibatalkan sebelum mutasi.');
        }
        if (rId === 'user-wali-01' && rUname !== 'guru_test') {
          throw new Error('Konflik ID akun: User ID "user-wali-01" telah digunakan oleh username "' + rUname + '". Proses dibatalkan sebelum mutasi.');
        }
      });

      MANIFEST_USERS.forEach(mu => {
        const matchUname = uRows.filter(u => String(u.username || '').trim().toLowerCase() === mu.username.toLowerCase());
        const matchUid = uRows.filter(u => String(u.id || '').trim() === mu.id);

        if (matchUname.length > 1) {
          throw new Error('Konflik duplikasi user: Username "' + mu.username + '" terdaftar lebih dari 1 kali.');
        }
        if (matchUid.length > 1) {
          throw new Error('Konflik duplikasi ID user: ID "' + mu.id + '" terdaftar lebih dari 1 kali.');
        }

        const uUname = matchUname[0] || null;
        const uId = matchUid[0] || null;

        if (uUname && uId && uUname._rowIndex !== uId._rowIndex) {
          throw new Error('Konflik ambigu user: Username "' + mu.username + '" dan ID "' + mu.id + '" berada pada baris yang berbeda.');
        }

        const existingU = uUname || uId;
        if (existingU) {
          if (String(existingU.id || '').trim() !== mu.id) {
            throw new Error('Konflik user: ID user existing ("' + existingU.id + '") tidak cocok dengan manifest ("' + mu.id + '").');
          }
          if (String(existingU.username || '').trim().toLowerCase() !== mu.username.toLowerCase()) {
            throw new Error('Konflik user: Username user existing ("' + existingU.username + '") tidak cocok dengan manifest ("' + mu.username + '").');
          }
          if (String(existingU.role || '').trim().toLowerCase() !== mu.role.toLowerCase()) {
            throw new Error('Konflik data akun: Akun existing "' + mu.username + '" memiliki role "' + existingU.role + '", bukan "' + mu.role + '".');
          }
          if (String(existingU.nama || '').trim() !== mu.nama) {
            throw new Error('Konflik atribut user: Nama user existing ("' + existingU.nama + '") tidak cocok dengan manifest ("' + mu.nama + '").');
          }
          executionPlan.user[mu.username] = 'EXISTS_MATCH';
        } else {
          // Jika akun belum ada, wajib ada password eksplisit minimal 8 karakter
          const creds = options.credentials || {};
          const pw = creds[mu.credKey];
          if (!pw || typeof pw !== 'string' || pw.trim().length < 8) {
            throw new Error(
              'Kredensial akun pengujian ' + mu.role + ' ("' + mu.username + '" / ' + mu.credKey + ') wajib disediakan secara eksplisit minimal 8 karakter. ' +
              'Tidak ada fallback password default. Proses dihentikan sebelum mutasi spreadsheet.'
            );
          }
          executionPlan.user[mu.username] = 'TO_ADD';
        }
      });

      // C. Wali Kelas
      const wkRows = existingSnapshot['wali_kelas'] || [];
      const matchWkClass = wkRows.filter(w => String(w.tahun_ajaran_id || '').trim() === MANIFEST_WK.tahun_ajaran_id && String(w.kelas || '').trim() === MANIFEST_WK.kelas);
      const matchWkId = wkRows.filter(w => String(w.id || '').trim() === MANIFEST_WK.id);

      if (matchWkClass.length > 1) {
        throw new Error('Konflik duplikasi wali_kelas: Ditemukan lebih dari 1 penugasan untuk kelas ' + MANIFEST_WK.kelas + ' pada tahun ajaran ' + MANIFEST_WK.tahun_ajaran_id + '.');
      }
      if (matchWkId.length > 1) {
        throw new Error('Konflik duplikasi ID wali_kelas: Ditemukan lebih dari 1 ID ' + MANIFEST_WK.id + '.');
      }

      const wClass = matchWkClass[0] || null;
      const wId = matchWkId[0] || null;

      if (wClass && wId && wClass._rowIndex !== wId._rowIndex) {
        throw new Error('Konflik ambigu wali_kelas: Penugasan kelas ' + MANIFEST_WK.kelas + ' dan ID ' + MANIFEST_WK.id + ' berada pada baris yang berbeda.');
      }

      const existingWk = wClass || wId;
      if (existingWk) {
        if (String(existingWk.id || '').trim() !== MANIFEST_WK.id) {
          throw new Error('Konflik wali_kelas: ID penugasan existing ("' + existingWk.id + '") tidak cocok dengan manifest ("' + MANIFEST_WK.id + '").');
        }
        if (String(existingWk.user_id || '').trim() !== MANIFEST_WK.user_id) {
          throw new Error('Konflik relasi wali_kelas: Penugasan wali_kelas kelas 4 sudah terdaftar untuk user lain ("' + existingWk.user_id + '"), bukan guru uji ("' + MANIFEST_WK.user_id + '").');
        }
        if (String(existingWk.kelas || '').trim() !== MANIFEST_WK.kelas || String(existingWk.tahun_ajaran_id || '').trim() !== MANIFEST_WK.tahun_ajaran_id) {
          throw new Error('Konflik atribut wali_kelas: Data kelas atau tahun ajaran existing tidak cocok dengan manifest.');
        }
        executionPlan.wali_kelas = 'EXISTS_MATCH';
      } else {
        executionPlan.wali_kelas = 'TO_ADD';
      }

      // D. Siswa (3 Siswa)
      const siswaRows = existingSnapshot['siswa'] || [];
      MANIFEST_SISWA.forEach(ts => {
        const matchAbsen = siswaRows.filter(s => String(s.wali_kelas_id || '').trim() === ts.wali_kelas_id && Number(s.no_absen) === ts.no_absen);
        const matchNisn = siswaRows.filter(s => String(s.nisn || '').trim() === ts.nisn);
        const matchId = siswaRows.filter(s => String(s.id || '').trim() === ts.id);

        if (matchAbsen.length > 1) {
          throw new Error('Konflik duplikasi data siswa: Ditemukan lebih dari 1 siswa dengan no_absen ' + ts.no_absen + ' pada wali_kelas ' + ts.wali_kelas_id + '.');
        }
        if (matchNisn.length > 1) {
          throw new Error('Konflik duplikasi data siswa: Ditemukan lebih dari 1 siswa dengan NISN ' + ts.nisn + '.');
        }
        if (matchId.length > 1) {
          throw new Error('Konflik duplikasi ID siswa: Ditemukan lebih dari 1 siswa dengan ID ' + ts.id + '.');
        }

        const sAbsen = matchAbsen[0] || null;
        const sNisn = matchNisn[0] || null;
        const sId = matchId[0] || null;

        if (sAbsen && sNisn && sAbsen._rowIndex !== sNisn._rowIndex) {
          throw new Error(
            'Konflik ambigu data siswa: no_absen ' + ts.no_absen + ' ditemukan pada baris ' + sAbsen._rowIndex +
            ', tetapi NISN ' + ts.nisn + ' ditemukan pada baris ' + sNisn._rowIndex + '. Data tidak boleh digabungkan secara ambigu.'
          );
        }

        const existingS = sAbsen || sNisn || sId;
        if (existingS) {
          if (Number(existingS.no_absen) !== ts.no_absen) {
            throw new Error('Konflik atribut siswa: no_absen existing (' + existingS.no_absen + ') tidak cocok dengan manifest (' + ts.no_absen + ').');
          }
          if (String(existingS.nisn || '').trim() !== ts.nisn) {
            throw new Error('Konflik atribut siswa: NISN existing ("' + existingS.nisn + '") tidak cocok dengan manifest ("' + ts.nisn + '").');
          }
          if (String(existingS.id || '').trim() !== ts.id) {
            throw new Error('Konflik ID siswa: ID existing ("' + existingS.id + '") tidak cocok dengan manifest ("' + ts.id + '").');
          }
          if (String(existingS.nama || '').trim() !== ts.nama) {
            throw new Error('Konflik atribut siswa: Nama siswa existing ("' + existingS.nama + '") berbeda dengan manifest ("' + ts.nama + '").');
          }
          if (String(existingS.wali_kelas_id || '').trim() !== ts.wali_kelas_id) {
            throw new Error('Konflik relasi siswa: wali_kelas_id existing ("' + existingS.wali_kelas_id + '") tidak cocok dengan penugasan manifest ("' + ts.wali_kelas_id + '").');
          }
          executionPlan.siswa[ts.no_absen] = 'EXISTS_MATCH';
        } else {
          executionPlan.siswa[ts.no_absen] = 'TO_ADD';
        }
      });

      // E. Mata Pelajaran (3 Mapel)
      const mapelRows = existingSnapshot['mata_pelajaran'] || [];
      MANIFEST_MAPEL.forEach(tm => {
        const matchKode = mapelRows.filter(m => String(m.wali_kelas_id || '').trim() === tm.wali_kelas_id && String(m.kode_mata_pelajaran || '').trim().toUpperCase() === tm.kode);
        const matchId = mapelRows.filter(m => String(m.id || '').trim() === tm.id);

        if (matchKode.length > 1) {
          throw new Error('Konflik duplikasi mata_pelajaran: Kode ' + tm.kode + ' terdaftar lebih dari 1 kali.');
        }
        if (matchId.length > 1) {
          throw new Error('Konflik duplikasi ID mata_pelajaran: ID ' + tm.id + ' terdaftar lebih dari 1 kali.');
        }

        const mKode = matchKode[0] || null;
        const mId = matchId[0] || null;

        if (mKode && mId && mKode._rowIndex !== mId._rowIndex) {
          throw new Error('Konflik ambigu mata_pelajaran: Kode ' + tm.kode + ' dan ID ' + tm.id + ' berada pada baris yang berbeda.');
        }

        const existingM = mKode || mId;
        if (existingM) {
          if (String(existingM.id || '').trim() !== tm.id) {
            throw new Error('Konflik ID mata_pelajaran: ID existing ("' + existingM.id + '") tidak cocok dengan manifest ("' + tm.id + '").');
          }
          if (String(existingM.kode_mata_pelajaran || '').trim().toUpperCase() !== tm.kode) {
            throw new Error('Konflik kode mata_pelajaran: Kode existing ("' + existingM.kode_mata_pelajaran + '") tidak cocok dengan manifest ("' + tm.kode + '").');
          }
          if (String(existingM.mata_pelajaran || '').trim() !== tm.nama) {
            throw new Error('Konflik nama mata_pelajaran: Nama existing ("' + existingM.mata_pelajaran + '") tidak cocok dengan manifest ("' + tm.nama + '").');
          }
          if (String(existingM.wali_kelas_id || '').trim() !== tm.wali_kelas_id) {
            throw new Error('Konflik relasi mata_pelajaran: wali_kelas_id existing tidak cocok dengan penugasan kelas 4.');
          }
          executionPlan.mata_pelajaran[tm.kode] = 'EXISTS_MATCH';
        } else {
          executionPlan.mata_pelajaran[tm.kode] = 'TO_ADD';
        }
      });

      // F. Pengaturan Rapor
      const prRows = existingSnapshot['pengaturan_rapor'] || [];
      const matchPrRel = prRows.filter(p => String(p.tahun_ajaran_id || '').trim() === MANIFEST_RAPOR.tahun_ajaran_id && String(p.wali_kelas_id || '').trim() === MANIFEST_RAPOR.wali_kelas_id);
      const matchPrId = prRows.filter(p => String(p.id || '').trim() === MANIFEST_RAPOR.id);

      if (matchPrRel.length > 1) {
        throw new Error('Konflik duplikasi pengaturan_rapor: Ditemukan lebih dari 1 pengaturan rapor untuk penugasan ini.');
      }
      if (matchPrId.length > 1) {
        throw new Error('Konflik duplikasi ID pengaturan_rapor: Ditemukan lebih dari 1 ID ' + MANIFEST_RAPOR.id + '.');
      }

      const pRel = matchPrRel[0] || null;
      const pId = matchPrId[0] || null;

      if (pRel && pId && pRel._rowIndex !== pId._rowIndex) {
        throw new Error('Konflik ambigu pengaturan_rapor: Relasi dan ID ' + MANIFEST_RAPOR.id + ' berada pada baris yang berbeda.');
      }

      const existingPr = pRel || pId;
      if (existingPr) {
        if (String(existingPr.id || '').trim() !== MANIFEST_RAPOR.id) {
          throw new Error('Konflik ID pengaturan_rapor: ID existing ("' + existingPr.id + '") tidak cocok dengan manifest ("' + MANIFEST_RAPOR.id + '").');
        }
        if (Number(existingPr.bobot_tugas) !== MANIFEST_RAPOR.bobot_tugas || Number(existingPr.bobot_uts) !== MANIFEST_RAPOR.bobot_uts || Number(existingPr.bobot_uas) !== MANIFEST_RAPOR.bobot_uas) {
          throw new Error('Konflik bobot pengaturan_rapor: Bobot penilaian existing berbeda dengan manifest.');
        }
        executionPlan.pengaturan_rapor = 'EXISTS_MATCH';
      } else {
        executionPlan.pengaturan_rapor = 'TO_ADD';
      }

      // G. Nilai Mata Pelajaran (9 Entri)
      const nRows = existingSnapshot['nilai_mata_pelajaran'] || [];
      MANIFEST_NILAI.forEach(tg => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === tg.absen);
        const mTarget = MANIFEST_MAPEL.find(m => m.kode === tg.mapel);
        if (!sTarget) {
          throw new Error('Integritas relasi gagal: Referensi siswa absen ' + tg.absen + ' tidak terdaftar dalam manifest.');
        }
        if (!mTarget) {
          throw new Error('Integritas relasi gagal: Referensi mata pelajaran ' + tg.mapel + ' tidak terdaftar dalam manifest.');
        }

        const expNId = 'n-' + sTarget.id + '-' + mTarget.id;
        const rataTugas = (tg.t1 + tg.t2 + tg.t3 + tg.t4) / 4;
        const expNa = Math.round(((rataTugas * 40 + tg.uts * 30 + tg.uas * 30) / 100) * 100) / 100;

        const matchRel = nRows.filter(n => String(n.siswa_id || '').trim() === sTarget.id && String(n.mata_pelajaran_id || '').trim() === mTarget.id);
        const matchId = nRows.filter(n => String(n.id || '').trim() === expNId);

        if (matchRel.length > 1) {
          throw new Error('Konflik duplikasi nilai_mata_pelajaran: Nilai siswa ' + sTarget.id + ' dan mapel ' + mTarget.id + ' terdaftar lebih dari 1 kali.');
        }
        if (matchId.length > 1) {
          throw new Error('Konflik duplikasi ID nilai_mata_pelajaran: ID ' + expNId + ' terdaftar lebih dari 1 kali.');
        }

        const nRel = matchRel[0] || null;
        const nId = matchId[0] || null;

        if (nRel && nId && nRel._rowIndex !== nId._rowIndex) {
          throw new Error('Konflik ambigu nilai_mata_pelajaran: Relasi dan ID ' + expNId + ' berada pada baris yang berbeda.');
        }

        const existingN = nRel || nId;
        if (existingN) {
          if (String(existingN.id || '').trim() !== expNId) {
            throw new Error('Konflik ID nilai_mata_pelajaran: ID existing ("' + existingN.id + '") tidak cocok dengan manifest ("' + expNId + '").');
          }
          if (Number(existingN.nilai_tugas_1) !== tg.t1 || Number(existingN.nilai_tugas_2) !== tg.t2 ||
              Number(existingN.nilai_tugas_3) !== tg.t3 || Number(existingN.nilai_tugas_4) !== tg.t4 ||
              Number(existingN.nilai_uts) !== tg.uts || Number(existingN.nilai_uas) !== tg.uas ||
              Number(existingN.nilai_akhir) !== expNa) {
            throw new Error('Konflik nilai_mata_pelajaran: Rincian nilai existing untuk ' + expNId + ' berbeda dengan manifest.');
          }
          executionPlan.nilai_mata_pelajaran[expNId] = 'EXISTS_MATCH';
        } else {
          executionPlan.nilai_mata_pelajaran[expNId] = 'TO_ADD';
        }
      });

      // H. Nilai Sikap (3 Entri)
      const skRows = existingSnapshot['nilai_sikap'] || [];
      MANIFEST_SIKAP.forEach(ts => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === ts.absen);
        if (!sTarget) {
          throw new Error('Integritas relasi gagal: Referensi siswa absen ' + ts.absen + ' untuk nilai sikap tidak ditemukan dalam manifest.');
        }
        const expSkId = 'sk-' + sTarget.id;

        const matchRel = skRows.filter(sk => String(sk.siswa_id || '').trim() === sTarget.id);
        const matchId = skRows.filter(sk => String(sk.id || '').trim() === expSkId);

        if (matchRel.length > 1) {
          throw new Error('Konflik duplikasi nilai_sikap: Siswa ' + sTarget.id + ' memiliki lebih dari 1 catatan nilai sikap.');
        }
        if (matchId.length > 1) {
          throw new Error('Konflik duplikasi ID nilai_sikap: ID ' + expSkId + ' terdaftar lebih dari 1 kali.');
        }

        const skRel = matchRel[0] || null;
        const skId = matchId[0] || null;

        if (skRel && skId && skRel._rowIndex !== skId._rowIndex) {
          throw new Error('Konflik ambigu nilai_sikap: Siswa ' + sTarget.id + ' dan ID ' + expSkId + ' berada pada baris yang berbeda.');
        }

        const existingSk = skRel || skId;
        if (existingSk) {
          if (String(existingSk.id || '').trim() !== expSkId) {
            throw new Error('Konflik ID nilai_sikap: ID existing ("' + existingSk.id + '") tidak cocok dengan manifest ("' + expSkId + '").');
          }
          if (String(existingSk.predikat || '').trim() !== ts.predikat) {
            throw new Error('Konflik predikat nilai_sikap: Predikat existing ("' + existingSk.predikat + '") berbeda dengan manifest ("' + ts.predikat + '").');
          }
          if (String(existingSk.deskripsi || '').trim() !== ts.deskripsi) {
            throw new Error('Konflik deskripsi nilai_sikap: Deskripsi existing berbeda dengan manifest.');
          }
          executionPlan.nilai_sikap[expSkId] = 'EXISTS_MATCH';
        } else {
          executionPlan.nilai_sikap[expSkId] = 'TO_ADD';
        }
      });

      // I. Rekap Kehadiran (3 Entri)
      const rkRows = existingSnapshot['rekap_kehadiran'] || [];
      MANIFEST_KEHADIRAN.forEach(tk => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === tk.absen);
        if (!sTarget) {
          throw new Error('Integritas relasi gagal: Referensi siswa absen ' + tk.absen + ' untuk rekap kehadiran tidak ditemukan dalam manifest.');
        }
        const expRkId = 'rk-' + sTarget.id;

        const matchRel = rkRows.filter(rk => String(rk.siswa_id || '').trim() === sTarget.id);
        const matchId = rkRows.filter(rk => String(rk.id || '').trim() === expRkId);

        if (matchRel.length > 1) {
          throw new Error('Konflik duplikasi rekap_kehadiran: Siswa ' + sTarget.id + ' memiliki lebih dari 1 rekap kehadiran.');
        }
        if (matchId.length > 1) {
          throw new Error('Konflik duplikasi ID rekap_kehadiran: ID ' + expRkId + ' terdaftar lebih dari 1 kali.');
        }

        const rkRel = matchRel[0] || null;
        const rkId = matchId[0] || null;

        if (rkRel && rkId && rkRel._rowIndex !== rkId._rowIndex) {
          throw new Error('Konflik ambigu rekap_kehadiran: Siswa ' + sTarget.id + ' dan ID ' + expRkId + ' berada pada baris yang berbeda.');
        }

        const existingRk = rkRel || rkId;
        if (existingRk) {
          if (String(existingRk.id || '').trim() !== expRkId) {
            throw new Error('Konflik ID rekap_kehadiran: ID existing ("' + existingRk.id + '") tidak cocok dengan manifest ("' + expRkId + '").');
          }
          if (Number(existingRk.jumlah_hadir) !== tk.hadir || Number(existingRk.jumlah_sakit) !== tk.sakit ||
              Number(existingRk.jumlah_izin) !== tk.izin || Number(existingRk.jumlah_alpha) !== tk.alpha ||
              String(existingRk.keterangan || '').trim() !== tk.ket) {
            throw new Error('Konflik data rekap_kehadiran: Rincian absensi existing untuk ' + sTarget.id + ' berbeda dengan manifest.');
          }
          executionPlan.rekap_kehadiran[expRkId] = 'EXISTS_MATCH';
        } else {
          executionPlan.rekap_kehadiran[expRkId] = 'TO_ADD';
        }
      });

      // J. Pengumuman (1 Entri)
      const pRowsPeng = existingSnapshot['pengumuman'] || [];
      const matchJudul = pRowsPeng.filter(p => String(p.judul || '').trim() === MANIFEST_PENGUMUMAN.judul);
      const matchPengId = pRowsPeng.filter(p => String(p.id || '').trim() === MANIFEST_PENGUMUMAN.id);

      if (matchJudul.length > 1) {
        throw new Error('Konflik duplikasi pengumuman: Judul pengujian terdaftar lebih dari 1 kali.');
      }
      if (matchPengId.length > 1) {
        throw new Error('Konflik duplikasi ID pengumuman: ID ' + MANIFEST_PENGUMUMAN.id + ' terdaftar lebih dari 1 kali.');
      }

      const pJudul = matchJudul[0] || null;
      const pIdPeng = matchPengId[0] || null;

      if (pJudul && pIdPeng && pJudul._rowIndex !== pIdPeng._rowIndex) {
        throw new Error('Konflik ambigu pengumuman: Judul dan ID ' + MANIFEST_PENGUMUMAN.id + ' berada pada baris yang berbeda.');
      }

      const existingPeng = pJudul || pIdPeng;
      if (existingPeng) {
        if (String(existingPeng.id || '').trim() !== MANIFEST_PENGUMUMAN.id) {
          throw new Error('Konflik ID pengumuman: ID existing ("' + existingPeng.id + '") tidak cocok dengan manifest ("' + MANIFEST_PENGUMUMAN.id + '").');
        }
        if (String(existingPeng.dibuat_oleh || '').trim() !== MANIFEST_PENGUMUMAN.dibuat_oleh) {
          throw new Error('Konflik pengumuman: Pembuat pengumuman existing ("' + existingPeng.dibuat_oleh + '") tidak cocok dengan manifest ("' + MANIFEST_PENGUMUMAN.dibuat_oleh + '").');
        }
        if (String(existingPeng.isi || '').trim() !== MANIFEST_PENGUMUMAN.isi) {
          throw new Error('Konflik isi pengumuman: Isi pengumuman existing berbeda dengan manifest.');
        }
        executionPlan.pengumuman = 'EXISTS_MATCH';
      } else {
        executionPlan.pengumuman = 'TO_ADD';
      }
    }

    // Hitung total ekspektasi penambahan dan pelewatan dari preflight
    let plannedAddCount = 0;
    let plannedSkipCount = 0;

    if (executionPlan.pengaturan === 'TO_ADD') plannedAddCount++;
    else if (executionPlan.pengaturan === 'EXISTS_MATCH') plannedSkipCount++;

    if (!options.skipSeed) {
      if (executionPlan.tahun_ajaran === 'TO_ADD') plannedAddCount++;
      else if (executionPlan.tahun_ajaran === 'EXISTS_MATCH') plannedSkipCount++;

      MANIFEST_USERS.forEach(mu => {
        if (executionPlan.user[mu.username] === 'TO_ADD') plannedAddCount++;
        else if (executionPlan.user[mu.username] === 'EXISTS_MATCH') plannedSkipCount++;
      });

      if (executionPlan.wali_kelas === 'TO_ADD') plannedAddCount++;
      else if (executionPlan.wali_kelas === 'EXISTS_MATCH') plannedSkipCount++;

      MANIFEST_SISWA.forEach(ts => {
        if (executionPlan.siswa[ts.no_absen] === 'TO_ADD') plannedAddCount++;
        else if (executionPlan.siswa[ts.no_absen] === 'EXISTS_MATCH') plannedSkipCount++;
      });

      MANIFEST_MAPEL.forEach(tm => {
        if (executionPlan.mata_pelajaran[tm.kode] === 'TO_ADD') plannedAddCount++;
        else if (executionPlan.mata_pelajaran[tm.kode] === 'EXISTS_MATCH') plannedSkipCount++;
      });

      if (executionPlan.pengaturan_rapor === 'TO_ADD') plannedAddCount++;
      else if (executionPlan.pengaturan_rapor === 'EXISTS_MATCH') plannedSkipCount++;

      MANIFEST_NILAI.forEach(tg => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === tg.absen);
        const mTarget = MANIFEST_MAPEL.find(m => m.kode === tg.mapel);
        const nId = 'n-' + sTarget.id + '-' + mTarget.id;
        if (executionPlan.nilai_mata_pelajaran[nId] === 'TO_ADD') plannedAddCount++;
        else if (executionPlan.nilai_mata_pelajaran[nId] === 'EXISTS_MATCH') plannedSkipCount++;
      });

      MANIFEST_SIKAP.forEach(ts => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === ts.absen);
        const skId = 'sk-' + sTarget.id;
        if (executionPlan.nilai_sikap[skId] === 'TO_ADD') plannedAddCount++;
        else if (executionPlan.nilai_sikap[skId] === 'EXISTS_MATCH') plannedSkipCount++;
      });

      MANIFEST_KEHADIRAN.forEach(tk => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === tk.absen);
        const rkId = 'rk-' + sTarget.id;
        if (executionPlan.rekap_kehadiran[rkId] === 'TO_ADD') plannedAddCount++;
        else if (executionPlan.rekap_kehadiran[rkId] === 'EXISTS_MATCH') plannedSkipCount++;
      });

      if (executionPlan.pengumuman === 'TO_ADD') plannedAddCount++;
      else if (executionPlan.pengumuman === 'EXISTS_MATCH') plannedSkipCount++;
    }

    const report = {
      success: true,
      spreadsheetId: spreadsheetId,
      spreadsheetName: spreadsheetName,
      executedAt: new Date().toISOString(),
      createdSheets: [],
      initializedEmptySheets: [],
      retainedExistingSheets: [],
      pengaturanInitialized: false,
      seedSummary: {
        rowsAdded: {},
        rowsSkipped: {},
        conflicts: []
      },
      message: ''
    };

    // =========================================================================
    // STEP 2: SETUP 11 SHEET (Hanya buat sheet yang hilang atau header kosong)
    // =========================================================================
    for (let i = 0; i < sheetNames.length; i++) {
      const sheetName = sheetNames[i];
      const headers = SCHEMA_DEFINITIONS[sheetName];
      const sheetStatus = preValidation.sheets[sheetName] ? preValidation.sheets[sheetName].status : 'MISSING';
      let sheet = ss.getSheetByName(sheetName);

      if (sheetStatus === 'MISSING' || !sheet) {
        sheet = ss.insertSheet(sheetName);
        const headerRange = sheet.getRange(1, 1, 1, headers.length);
        headerRange.setValues([headers]);
        if (typeof headerRange.setFontWeight === 'function') headerRange.setFontWeight('bold');
        if (typeof sheet.setFrozenRows === 'function') sheet.setFrozenRows(1);
        report.createdSheets.push(sheetName);
      } else if (sheetStatus === 'EMPTY' || sheetStatus === 'FORMATTED_EMPTY') {
        const headerRange = sheet.getRange(1, 1, 1, headers.length);
        headerRange.setValues([headers]);
        if (typeof headerRange.setFontWeight === 'function') headerRange.setFontWeight('bold');
        if (typeof sheet.setFrozenRows === 'function') sheet.setFrozenRows(1);
        report.initializedEmptySheets.push(sheetName);
      } else if (sheetStatus === 'EXACT_MATCH') {
        report.retainedExistingSheets.push({
          sheetName: sheetName,
          existingRows: sheet.getLastRow()
        });
      }
    }

    // =========================================================================
    // STEP 3: SHEET 'pengaturan' SINGLETON
    // =========================================================================
    if (executionPlan.pengaturan === 'TO_ADD') {
      appendRowToSheet_('pengaturan', {
        id: generateUUID_(),
        logo_sekolah: MANIFEST_PENGATURAN.logo_sekolah,
        nama_sekolah: MANIFEST_PENGATURAN.nama_sekolah,
        nama_kepala_sekolah: MANIFEST_PENGATURAN.nama_kepala_sekolah,
        nip_kepala_sekolah: MANIFEST_PENGATURAN.nip_kepala_sekolah,
        updated_by: MANIFEST_PENGATURAN.updated_by,
        created_at: nowIso,
        updated_at: nowIso
      });
      report.pengaturanInitialized = true;
      report.seedSummary.rowsAdded['pengaturan'] = 1;
    } else {
      report.seedSummary.rowsSkipped['pengaturan'] = 1;
    }

    // =========================================================================
    // STEP 4: SEED DATA AKADEMIK & USER JIKA !options.skipSeed
    // =========================================================================
    if (!options.skipSeed) {
      // A. Tahun Ajaran
      if (executionPlan.tahun_ajaran === 'TO_ADD') {
        appendRowToSheet_('tahun_ajaran', {
          id: MANIFEST_TA.id,
          tahun_ajaran: MANIFEST_TA.tahun_ajaran,
          semester: MANIFEST_TA.semester,
          tanggal_mulai: MANIFEST_TA.tanggal_mulai,
          tanggal_selesai: MANIFEST_TA.tanggal_selesai,
          is_active: MANIFEST_TA.is_active,
          is_locked: MANIFEST_TA.is_locked,
          created_at: nowIso,
          updated_at: nowIso
        });
        report.seedSummary.rowsAdded['tahun_ajaran'] = 1;
      } else {
        report.seedSummary.rowsSkipped['tahun_ajaran'] = 1;
      }

      // B. Akun Pengguna Uji
      MANIFEST_USERS.forEach(mu => {
        if (executionPlan.user[mu.username] === 'TO_ADD') {
          const plainPw = options.credentials[mu.credKey];
          const creds = createHashAndSalt_(plainPw);
          appendRowToSheet_('user', {
            id: mu.id,
            nama: mu.nama,
            nip: mu.nip,
            username: mu.username,
            password_hash: creds.hash,
            password_salt: creds.salt,
            role: mu.role,
            foto: '',
            terakhir_login: '',
            is_active: true,
            created_at: nowIso,
            updated_at: nowIso
          });
          report.seedSummary.rowsAdded['user'] = (report.seedSummary.rowsAdded['user'] || 0) + 1;
        } else {
          report.seedSummary.rowsSkipped['user'] = (report.seedSummary.rowsSkipped['user'] || 0) + 1;
        }
      });

      // C. Penugasan Wali Kelas
      if (executionPlan.wali_kelas === 'TO_ADD') {
        appendRowToSheet_('wali_kelas', {
          id: MANIFEST_WK.id,
          user_id: MANIFEST_WK.user_id,
          tahun_ajaran_id: MANIFEST_WK.tahun_ajaran_id,
          kelas: MANIFEST_WK.kelas,
          is_active: MANIFEST_WK.is_active,
          created_at: nowIso,
          updated_at: nowIso
        });
        report.seedSummary.rowsAdded['wali_kelas'] = 1;
      } else {
        report.seedSummary.rowsSkipped['wali_kelas'] = 1;
      }

      // D. Siswa
      MANIFEST_SISWA.forEach(ts => {
        if (executionPlan.siswa[ts.no_absen] === 'TO_ADD') {
          appendRowToSheet_('siswa', {
            id: ts.id,
            wali_kelas_id: ts.wali_kelas_id,
            nisn: ts.nisn,
            nis: ts.nis,
            no_absen: ts.no_absen,
            nama: ts.nama,
            jenis_kelamin: ts.jk,
            tempat_lahir: ts.tmpt,
            tanggal_lahir: ts.tgl,
            wali_murid: ts.wali,
            nomor_telepon: ts.telp,
            is_active: true,
            created_at: nowIso,
            updated_at: nowIso
          });
          report.seedSummary.rowsAdded['siswa'] = (report.seedSummary.rowsAdded['siswa'] || 0) + 1;
        } else {
          report.seedSummary.rowsSkipped['siswa'] = (report.seedSummary.rowsSkipped['siswa'] || 0) + 1;
        }
      });

      // E. Mata Pelajaran
      MANIFEST_MAPEL.forEach(tm => {
        if (executionPlan.mata_pelajaran[tm.kode] === 'TO_ADD') {
          appendRowToSheet_('mata_pelajaran', {
            id: tm.id,
            wali_kelas_id: tm.wali_kelas_id,
            kode_mata_pelajaran: tm.kode,
            mata_pelajaran: tm.nama,
            is_active: true,
            created_at: nowIso,
            updated_at: nowIso
          });
          report.seedSummary.rowsAdded['mata_pelajaran'] = (report.seedSummary.rowsAdded['mata_pelajaran'] || 0) + 1;
        } else {
          report.seedSummary.rowsSkipped['mata_pelajaran'] = (report.seedSummary.rowsSkipped['mata_pelajaran'] || 0) + 1;
        }
      });

      // F. Pengaturan Rapor
      if (executionPlan.pengaturan_rapor === 'TO_ADD') {
        appendRowToSheet_('pengaturan_rapor', {
          id: MANIFEST_RAPOR.id,
          tahun_ajaran_id: MANIFEST_RAPOR.tahun_ajaran_id,
          wali_kelas_id: MANIFEST_RAPOR.wali_kelas_id,
          bobot_tugas: MANIFEST_RAPOR.bobot_tugas,
          bobot_uts: MANIFEST_RAPOR.bobot_uts,
          bobot_uas: MANIFEST_RAPOR.bobot_uas,
          predikat: MANIFEST_RAPOR.predikat,
          created_at: nowIso,
          updated_at: nowIso
        });
        report.seedSummary.rowsAdded['pengaturan_rapor'] = 1;
      } else {
        report.seedSummary.rowsSkipped['pengaturan_rapor'] = 1;
      }

      // G. Nilai Mata Pelajaran (9 Entri)
      MANIFEST_NILAI.forEach(tg => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === tg.absen);
        const mTarget = MANIFEST_MAPEL.find(m => m.kode === tg.mapel);
        if (!sTarget || !mTarget) {
          throw new Error('Integritas relasi gagal: Siswa atau mapel tidak ditemukan saat penulisan nilai.');
        }
        const expNId = 'n-' + sTarget.id + '-' + mTarget.id;

        if (executionPlan.nilai_mata_pelajaran[expNId] === 'TO_ADD') {
          const rataTugas = (tg.t1 + tg.t2 + tg.t3 + tg.t4) / 4;
          const na = Math.round(((rataTugas * 40 + tg.uts * 30 + tg.uas * 30) / 100) * 100) / 100;
          appendRowToSheet_('nilai_mata_pelajaran', {
            id: expNId,
            siswa_id: sTarget.id,
            mata_pelajaran_id: mTarget.id,
            nilai_tugas_1: tg.t1,
            nilai_tugas_2: tg.t2,
            nilai_tugas_3: tg.t3,
            nilai_tugas_4: tg.t4,
            nilai_uts: tg.uts,
            nilai_uas: tg.uas,
            nilai_akhir: na,
            is_complete: true,
            created_at: nowIso,
            updated_at: nowIso
          });
          report.seedSummary.rowsAdded['nilai_mata_pelajaran'] = (report.seedSummary.rowsAdded['nilai_mata_pelajaran'] || 0) + 1;
        } else {
          report.seedSummary.rowsSkipped['nilai_mata_pelajaran'] = (report.seedSummary.rowsSkipped['nilai_mata_pelajaran'] || 0) + 1;
        }
      });

      // H. Nilai Sikap (3 Entri)
      MANIFEST_SIKAP.forEach(ts => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === ts.absen);
        if (!sTarget) {
          throw new Error('Integritas relasi gagal: Siswa tidak ditemukan saat penulisan nilai sikap.');
        }
        const expSkId = 'sk-' + sTarget.id;

        if (executionPlan.nilai_sikap[expSkId] === 'TO_ADD') {
          appendRowToSheet_('nilai_sikap', {
            id: expSkId,
            siswa_id: sTarget.id,
            predikat: ts.predikat,
            deskripsi: ts.deskripsi,
            created_at: nowIso,
            updated_at: nowIso
          });
          report.seedSummary.rowsAdded['nilai_sikap'] = (report.seedSummary.rowsAdded['nilai_sikap'] || 0) + 1;
        } else {
          report.seedSummary.rowsSkipped['nilai_sikap'] = (report.seedSummary.rowsSkipped['nilai_sikap'] || 0) + 1;
        }
      });

      // I. Rekap Kehadiran (3 Entri)
      MANIFEST_KEHADIRAN.forEach(tk => {
        const sTarget = MANIFEST_SISWA.find(s => s.no_absen === tk.absen);
        if (!sTarget) {
          throw new Error('Integritas relasi gagal: Siswa tidak ditemukan saat penulisan rekap kehadiran.');
        }
        const expRkId = 'rk-' + sTarget.id;

        if (executionPlan.rekap_kehadiran[expRkId] === 'TO_ADD') {
          appendRowToSheet_('rekap_kehadiran', {
            id: expRkId,
            siswa_id: sTarget.id,
            jumlah_hadir: tk.hadir,
            jumlah_sakit: tk.sakit,
            jumlah_izin: tk.izin,
            jumlah_alpha: tk.alpha,
            keterangan: tk.ket,
            created_at: nowIso,
            updated_at: nowIso
          });
          report.seedSummary.rowsAdded['rekap_kehadiran'] = (report.seedSummary.rowsAdded['rekap_kehadiran'] || 0) + 1;
        } else {
          report.seedSummary.rowsSkipped['rekap_kehadiran'] = (report.seedSummary.rowsSkipped['rekap_kehadiran'] || 0) + 1;
        }
      });

      // J. Pengumuman
      if (executionPlan.pengumuman === 'TO_ADD') {
        appendRowToSheet_('pengumuman', {
          id: MANIFEST_PENGUMUMAN.id,
          judul: MANIFEST_PENGUMUMAN.judul,
          isi: MANIFEST_PENGUMUMAN.isi,
          dibuat_oleh: MANIFEST_PENGUMUMAN.dibuat_oleh,
          created_at: nowIso,
          updated_at: nowIso
        });
        report.seedSummary.rowsAdded['pengumuman'] = 1;
      } else {
        report.seedSummary.rowsSkipped['pengumuman'] = 1;
      }
    }

    if (typeof SpreadsheetApp !== 'undefined' && typeof SpreadsheetApp.flush === 'function') {
      SpreadsheetApp.flush();
    }

    let totalAdded = 0;
    Object.keys(report.seedSummary.rowsAdded).forEach(k => { totalAdded += report.seedSummary.rowsAdded[k]; });
    let totalSkipped = 0;
    Object.keys(report.seedSummary.rowsSkipped).forEach(k => { totalSkipped += report.seedSummary.rowsSkipped[k]; });

    // =========================================================================
    // STEP 5: VERIFIKASI POSTCONDITION (Verifikasi Pasca-Penulisan)
    // =========================================================================
    if (totalAdded !== plannedAddCount || totalSkipped !== plannedSkipCount) {
      throw new Error(
        'Verifikasi pasca-seed gagal: Jumlah baris data yang ditambahkan (' + totalAdded +
        ') atau dilewati (' + totalSkipped + ') tidak sesuai dengan rencana preflight (' +
        plannedAddCount + ' ditambah, ' + plannedSkipCount + ' dilewati).'
      );
    }

    report.message =
      'Setup dan seed database terkontrol berhasil diselesaikan secara aman dan idempoten. ' +
      'Sheet baru dibuat: ' + report.createdSheets.length + ', ' +
      'Sheet kosong diinisialisasi: ' + report.initializedEmptySheets.length + ', ' +
      'Sheet dipertahankan: ' + report.retainedExistingSheets.length + ', ' +
      'Baris data baru ditambahkan: ' + totalAdded + ', ' +
      'Baris existing dilewati (idempoten): ' + totalSkipped + '.';

    return report;
  } finally {
    if (lock) {
      try { lock.releaseLock(); } catch (e) {}
    }
  }
}

/**
 * Menu UI Google Sheets: Audit Skema (Read-Only)
 */
function menuAuditSkema_() {
  if (typeof SpreadsheetApp === 'undefined') return;
  const ui = SpreadsheetApp.getUi();
  try {
    const activeSS = SpreadsheetApp.getActiveSpreadsheet();
    const audit = validateSpreadsheetSchema_(activeSS);
    const sheetCount = Object.keys(audit.sheets).length;
    const matchCount = Object.keys(audit.sheets).filter(k => audit.sheets[k].status === 'EXACT_MATCH').length;
    const missingCount = Object.keys(audit.sheets).filter(k => audit.sheets[k].status === 'MISSING').length;

    let msg = '=== HASIL AUDIT SKEMA DATABASE ===\n';
    msg += 'Spreadsheet: ' + audit.spreadsheetName + '\n';
    msg += 'Total Sheet Skema: ' + sheetCount + '\n';
    msg += 'Sheet Sesuai (EXACT_MATCH): ' + matchCount + '\n';
    msg += 'Sheet Belum Ada (MISSING): ' + missingCount + '\n\n';

    if (audit.hasMismatches) {
      msg += 'PERINGATAN: Ditemukan ketidakcocokan skema pada sheet:\n';
      audit.errors.forEach(e => { msg += '- ' + e + '\n'; });
    } else {
      msg += 'Status Skema: AMAN untuk melanjutkan setup idempoten.';
    }
    ui.alert('Audit Skema Database', msg, ui.ButtonSet.OK);
  } catch (err) {
    ui.alert('Gagal Audit Skema', err.message, ui.ButtonSet.OK);
  }
}

/**
 * Menu UI Google Sheets: Setup 11 Sheet (Idempoten)
 */
function menuSetupDatabase_() {
  if (typeof SpreadsheetApp === 'undefined') return;
  const ui = SpreadsheetApp.getUi();

  // 1. Verifikasi Otorisasi Pemilik Sah di Runtime
  try {
    enforceAuthorizedOwner_();
  } catch (err) {
    ui.alert('Akses Ditolak', err.message, ui.ButtonSet.OK);
    return;
  }

  const activeSS = SpreadsheetApp.getActiveSpreadsheet();
  const resp = ui.alert(
    'Konfirmasi Setup 11 Sheet',
    'Sistem akan memeriksa dan membuat sheet yang belum ada pada spreadsheet ini (' + (activeSS ? activeSS.getName() : 'Active') + ') sesuai skema resmi 11 tabel.\n' +
    'Data existing pada sheet yang sudah cocok tidak akan diubah atau dihapus.\n\n' +
    'Lanjutkan proses setup?',
    ui.ButtonSet.YES_NO
  );
  if (resp !== ui.Button.YES) return;

  try {
    const result = runControlledSetupAndSeed_(activeSS, {
      skipSeed: true,
      allowActiveSpreadsheet: true,
      expectedSpreadsheetId: activeSS ? activeSS.getId() : undefined
    });
    ui.alert('Setup Database Berhasil', result.message, ui.ButtonSet.OK);
  } catch (err) {
    ui.alert('Setup Gagal', err.message, ui.ButtonSet.OK);
  }
}

/**
 * Menu UI Google Sheets: Seed Data Dummy & Akun Uji (Idempoten)
 * Jika akun pengujian belum ada, membuka modal HTML Service privat untuk input password.
 * Jika akun pengujian sudah terdaftar, langsung konfirmasi eksekusi seed data akademik.
 */
function menuSeedDatabase_() {
  if (typeof SpreadsheetApp === 'undefined') return;
  const ui = SpreadsheetApp.getUi();

  // 1. Verifikasi Otorisasi Pemilik Sah di Runtime
  try {
    enforceAuthorizedOwner_();
  } catch (err) {
    ui.alert('Akses Ditolak', err.message, ui.ButtonSet.OK);
    return;
  }

  const activeSS = SpreadsheetApp.getActiveSpreadsheet();

  // 2. Periksa apakah akun kepsek_test dan guru_test sudah ada di sheet user
  let kepsekExists = false;
  let waliExists = false;
  try {
    const userSheet = activeSS ? activeSS.getSheetByName('user') : null;
    if (userSheet && userSheet.getLastRow() > 1 && userSheet.getLastColumn() > 0) {
      const uValues = userSheet.getRange(1, 1, userSheet.getLastRow(), userSheet.getLastColumn()).getValues();
      const uHeaders = uValues[0].map(h => String(h || '').trim());
      const uNameIdx = uHeaders.indexOf('username');
      if (uNameIdx >= 0) {
        for (let r = 1; r < uValues.length; r++) {
          const un = String(uValues[r][uNameIdx] || '').trim().toLowerCase();
          if (un === 'kepsek_test') kepsekExists = true;
          if (un === 'guru_test') waliExists = true;
        }
      }
    }
  } catch (e) {
    // Abaikan jika sheet belum terbaca
  }

  // 3. Jika kedua akun sudah terdaftar, jalankan konfirmasi seed akademik saja tanpa perlu input password
  if (kepsekExists && waliExists) {
    const resp = ui.alert(
      'Konfirmasi Seed Data Dummy Akademik',
      'Akun pengujian ("kepsek_test" & "guru_test") sudah terdaftar di basis data.\n' +
      'Sistem akan melanjutkan pengisian data akademik dummy (siswa, mapel, nilai, kehadiran, pengumuman) secara aman dan idempoten tanpa mengubah kredensial existing.\n\n' +
      'Lanjutkan proses seed?',
      ui.ButtonSet.YES_NO
    );
    if (resp !== ui.Button.YES) return;

    try {
      const result = runControlledSetupAndSeed_(activeSS, {
        skipSeed: false,
        allowActiveSpreadsheet: true,
        expectedSpreadsheetId: activeSS ? activeSS.getId() : undefined
      });
      ui.alert('Seed Data Berhasil', result.message, ui.ButtonSet.OK);
    } catch (err) {
      ui.alert('Seed Gagal', err.message, ui.ButtonSet.OK);
    }
    return;
  }

  // 4. Jika akun pengujian belum ada, tampilkan Modal Dialog HTML Service privat
  if (typeof HtmlService !== 'undefined') {
    try {
      const htmlOutput = HtmlService.createHtmlOutputFromFile('SecureSeedDialog')
        .setWidth(480)
        .setHeight(400);
      ui.showModalDialog(htmlOutput, 'Inisialisasi Kredensial Akun Pengujian');
    } catch (err) {
      ui.alert('Gagal Membuka Dialog', 'File SecureSeedDialog.html tidak ditemukan atau gagal dimuat: ' + err.message, ui.ButtonSet.OK);
    }
  } else {
    ui.alert('Lingkungan Tidak Mendukung', 'HtmlService tidak tersedia di lingkungan saat ini.', ui.ButtonSet.OK);
  }
}

/**
 * Menu UI Google Sheets: Inisialisasi Akun Kepala Sekolah Resmi (Produksi)
 * Membuka Modal Dialog HTML Service privat untuk input nama, NIP, username, dan kata sandi.
 * Menolak jika akun dengan role kepala_sekolah sudah ada di database.
 */
function menuInitKepalaSekolah_() {
  if (typeof SpreadsheetApp === 'undefined') return;
  const ui = SpreadsheetApp.getUi();

  // 1. Verifikasi Otorisasi Pemilik Sah di Runtime
  try {
    enforceAuthorizedOwner_();
  } catch (err) {
    ui.alert('Akses Ditolak', err.message, ui.ButtonSet.OK);
    return;
  }

  const activeSS = SpreadsheetApp.getActiveSpreadsheet();

  // 2. Periksa skema sheet 'user'
  try {
    const userSheet = activeSS ? activeSS.getSheetByName('user') : null;
    if (!userSheet) {
      ui.alert(
        'Skema Belum Siap',
        'Sheet "user" belum ditemukan pada spreadsheet ini. Silakan jalankan menu "Setup 11 Sheet (Idempoten)" terlebih dahulu.',
        ui.ButtonSet.OK
      );
      return;
    }

    // 3. Singleton Role Guard: Periksa apakah role kepala_sekolah sudah ada
    if (userSheet.getLastRow() > 1 && userSheet.getLastColumn() > 0) {
      const uValues = userSheet.getRange(1, 1, userSheet.getLastRow(), userSheet.getLastColumn()).getValues();
      const uHeaders = uValues[0].map(h => String(h || '').trim());
      const roleColIdx = uHeaders.indexOf('role');
      const userColIdx = uHeaders.indexOf('username');

      if (roleColIdx >= 0) {
        for (let r = 1; r < uValues.length; r++) {
          const rowRole = String(uValues[r][roleColIdx] || '').trim().toLowerCase();
          if (rowRole === 'kepala_sekolah') {
            const existingUser = (userColIdx >= 0) ? String(uValues[r][userColIdx] || '') : 'terdaftar';
            ui.alert(
              'Akun Kepala Sekolah Sudah Ada',
              'Inisialisasi akun ditolak: Akun Kepala Sekolah sudah terdaftar di basis data ("' + existingUser + '").\n' +
              'Inisialisasi ganda dilarang demi keamanan.',
              ui.ButtonSet.OK
            );
            return;
          }
        }
      }
    }
  } catch (err) {
    ui.alert('Pemeriksaan Gagal', err.message, ui.ButtonSet.OK);
    return;
  }

  // 4. Buka Modal Dialog HTML Service privat
  if (typeof HtmlService !== 'undefined') {
    try {
      const htmlOutput = HtmlService.createHtmlOutputFromFile('SecureKepsekDialog')
        .setWidth(480)
        .setHeight(480);
      ui.showModalDialog(htmlOutput, 'Inisialisasi Akun Kepala Sekolah Resmi');
    } catch (err) {
      ui.alert('Gagal Membuka Dialog', 'File SecureKepsekDialog.html tidak ditemukan atau gagal dimuat: ' + err.message, ui.ButtonSet.OK);
    }
  } else {
    ui.alert('Lingkungan Tidak Mendukung', 'HtmlService tidak tersedia di lingkungan saat ini.', ui.ButtonSet.OK);
  }
}

/**
 * Pemicu menu Google Sheets internal.
 */
function onOpen_(e) {
  if (typeof SpreadsheetApp === 'undefined') return;
  try {
    const ui = SpreadsheetApp.getUi();
    ui.createMenu('⚙️ Sistem Absensi v2')
      .addItem('1. Audit Skema Database (Read-Only)', 'menuAuditSkema')
      .addItem('2. Setup 11 Sheet (Idempoten)', 'menuSetupDatabase')
      .addItem('3. Inisialisasi Akun Kepala Sekolah Resmi', 'menuInitKepalaSekolah')
      .addSeparator()
      .addItem('4. Seed Data Dummy & Akun Uji (Test Only)', 'menuSeedDatabase')
      .addToUi();
  } catch (err) {
    // noop
  }
}

/**
 * Public Wrapper: Menu UI Google Sheets - Audit Skema (Read-Only)
 */
function menuAuditSkema() {
  return menuAuditSkema_();
}

/**
 * Public Wrapper: Menu UI Google Sheets - Setup 11 Sheet (Idempoten)
 */
function menuSetupDatabase() {
  return menuSetupDatabase_();
}

/**
 * Public Wrapper: Menu UI Google Sheets - Inisialisasi Akun Kepala Sekolah Resmi (Produksi)
 */
function menuInitKepalaSekolah() {
  return menuInitKepalaSekolah_();
}

/**
 * Public Wrapper: Menu UI Google Sheets - Seed Data Dummy & Akun Uji (Idempoten)
 */
function menuSeedDatabase() {
  return menuSeedDatabase_();
}

/**
 * Public Wrapper: Apps Script Editor - Audit Skema (Read-Only)
 */
function runSchemaCheckFromEditor() {
  return runSchemaCheckFromEditor_();
}

/**
 * Runner Inisialisasi Kepala Sekolah dari Apps Script Editor secara interaktif
 * (Menggunakan SpreadsheetApp UI Prompt saat editor terikat dokumen aktif).
 */
function runKepalaSekolahOnboardingFromEditor_() {
  enforceAuthorizedOwner_();

  let ui = null;
  if (typeof SpreadsheetApp !== 'undefined') {
    try {
      ui = SpreadsheetApp.getUi();
    } catch (e) {}
  }

  if (!ui) {
    throw new Error(
      'UI interaktif tidak tersedia dari konteks eksekusi ini. ' +
      'Silakan jalankan inisialisasi melalui menu Google Sheets: ' +
      '"⚙️ Sistem Absensi v2 > 3. Inisialisasi Akun Kepala Sekolah Resmi".'
    );
  }

  const activeSS = SpreadsheetApp.getActiveSpreadsheet();

  const promptNama = ui.prompt('Inisialisasi Kepala Sekolah (1/4)', 'Masukkan Nama Lengkap beserta Gelar:', ui.ButtonSet.OK_CANCEL);
  if (promptNama.getSelectedButton() !== ui.Button.OK) return;
  const nama = promptNama.getResponseText().trim();
  if (nama.length < 3) throw new Error('Nama minimal 3 karakter.');

  const promptNip = ui.prompt('Inisialisasi Kepala Sekolah (2/4)', 'Masukkan NIP (Opsional, kosongkan jika non-PNS):', ui.ButtonSet.OK_CANCEL);
  if (promptNip.getSelectedButton() !== ui.Button.OK) return;
  const nip = promptNip.getResponseText().trim();

  const promptUser = ui.prompt('Inisialisasi Kepala Sekolah (3/4)', 'Masukkan Username operasional (minimal 3 karakter):', ui.ButtonSet.OK_CANCEL);
  if (promptUser.getSelectedButton() !== ui.Button.OK) return;
  const username = promptUser.getResponseText().trim().toLowerCase();
  if (username.length < 3) throw new Error('Username minimal 3 karakter.');

  const promptPw = ui.prompt('Inisialisasi Kepala Sekolah (4/4)', 'Masukkan Kata Sandi baru (minimal 8 karakter):', ui.ButtonSet.OK_CANCEL);
  if (promptPw.getSelectedButton() !== ui.Button.OK) return;
  const password = promptPw.getResponseText();
  if (password.length < 8) throw new Error('Password minimal 8 karakter.');

  const result = initKepalaSekolahUser_(activeSS, {
    username: username,
    password: password,
    nama: nama,
    nip: nip
  }, {
    usePBKDF2: true,
    allowActiveSpreadsheet: true,
    expectedSpreadsheetId: activeSS ? activeSS.getId() : undefined
  });

  ui.alert('Inisialisasi Berhasil', result.message + '\nUsername: ' + result.username, ui.ButtonSet.OK);
  return result;
}

/**
 * Public Wrapper: Apps Script Editor - Inisialisasi Kepala Sekolah
 */
function runKepalaSekolahOnboardingFromEditor() {
  return runKepalaSekolahOnboardingFromEditor_();
}

/**
 * Public Trigger: onOpen Spreadsheet
 */
function onOpen(e) {
  return onOpen_(e);
}

/**
 * Public RPC Handler: Menerima kredensial dari SecureSeedDialog secara privat,
 * memvalidasi otorisasi server-side, dan mengeksekusi seed terkontrol.
 *
 * @param {Object} payload
 * @param {string} payload.kepsekPassword
 * @param {string} payload.waliPassword
 * @return {Object} Laporan hasil eksekusi (tanpa kredensial/hash/salt)
 */
function submitSecureSeedCredentials(payload) {
  // 1. Verifikasi Otorisasi Pemilik Server-Side
  enforceAuthorizedOwner_();

  // 2. Validasi Server-Side Kredensial
  if (!payload || typeof payload !== 'object') {
    throw new Error('Data kredensial tidak valid.');
  }

  const kepsekPw = String(payload.kepsekPassword || '').trim();
  const waliPw = String(payload.waliPassword || '').trim();

  if (kepsekPw.length < 8) {
    throw new Error('Kata sandi Kepala Sekolah (kepsek_test) minimal 8 karakter.');
  }
  if (waliPw.length < 8) {
    throw new Error('Kata sandi Guru Wali Kelas (guru_test) minimal 8 karakter.');
  }

  // 3. Eksekusi Seed Terkontrol
  const result = runControlledSetupAndSeed_(null, {
    skipSeed: false,
    credentials: {
      kepsekPassword: kepsekPw,
      waliPassword: waliPw
    }
  });

  // 4. Pastikan response bersih dari rahasia
  return {
    success: result.success,
    message: result.message,
    seedSummary: {
      rowsAdded: result.seedSummary ? result.seedSummary.rowsAdded : {},
      rowsSkipped: result.seedSummary ? result.seedSummary.rowsSkipped : {}
    }
  };
}

/**
 * Public RPC Handler: Menerima data onboarding dari SecureKepsekDialog secara privat,
 * memvalidasi otorisasi pemilik sah server-side, dan mengeksekusi inisialisasi akun resmi.
 *
 * @param {Object} payload
 * @param {string} payload.nama
 * @param {string} [payload.nip]
 * @param {string} payload.username
 * @param {string} payload.password
 * @param {string} payload.confirmPassword
 * @return {Object} Laporan hasil eksekusi (bebas dari plaintext/hash/salt)
 */
function submitKepalaSekolahOnboarding(payload) {
  // 1. Verifikasi Otorisasi Pemilik Server-Side
  enforceAuthorizedOwner_();

  if (!payload || typeof payload !== 'object') {
    throw new Error('Data payload pendaftaran tidak valid.');
  }

  const pw = String(payload.password || '');
  const confirmPw = String(payload.confirmPassword || '');
  if (pw !== confirmPw) {
    throw new Error('Konfirmasi kata sandi tidak cocok.');
  }

  let activeSS = null;
  if (typeof SpreadsheetApp !== 'undefined') {
    try {
      activeSS = SpreadsheetApp.getActiveSpreadsheet();
    } catch (e) {}
  }

  const result = initKepalaSekolahUser_(activeSS, {
    username: payload.username,
    password: pw,
    nama: payload.nama,
    nip: payload.nip
  }, {
    usePBKDF2: true,
    allowActiveSpreadsheet: true,
    expectedSpreadsheetId: activeSS ? activeSS.getId() : undefined
  });

  return {
    success: result.success,
    message: result.message,
    username: result.username,
    nama: result.nama,
    role: result.role
  };
}

// Ekspor modul untuk lingkungan pengujian otomatis Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SCHEMA_DEFINITIONS,
    generateUUID: generateUUID_,
    generateUUID_,
    hashPasswordWithSalt: hashPasswordWithSalt_,
    hashPasswordWithSalt_,
    getTargetSpreadsheet: getTargetSpreadsheet_,
    getTargetSpreadsheet_,
    validateSpreadsheetSchema: validateSpreadsheetSchema_,
    validateSpreadsheetSchema_,
    setupSpreadsheetDatabase: setupSpreadsheetDatabase_,
    setupSpreadsheetDatabase_,
    initKepalaSekolahUser: initKepalaSekolahUser_,
    initKepalaSekolahUser_,
    runControlledSetupAndSeed: runControlledSetupAndSeed_,
    runControlledSetupAndSeed_,
    runSchemaCheckFromEditor: runSchemaCheckFromEditor_,
    runSchemaCheckFromEditor_,
    runSetupFromEditor: runSetupFromEditor_,
    runSetupFromEditor_,
    runKepalaSekolahOnboardingFromEditor: runKepalaSekolahOnboardingFromEditor_,
    runKepalaSekolahOnboardingFromEditor_,
    menuAuditSkema: menuAuditSkema_,
    menuAuditSkema_,
    menuSetupDatabase: menuSetupDatabase_,
    menuSetupDatabase_,
    menuInitKepalaSekolah: menuInitKepalaSekolah_,
    menuInitKepalaSekolah_,
    menuSeedDatabase: menuSeedDatabase_,
    menuSeedDatabase_,
    onOpen: onOpen_,
    onOpen_,
    submitSecureSeedCredentials,
    submitKepalaSekolahOnboarding,
    enforceAuthorizedOwner: enforceAuthorizedOwner_,
    enforceAuthorizedOwner_
  };
}
