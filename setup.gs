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
 *    initKepalaSekolahUser(), memverifikasi skema sheet user terlebih dahulu, dan
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
function generateUUID() {
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
function hashPasswordWithSalt(passwordPlaintext, salt) {
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
 * @param {string} [spreadsheetId]
 * @return {GoogleAppsScript.Spreadsheet.Spreadsheet}
 */
function getTargetSpreadsheet(spreadsheetId) {
  if (spreadsheetId && typeof spreadsheetId === 'string' && spreadsheetId.trim() !== '') {
    if (typeof SpreadsheetApp !== 'undefined') {
      return SpreadsheetApp.openById(spreadsheetId.trim());
    }
  }

  // Cek konfigurasi ScriptProperties
  if (typeof PropertiesService !== 'undefined') {
    const storedId = PropertiesService.getScriptProperties().getProperty('SPREADSHEET_ID');
    if (storedId && storedId.trim() !== '') {
      if (typeof SpreadsheetApp !== 'undefined') {
        return SpreadsheetApp.openById(storedId.trim());
      }
    }
  }

  // Cek active container-bound spreadsheet
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

  throw new Error(
    'Target Spreadsheet belum ditentukan secara eksplisit.\n' +
    'Solusi:\n' +
    '1. Masukkan spreadsheetId sebagai argumen fungsi: setupSpreadsheetDatabase("YOUR_SPREADSHEET_ID"), ATAU\n' +
    '2. Simpan properti SPREADSHEET_ID melalui PropertiesService.getScriptProperties().setProperty("SPREADSHEET_ID", "ID_ANDA"), ATAU\n' +
    '3. Jalankan script ini sebagai Container-bound Script langsung dari dalam Google Spreadsheet target.'
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
function validateSpreadsheetSchema(target) {
  const ss = (target && typeof target === 'object' && typeof target.getSheetByName === 'function')
    ? target
    : getTargetSpreadsheet(typeof target === 'string' ? target : undefined);

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
function setupSpreadsheetDatabase(target) {
  let lock;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }

  try {
    const ss = (target && typeof target === 'object' && typeof target.getSheetByName === 'function')
      ? target
      : getTargetSpreadsheet(typeof target === 'string' ? target : undefined);

    // Langkah 1: Audit skema awal secara menyeluruh sebelum melakukan mutasi
    const preValidation = validateSpreadsheetSchema(ss);

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
          const defaultSettingsId = generateUUID();
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
function initKepalaSekolahUser(target, credentials) {
  if (!credentials || !credentials.username || !credentials.password || !credentials.nama) {
    throw new Error('Inisialisasi akun kepala sekolah membutuhkan username, password, dan nama yang lengkap.');
  }

  const username = String(credentials.username).trim().toLowerCase();
  const password = String(credentials.password);
  const nama = String(credentials.nama).trim();
  const nip = credentials.nip ? String(credentials.nip).trim() : '';

  if (username.length < 3) {
    throw new Error('Username minimal 3 karakter.');
  }
  if (password.length < 6) {
    throw new Error('Password minimal 6 karakter.');
  }

  let lock;
  if (typeof LockService !== 'undefined') {
    lock = LockService.getScriptLock();
    lock.waitLock(30000);
  }

  try {
    const ss = (target && typeof target === 'object' && typeof target.getSheetByName === 'function')
      ? target
      : getTargetSpreadsheet(typeof target === 'string' ? target : undefined);

    // Validasi skema sheet 'user' secara ketat sebelum membaca/menulis
    const schemaAudit = validateSpreadsheetSchema(ss);
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

    const lastRow = userSheet.getLastRow();
    if (lastRow > 1) {
      const values = userSheet.getRange(2, 1, lastRow - 1, userSheet.getLastColumn()).getValues();
      for (let r = 0; r < values.length; r++) {
        const existingUsername = String(values[r][usernameColIdx]).trim().toLowerCase();
        if (existingUsername === username) {
          throw new Error('Username "' + username + '" sudah terdaftar.');
        }
      }
    }

    // Buat salt acak dan hash password (TIDAK PERNAH MENYIMPAN PASSWORD MENTAH)
    const salt = generateUUID().replace(/-/g, '');
    const passwordHash = hashPasswordWithSalt(password, salt);
    const userId = generateUUID();
    const now = new Date().toISOString();

    // Petakan kolom secara dinamis sesuai SCHEMA_DEFINITIONS.user
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
      message: 'Akun Kepala Sekolah berhasil diinisialisasi secara aman.',
      userId: userId,
      username: username,
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
function runSchemaCheckFromEditor() {
  try {
    const audit = validateSpreadsheetSchema();
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
function runSetupFromEditor() {
  try {
    const result = setupSpreadsheetDatabase();
    Logger.log('=== HASIL SETUP DATABASE SPREADSHEET ===');
    Logger.log(JSON.stringify(result, null, 2));
    return result;
  } catch (err) {
    Logger.log('GAGAL SETUP: ' + err.message);
    throw err;
  }
}

// Ekspor modul untuk lingkungan pengujian otomatis Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    SCHEMA_DEFINITIONS,
    generateUUID,
    hashPasswordWithSalt,
    getTargetSpreadsheet,
    validateSpreadsheetSchema,
    setupSpreadsheetDatabase,
    initKepalaSekolahUser
  };
}
