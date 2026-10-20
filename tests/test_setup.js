/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: tests/test_setup.js — Pengujian Komprehensif Skema & Setup Spreadsheet (Phase 1.3 Refined)
 * ============================================================================
 *
 * Dokumentasi Batasan Simulasi Mock:
 * 1. Mock appendRow():
 *    Pada Google Apps Script nyata, appendRow(rowContents) adalah operasi atomik pada level baris
 *    yang menyisipkan satu baris utuh ke posisi baris berikutnya.
 *    Dalam mock ini, simulasi kegagalan (failOnAppendRow = true) membatalkan operasi dan melempar
 *    error sebelum data dimasukkan ke array baris. Pengujian ini membuktikan bahwa kegagalan penambahan
 *    record tidak meninggalkan data korup, dan sistem siap melakukan retry yang idempoten.
 * 2. Mock setValues():
 *    Pada Google Apps Script nyata, setValues(values) menulis matriks 2D ke sebuah Range.
 *    Untuk menguji skenario koneksi/kuota terputus saat penulisan range lebar, mock menyediakan
 *    failOnSetValuesAfterCols yang menulis sebagian kolom lalu melempar error. Pengujian membuktikan
 *    bahwa header parsial yang ditinggalkan akibat kegagalan tidak akan ditimpa sembarangan pada retry,
 *    melainkan ditolak secara aman (MISMATCH) untuk meminta pemulihan manual.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

// 1. Memuat setup.gs dengan path relatif terhadap lokasi file tes
const setupPath = path.join(__dirname, '../setup.gs');
const setupCode = fs.readFileSync(setupPath, 'utf8');
const setupModule = require(setupPath);

const {
  SCHEMA_DEFINITIONS,
  generateUUID,
  hashPasswordWithSalt,
  validateSpreadsheetSchema,
  setupSpreadsheetDatabase,
  initKepalaSekolahUser
} = setupModule;

// ============================================================================
// ENGINE MOCK IN-MEMORY GOOGLE APPS SCRIPT / SPREADSHEET (SEMANTIK REALISTIS GAS)
// ============================================================================
class MockRange {
  constructor(sheet, startRow, startCol, numRows, numCols) {
    this.sheet = sheet;
    this.startRow = startRow;
    this.startCol = startCol;
    this.numRows = numRows;
    this.numCols = numCols;
  }

  getValues() {
    const res = [];
    for (let r = 0; r < this.numRows; r++) {
      const rowIdx = this.startRow - 1 + r;
      const row = this.sheet.rows[rowIdx] || [];
      const rowSlice = [];
      for (let c = 0; c < this.numCols; c++) {
        const colIdx = this.startCol - 1 + c;
        rowSlice.push(row[colIdx] !== undefined ? row[colIdx] : '');
      }
      res.push(rowSlice);
    }
    return res;
  }

  getFormulas() {
    const res = [];
    for (let r = 0; r < this.numRows; r++) {
      const rowIdx = this.startRow - 1 + r;
      const row = this.sheet.formulas[rowIdx] || [];
      const rowSlice = [];
      for (let c = 0; c < this.numCols; c++) {
        const colIdx = this.startCol - 1 + c;
        rowSlice.push(row[colIdx] !== undefined ? row[colIdx] : '');
      }
      res.push(rowSlice);
    }
    return res;
  }

  setValues(values) {
    if (this.sheet.failOnSetValues) {
      throw new Error('SIMULATED_API_ERROR: Kuota API terlampaui saat menulis nilai.');
    }
    if (typeof this.sheet.failOnSetValuesAfterCols === 'number') {
      const limit = this.sheet.failOnSetValuesAfterCols;
      for (let r = 0; r < values.length; r++) {
        const targetRow = this.startRow - 1 + r;
        if (!this.sheet.rows[targetRow]) {
          this.sheet.rows[targetRow] = [];
        }
        for (let c = 0; c < Math.min(limit, values[r].length); c++) {
          const targetCol = this.startCol - 1 + c;
          this.sheet.rows[targetRow][targetCol] = values[r][c];
        }
      }
      throw new Error(`SIMULATED_API_ERROR: Koneksi terputus setelah menulis ${limit} kolom.`);
    }
    for (let r = 0; r < values.length; r++) {
      const targetRow = this.startRow - 1 + r;
      if (!this.sheet.rows[targetRow]) {
        this.sheet.rows[targetRow] = [];
      }
      for (let c = 0; c < values[r].length; c++) {
        const targetCol = this.startCol - 1 + c;
        this.sheet.rows[targetRow][targetCol] = values[r][c];
      }
    }
    return this;
  }

  setFormulas(formulas) {
    for (let r = 0; r < formulas.length; r++) {
      const targetRow = this.startRow - 1 + r;
      if (!this.sheet.formulas[targetRow]) {
        this.sheet.formulas[targetRow] = [];
      }
      for (let c = 0; c < formulas[r].length; c++) {
        const targetCol = this.startCol - 1 + c;
        this.sheet.formulas[targetRow][targetCol] = formulas[r][c];
      }
    }
    return this;
  }

  setFontWeight(weight) {
    this.fontWeight = weight;
    return this;
  }
}

class MockSheet {
  constructor(name) {
    this.name = name;
    this.rows = [];
    this.formulas = [];
    this.frozenRows = 0;
    this.failOnSetValues = false;
    this.failOnSetValuesAfterCols = null; // Menulis sebagian kolom lalu gagal
    this.failOnAppendRow = false;
  }

  getName() { return this.name; }

  /**
   * Semantik Google Apps Script:
   * getLastRow() hanya menghitung baris yang memiliki konten (nilai non-kosong ATAU formula).
   * Format sel (warna/border) atau sel kosong bernilai '' tidak dianggap konten (mengembalikan 0).
   */
  getLastRow() {
    const maxRows = Math.max(this.rows.length, this.formulas.length);
    for (let r = maxRows - 1; r >= 0; r--) {
      const rowVals = this.rows[r] || [];
      const rowForms = this.formulas[r] || [];
      const maxCols = Math.max(rowVals.length, rowForms.length);
      for (let c = 0; c < maxCols; c++) {
        const val = rowVals[c];
        const form = rowForms[c];
        const hasVal = (val !== '' && val !== null && val !== undefined);
        const hasForm = (form !== '' && form !== null && form !== undefined);
        if (hasVal || hasForm) {
          return r + 1; // 1-indexed
        }
      }
    }
    return 0;
  }

  /**
   * Semantik Google Apps Script:
   * getLastColumn() hanya menghitung kolom terjauh yang memiliki konten (nilai non-kosong ATAU formula).
   */
  getLastColumn() {
    let maxColIndex = 0;
    const maxRows = Math.max(this.rows.length, this.formulas.length);
    for (let r = 0; r < maxRows; r++) {
      const rowVals = this.rows[r] || [];
      const rowForms = this.formulas[r] || [];
      const maxCols = Math.max(rowVals.length, rowForms.length);
      for (let c = 0; c < maxCols; c++) {
        const val = rowVals[c];
        const form = rowForms[c];
        const hasVal = (val !== '' && val !== null && val !== undefined);
        const hasForm = (form !== '' && form !== null && form !== undefined);
        if (hasVal || hasForm) {
          if (c + 1 > maxColIndex) {
            maxColIndex = c + 1;
          }
        }
      }
    }
    return maxColIndex;
  }

  getRange(startRow, startCol, numRows, numCols) {
    return new MockRange(this, startRow, startCol, numRows, numCols);
  }

  appendRow(rowValues) {
    if (this.failOnAppendRow) {
      throw new Error('SIMULATED_API_ERROR: Kuota API terlampaui saat appendRow.');
    }
    this.rows.push([...rowValues]);
    return this;
  }

  setFrozenRows(n) {
    this.frozenRows = n;
  }
}

class MockSpreadsheet {
  constructor(name = 'Test Database SD', id = 'mock-spreadsheet-123') {
    this.name = name;
    this.id = id;
    this.sheets = new Map();
    this.failOnInsertSheet = null; // Nama sheet tertentu yang disimulasikan gagal dibuat
  }

  getName() { return this.name; }
  getId() { return this.id; }

  getSheetByName(name) {
    return this.sheets.get(name) || null;
  }

  insertSheet(name) {
    if (this.failOnInsertSheet === name) {
      throw new Error(`SIMULATED_API_ERROR: Gagal membuat sheet "${name}".`);
    }
    if (this.sheets.has(name)) {
      throw new Error(`Sheet ${name} sudah ada!`);
    }
    const sheet = new MockSheet(name);
    this.sheets.set(name, sheet);
    return sheet;
  }

  // Snapshot mendalam seluruh sheet, baris, nilai, dan formula
  createSnapshot() {
    const snapshot = {};
    for (const [name, sheet] of this.sheets.entries()) {
      snapshot[name] = {
        rows: sheet.rows.map(r => [...r]),
        formulas: sheet.formulas.map(f => [...f])
      };
    }
    return snapshot;
  }
}

// ============================================================================
// PARSER DOKUMENTASI SKEMA TERVERIFIKASI & KETAT
// ============================================================================

/**
 * Mem-parsing tabel skema sheet dari file markdown .docs/.database.md.
 * Gagal secara eksplisit jika format tidak dikenali, section hilang, atau tabel kosong.
 *
 * @param {string} mdContent
 * @return {Object.<string, string[]>}
 */
function parseSchemaFromDatabaseMd(mdContent) {
  if (!mdContent || typeof mdContent !== 'string') {
    throw new Error('PARSER_ERROR: Konten markdown kosong atau bukan string.');
  }

  const expected11Sheets = [
    'user',
    'tahun_ajaran',
    'wali_kelas',
    'siswa',
    'mata_pelajaran',
    'nilai_mata_pelajaran',
    'nilai_sikap',
    'rekap_kehadiran',
    'pengumuman',
    'pengaturan_rapor',
    'pengaturan'
  ];

  const result = {};

  for (const sheetName of expected11Sheets) {
    // Cari judul section persis: ### 3.x Sheet `sheetName`
    const sectionRegex = new RegExp(`### 3\\.\\d+\\s+Sheet\\s+\`${sheetName}\`([\\s\\S]*?)(?=### 3\\.\\d+|## 4|$)`, 'i');
    const match = mdContent.match(sectionRegex);
    if (!match) {
      throw new Error(`PARSER_ERROR: Section untuk sheet "${sheetName}" tidak ditemukan di database.md.`);
    }

    const sectionBody = match[1];
    const lines = sectionBody.split('\n');
    const headers = [];
    let inTable = false;
    let foundTableFormat = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('| Kolom |') || trimmed.startsWith('|Kolom|')) {
        inTable = true;
        foundTableFormat = true;
        continue;
      }
      if (inTable) {
        if (/^\|[-:| ]+\|$/.test(trimmed)) {
          // Baris pemisah header tabel (|---|---|---|)
          continue;
        }
        if (trimmed.startsWith('|')) {
          const cells = trimmed.split('|').map(c => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
          if (cells.length > 0) {
            const colName = cells[0];
            if (colName && colName !== 'Kolom') {
              headers.push(colName);
            }
          }
        } else {
          // Akhir dari tabel
          if (headers.length > 0) break;
        }
      }
    }

    if (!foundTableFormat) {
      throw new Error(`PARSER_ERROR: Format tabel skema tidak dikenali untuk sheet "${sheetName}".`);
    }
    if (headers.length === 0) {
      throw new Error(`PARSER_ERROR: Tabel skema untuk sheet "${sheetName}" kosong atau tidak memiliki kolom.`);
    }

    result[sheetName] = headers;
  }

  if (Object.keys(result).length !== 11) {
    throw new Error(`PARSER_ERROR: Hasil parsing tidak lengkap. Ditemukan ${Object.keys(result).length} dari 11 sheet.`);
  }

  return result;
}

// ============================================================================
// SUITE PENGUJIAN OTOMATIS
// ============================================================================

console.log('=== MENJALANKAN SUITE PENGUJIAN SETUP.GS (PHASE 1.3 REFINED) ===\n');

// --- UJI 1: Deteksi Pola Destruktif ---
console.log('1. Memverifikasi Tidak Ada Operasi Destruktif di setup.gs');
const destructivePatterns = [
  /\.clear\(\)/,
  /\.clearContents\(\)/,
  /\.deleteRow\(/,
  /\.deleteRows\(/,
  /\.deleteSheet\(/,
  /\.deleteColumns\(/
];
destructivePatterns.forEach(pattern => {
  const match = setupCode.match(pattern);
  assert.strictEqual(match, null, `Ditemukan pola destruktif yang dilarang: ${pattern}`);
});
console.log('   ✓ Lolos: Tidak ada operasi destruktif (.clear, .deleteRow, .deleteSheet, dll).');

// --- UJI 2: Semantik Realistis Mock Google Apps Script (getLastRow & getLastColumn) ---
console.log('\n2. Menguji Kesesuaian Semantik MockSheet (getLastRow & getLastColumn)');
const semanticSheet = new MockSheet('semantic_test');
assert.strictEqual(semanticSheet.getLastRow(), 0, 'Sheet baru harus memiliki lastRow = 0');
assert.strictEqual(semanticSheet.getLastColumn(), 0, 'Sheet baru harus memiliki lastColumn = 0');

// Baris berisi sel string kosong (formatting tanpa konten)
semanticSheet.rows.push(['', '', '']);
semanticSheet.rows.push(['', '', '']);
assert.strictEqual(semanticSheet.getLastRow(), 0, 'Baris bernilai kosong tidak boleh dihitung sebagai konten');
assert.strictEqual(semanticSheet.getLastColumn(), 0, 'Kolom bernilai kosong tidak boleh dihitung sebagai konten');

// Formula tersembunyi yang menghasilkan string kosong di baris ke-2
semanticSheet.formulas[1] = ['=""', '', ''];
assert.strictEqual(semanticSheet.getLastRow(), 2, 'Formula (meskipun bernilai "") harus dihitung sebagai konten');
assert.strictEqual(semanticSheet.getLastColumn(), 1, 'Kolom formula harus dihitung');
console.log('   ✓ Lolos: Semantik getLastRow/getLastColumn sesuai dengan perilaku Google Apps Script nyata.');

// --- UJI 3: Validasi Ketat Parser Dokumentasi Skema & Pengujian Negatif Parser ---
console.log('\n3. Menguji Parser Dokumentasi Skema (Termasuk Pengujian Negatif Parser)');
const dbDocPath = path.join(__dirname, '../.docs/.database.md');
const dbDoc = fs.readFileSync(dbDocPath, 'utf8');

const parsedSchema = parseSchemaFromDatabaseMd(dbDoc);
assert.strictEqual(Object.keys(parsedSchema).length, 11);

for (const sheetName of Object.keys(SCHEMA_DEFINITIONS)) {
  const expected = Array.from(SCHEMA_DEFINITIONS[sheetName]);
  const fromDoc = parsedSchema[sheetName];
  assert(fromDoc, `Tabel skema untuk "${sheetName}" tidak ditemukan di database.md`);
  assert.strictEqual(expected.length, fromDoc.length, `Jumlah kolom sheet "${sheetName}" tidak sama`);
  for (let c = 0; c < expected.length; c++) {
    assert.strictEqual(
      expected[c],
      fromDoc[c],
      `Kolom ke-${c+1} pada sheet "${sheetName}" tidak cocok: diharapkan "${expected[c]}", ditemukan "${fromDoc[c]}"`
    );
  }
  assert.strictEqual(
    expected[expected.length - 1],
    fromDoc[fromDoc.length - 1],
    `Kolom terakhir pada sheet "${sheetName}" harus persis "${expected[expected.length - 1]}"`
  );
}

// Uji negatif parser
assert.throws(() => parseSchemaFromDatabaseMd(''), /PARSER_ERROR/, 'Parser harus menolak konten kosong');
assert.throws(() => parseSchemaFromDatabaseMd('### 3.1 Sheet `user`\nKonten tanpa tabel'), /PARSER_ERROR/, 'Parser harus menolak section tanpa format tabel');
assert.throws(() => parseSchemaFromDatabaseMd('### 3.1 Sheet `user`\n| Kolom | Tipe |\n|---|---|\n'), /PARSER_ERROR/, 'Parser harus menolak tabel tanpa baris kolom');
console.log('   ✓ Lolos: Seluruh 11 skema tabel cocok persis 100%, dan parser terbukti gagal secara eksplisit pada input rusak.');

// --- UJI 4: Penolakan Header Berbeda Spasi (Strict Whitespace Check) ---
console.log('\n4. Menguji Penolakan Header yang Berbeda Spasi (Strict Whitespace Check)');
const whitespaceSS = new MockSpreadsheet('Whitespace Test SS');
const wsUserSheet = whitespaceSS.insertSheet('user');
const corruptedWhitespaceHeaders = [...SCHEMA_DEFINITIONS.user];
corruptedWhitespaceHeaders[0] = 'id ';
corruptedWhitespaceHeaders[1] = ' nama';
wsUserSheet.appendRow(corruptedWhitespaceHeaders);

const auditWs = validateSpreadsheetSchema(whitespaceSS);
assert.strictEqual(auditWs.hasMismatches, true);
assert.strictEqual(auditWs.canProceedSafely, false);
assert(auditWs.errors.some(e => e.includes('spasi (whitespace)')));
assert.throws(() => setupSpreadsheetDatabase(whitespaceSS), /SETUP DIBATALKAN/, 'Setup harus menolak header berspasi');
console.log('   ✓ Lolos: Header berspasi tambahan ("id ", " nama") ditolak secara ketat.');

// --- UJI 5: Sheet Tanpa Header Tetapi Memiliki Data/Formula ---
console.log('\n5. Menguji Deteksi Sheet Tanpa Header Tetapi Memiliki Data/Formula (DATA_WITHOUT_HEADER)');
const noHeaderSS = new MockSpreadsheet('No Header SS');
const noHeaderSheet = noHeaderSS.insertSheet('siswa');
noHeaderSheet.rows[0] = ['', '', '', '', '', ''];
noHeaderSheet.rows[1] = ['s1', 'w1', '001', '101', 1, 'Budi'];

const auditNoHeader = validateSpreadsheetSchema(noHeaderSS);
assert.strictEqual(auditNoHeader.hasMismatches, true);
assert.strictEqual(auditNoHeader.sheets.siswa.status, 'DATA_WITHOUT_HEADER');

const snapNoHeaderBefore = noHeaderSS.createSnapshot();
assert.throws(() => setupSpreadsheetDatabase(noHeaderSS), /SETUP DIBATALKAN/);
const snapNoHeaderAfter = noHeaderSS.createSnapshot();
assert.deepStrictEqual(snapNoHeaderAfter, snapNoHeaderBefore, 'Data siswa baris ke-2 tidak boleh berubah');
console.log('   ✓ Lolos: DATA_WITHOUT_HEADER terdeteksi dan data baris lanjutan dilindungi.');

// --- UJI 6: Formula pada Baris 1 atau Baris Lanjutan (Termasuk ="" ) ---
console.log('\n6. Menguji Sheet dengan Formula (Termasuk Formula Bernilai Kosong ="" )');
const f1SS = new MockSpreadsheet('F1 SS');
const f1Sheet = f1SS.insertSheet('mata_pelajaran');
f1Sheet.rows[0] = ['', '', '', '', '', '', ''];
f1Sheet.formulas[0] = ['=""', '', '', '', '', '', ''];
const auditF1 = validateSpreadsheetSchema(f1SS);
assert.strictEqual(auditF1.hasMismatches, true);
assert.strictEqual(auditF1.sheets.mata_pelajaran.status, 'MISMATCH');
assert.throws(() => setupSpreadsheetDatabase(f1SS), /SETUP DIBATALKAN/);

const f2SS = new MockSpreadsheet('F2 SS');
const f2Sheet = f2SS.insertSheet('rekap_kehadiran');
f2Sheet.rows[0] = ['', '', '', '', '', '', '', '', ''];
f2Sheet.formulas[0] = ['', '', '', '', '', '', '', '', ''];
f2Sheet.rows[1] = ['', '', '', '', '', '', '', '', ''];
f2Sheet.formulas[1] = ['=IF(TRUE, "", "")', '', '', '', '', '', '', '', ''];
const auditF2 = validateSpreadsheetSchema(f2SS);
assert.strictEqual(auditF2.hasMismatches, true);
assert.strictEqual(auditF2.sheets.rekap_kehadiran.status, 'DATA_WITHOUT_HEADER');
assert.throws(() => setupSpreadsheetDatabase(f2SS), /SETUP DIBATALKAN/);
console.log('   ✓ Lolos: Formula pada baris 1 maupun baris lanjutan terdeteksi dan dicegah agar tidak tertimpa.');

// --- UJI 7: Immutability Data & Formula Ketika Setup Ditolak (Snapshot Check) ---
console.log('\n7. Memverifikasi Tidak Ada Data/Formula yang Berubah Ketika Setup Ditolak (Snapshot Check)');
const protectSS = new MockSpreadsheet('Protect SS');
const pSiswa = protectSS.insertSheet('siswa');
pSiswa.appendRow([...SCHEMA_DEFINITIONS.siswa]);
pSiswa.appendRow(['s-1', 'w-1', '001', '101', 1, 'Budi Santoso', 'L', 'Jakarta', '2015-01-01', 'Ayah', '08123', true, 'now', 'now']);
pSiswa.formulas[1] = ['', '', '', '', '', '', '', '', '', '', '', '', '=NOW()', '=NOW()'];

const pUser = protectSS.insertSheet('user');
pUser.appendRow(['id', 'nama', 'username', 'kolom_salah']);
pUser.appendRow(['u-1', 'Pak Guru', 'guru1', 'data_penting']);

const snapshotBefore = protectSS.createSnapshot();
assert.throws(() => setupSpreadsheetDatabase(protectSS), /SETUP DIBATALKAN/);
const snapshotAfter = protectSS.createSnapshot();
assert.deepStrictEqual(snapshotAfter, snapshotBefore, 'Data dan formula pada seluruh sheet terbukti tidak berubah saat setup ditolak');
console.log('   ✓ Lolos: Kondisi data dan formula pada seluruh sheet terbukti tidak berubah saat setup ditolak.');

// --- UJI 8: Kegagalan insertSheet() SETELAH Sebagian Sheet Terbuat Beserta Snapshot Lengkap & Retry ---
console.log('\n8. Menguji Kegagalan insertSheet() SETELAH Sebagian Sheet Terbuat (Snapshot Lengkap Seluruh Isi & Formula)');
const failInsertSS = new MockSpreadsheet('Fail Insert SS');

// Pra-isi sheet 'user' dan sheet 'siswa' dengan header, multi-baris data, dan formula lengkap
const preUserSheet = failInsertSS.insertSheet('user');
preUserSheet.appendRow([...SCHEMA_DEFINITIONS.user]);
preUserSheet.appendRow(['u-pre-1', 'Guru Satu', '19800101', 'gurusatu', 'hash1', 'salt1', 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01']);
preUserSheet.appendRow(['u-pre-2', 'Guru Dua', '19800202', 'gurudua', 'hash2', 'salt2', 'wali_kelas', '', '', true, '2026-01-01', '2026-01-01']);
preUserSheet.formulas[1] = ['', '', '', '', '', '', '', '', '', '', '=TODAY()', '=TODAY()'];
preUserSheet.formulas[2] = ['', '', '', '', '', '', '', '', '', '', '=TODAY()', '=TODAY()'];

const preSiswaSheet = failInsertSS.insertSheet('siswa');
preSiswaSheet.appendRow([...SCHEMA_DEFINITIONS.siswa]);
preSiswaSheet.appendRow(['s-pre-1', 'w-1', '001', '101', 1, 'Ahmad', 'L', 'Jakarta', '2015-05-05', 'Wali Ahmad', '08111', true, 'now', 'now']);
preSiswaSheet.formulas[1] = ['', '', '', '', '', '', '', '', '', '', '', '', '=NOW()', '=NOW()'];

// SIMPAN SNAPSHOT LENGKAP PRA-EKSISTING SEBELUM SETUP DIJALANKAN
const snapshotPreExistingBefore = failInsertSS.createSnapshot();

// Simulasikan kegagalan di sheet ke-5 ('mata_pelajaran') SETELAH 4 sheet pertama berhasil diproses
failInsertSS.failOnInsertSheet = 'mata_pelajaran';

assert.throws(() => setupSpreadsheetDatabase(failInsertSS), /SIMULATED_API_ERROR/);

// Snapshot kondisi setelah kegagalan
const snapshotAfterFailure = failInsertSS.createSnapshot();

// Verifikasi kondisi pasca-kegagalan:
assert(snapshotAfterFailure.user, 'Sheet user harus ada');
assert(snapshotAfterFailure.tahun_ajaran, 'Sheet tahun_ajaran harus sudah terbuat sebelum crash');
assert(snapshotAfterFailure.wali_kelas, 'Sheet wali_kelas harus sudah terbuat sebelum crash');
assert(snapshotAfterFailure.siswa, 'Sheet siswa harus ada');
assert.strictEqual(failInsertSS.getSheetByName('mata_pelajaran'), null, 'Sheet mata_pelajaran belum terbuat');

// ASSERTION MENDALAM: Seluruh isi data dan formula sheet pra-eksisting 'user' dan 'siswa'
// HARUS PERSIS 100% SAMA DENGAN SNAPSHOT SEBELUM KEGAGALAN
assert.deepStrictEqual(
  snapshotAfterFailure.user,
  snapshotPreExistingBefore.user,
  'Seluruh data dan formula sheet user pra-eksisting harus persis sama setelah kegagalan'
);
assert.deepStrictEqual(
  snapshotAfterFailure.siswa,
  snapshotPreExistingBefore.siswa,
  'Seluruh data dan formula sheet siswa pra-eksisting harus persis sama setelah kegagalan'
);

// Pulihkan API dan jalankan ulang setup (Retry)
failInsertSS.failOnInsertSheet = null;
const retryInsertRes = setupSpreadsheetDatabase(failInsertSS);
assert.strictEqual(retryInsertRes.success, true);
assert.strictEqual(retryInsertRes.createdSheets.length, 7, 'Harus membuat 7 sheet sisanya');
assert.strictEqual(retryInsertRes.retainedExistingSheets.length, 4, 'Harus mempertahankan 4 sheet awal');
assert.strictEqual(failInsertSS.sheets.size, 11, 'Seluruh 11 sheet harus ada setelah retry');

// ASSERTION MENDALAM: Setelah retry selesai, seluruh data dan formula sheet pra-eksisting
// TETAP PERSIS 100% SAMA DENGAN SNAPSHOT AWAL
const snapshotAfterRetry = failInsertSS.createSnapshot();
assert.deepStrictEqual(
  snapshotAfterRetry.user,
  snapshotPreExistingBefore.user,
  'Seluruh data dan formula sheet user pra-eksisting harus tetap persis sama setelah retry selesai'
);
assert.deepStrictEqual(
  snapshotAfterRetry.siswa,
  snapshotPreExistingBefore.siswa,
  'Seluruh data dan formula sheet siswa pra-eksisting harus tetap persis sama setelah retry selesai'
);
console.log('   ✓ Lolos: Kegagalan insertSheet terbukti tidak mengubah data/formula pra-eksisting (terverifikasi melalui deep snapshot).');

// --- UJI 9: Simulasi Kegagalan setValues() (Gagal Total vs Gagal Menulis Sebagian Kolom) ---
console.log('\n9. Menguji Kegagalan setValues(): Gagal Bersih vs Header Parsial Rusak');

// A. Gagal bersih saat setValues (sheet terbuat tapi kosong)
const failSetValSS = new MockSpreadsheet('Fail SetVal Clean SS');
const origInsertClean = failSetValSS.insertSheet.bind(failSetValSS);
failSetValSS.insertSheet = function(name) {
  const s = origInsertClean(name);
  if (name === 'user') {
    s.failOnSetValues = true;
  }
  return s;
};

assert.throws(() => setupSpreadsheetDatabase(failSetValSS), /SIMULATED_API_ERROR/);
const userSheetCreated = failSetValSS.getSheetByName('user');
assert(userSheetCreated, 'Sheet user sudah terbuat');
assert.strictEqual(userSheetCreated.getLastRow(), 0, 'Header belum tertulis karena gagal setValues');

userSheetCreated.failOnSetValues = false;
failSetValSS.insertSheet = origInsertClean;
const retrySetValRes = setupSpreadsheetDatabase(failSetValSS);
assert.strictEqual(retrySetValRes.success, true);
assert(retrySetValRes.initializedEmptySheets.includes('user'));
assert.strictEqual(userSheetCreated.rows[0][0], 'id');

// B. Gagal setelah menulis SEBAGIAN kolom (failOnSetValuesAfterCols = 3 dari 7 kolom mata_pelajaran)
const failPartialColSS = new MockSpreadsheet('Fail Partial Col SS');
const origInsertPartial = failPartialColSS.insertSheet.bind(failPartialColSS);
failPartialColSS.insertSheet = function(name) {
  const s = origInsertPartial(name);
  if (name === 'mata_pelajaran') {
    s.failOnSetValuesAfterCols = 3; // Putus setelah menulis 3 kolom
  }
  return s;
};

assert.throws(() => setupSpreadsheetDatabase(failPartialColSS), /SIMULATED_API_ERROR/);
const brokenMapelSheet = failPartialColSS.getSheetByName('mata_pelajaran');
assert.strictEqual(brokenMapelSheet.rows[0].length, 3, 'Hanya 3 kolom yang tertulis');

const snapBrokenBefore = failPartialColSS.createSnapshot();
failPartialColSS.insertSheet = origInsertPartial;
brokenMapelSheet.failOnSetValuesAfterCols = null;

assert.throws(() => setupSpreadsheetDatabase(failPartialColSS), /SETUP DIBATALKAN/, 'Setup harus menolak header parsial');
const snapBrokenAfter = failPartialColSS.createSnapshot();
assert.deepStrictEqual(snapBrokenAfter, snapBrokenBefore, 'Kondisi header parsial tidak boleh ditimpa sembarangan');
console.log('   ✓ Lolos: Kegagalan setValues gagal bersih dapat di-retry; kegagalan parsial kolom ditolak secara aman.');

// --- UJI 10: Kegagalan appendRow() pada Sheet 'pengaturan' Beserta Verifikasi Snapshot Lengkap ---
console.log('\n10. Menguji Kegagalan appendRow() pada Sheet "pengaturan" Beserta Snapshot Lengkap Seluruh Sheet & Retry');
const failAppendSS = new MockSpreadsheet('Fail Append SS');
const origInsertForAppend = failAppendSS.insertSheet.bind(failAppendSS);
failAppendSS.insertSheet = function(name) {
  const s = origInsertForAppend(name);
  if (name === 'pengaturan') {
    s.failOnAppendRow = true;
  }
  return s;
};

assert.throws(() => setupSpreadsheetDatabase(failAppendSS), /SIMULATED_API_ERROR/);

// Ambil snapshot kondisi pasca-kegagalan appendRow
const snapFailAppend = failAppendSS.createSnapshot();

// VERIFIKASI MENDALAM ATAS SNAPSHOT PASCA-KEGAGALAN:
// Seluruh 11 sheet harus sudah ada, dan baris 1 pada setiap sheet harus persis sesuai SCHEMA_DEFINITIONS
assert.strictEqual(Object.keys(snapFailAppend).length, 11, 'Seluruh 11 sheet harus terbuat sebelum crash appendRow');
for (const sheetName of Object.keys(SCHEMA_DEFINITIONS)) {
  const sheetSnap = snapFailAppend[sheetName];
  assert(sheetSnap, `Sheet "${sheetName}" harus ada di snapshot pasca-kegagalan`);
  assert.strictEqual(sheetSnap.rows.length, 1, `Sheet "${sheetName}" harus tepat memiliki 1 baris (header row)`);
  assert.deepStrictEqual(
    sheetSnap.rows[0],
    Array.from(SCHEMA_DEFINITIONS[sheetName]),
    `Header sheet "${sheetName}" harus persis sesuai skema`
  );
  assert.strictEqual(sheetSnap.formulas.length, 0, `Tidak boleh ada formula pada sheet baru "${sheetName}"`);
}

// Pulihkan API dan jalankan ulang setup (Retry Pertama)
const pengaturanSheet = failAppendSS.getSheetByName('pengaturan');
pengaturanSheet.failOnAppendRow = false;
failAppendSS.insertSheet = origInsertForAppend;

const retryAppendRes = setupSpreadsheetDatabase(failAppendSS);
assert.strictEqual(retryAppendRes.success, true);
assert.strictEqual(retryAppendRes.pengaturanInitialized, true, 'Pengaturan harus berhasil diinisialisasi pada retry');
assert.strictEqual(pengaturanSheet.rows.length, 2, 'Sheet pengaturan sekarang tepat 2 baris (1 header + 1 record)');
assert.strictEqual(pengaturanSheet.rows[1][2], '', 'nama_sekolah kosong sesuai dokumentasi');

// Ambil snapshot setelah retry pertama berhasil
const snapAfterRetry1 = failAppendSS.createSnapshot();

// Retry kedua: Memastikan tidak ada duplikasi record dan seluruh data/formula tetap idempoten
const secondRetryRes = setupSpreadsheetDatabase(failAppendSS);
assert.strictEqual(secondRetryRes.success, true);
assert.strictEqual(secondRetryRes.pengaturanInitialized, false, 'Pengaturan tidak boleh diinisialisasi ulang');

// Ambil snapshot setelah retry kedua
const snapAfterRetry2 = failAppendSS.createSnapshot();

// ASSERTION MENDALAM: Kondisi seluruh 11 sheet pada retry kedua HARUS 100% IDENTIK dengan retry pertama
assert.deepStrictEqual(
  snapAfterRetry2,
  snapAfterRetry1,
  'Kondisi seluruh spreadsheet pada retry kedua harus persis identik dengan retry pertama (tidak ada duplikasi/perubahan)'
);
console.log('   ✓ Lolos: Kegagalan appendRow pengaturan teruji dengan snapshot komprehensif; retry berhasil tanpa duplikasi.');

// --- UJI 11: Inisialisasi Akun Kepala Sekolah, Kegagalan appendRow() Akun, Hashing Salt, & Duplikasi ---
console.log('\n11. Menguji initKepalaSekolahUser(), Kegagalan appendRow() User Beserta Snapshot Lengkap & Duplikasi');
const userSS = new MockSpreadsheet('User SS');
setupSpreadsheetDatabase(userSS);
const userSheet = userSS.getSheetByName('user');

// Ambil snapshot sheet user SEBELUM inisialisasi akun
const snapUserBefore = userSS.createSnapshot();
assert.strictEqual(snapUserBefore.user.rows.length, 1, 'Sheet user awalnya tepat 1 baris (header)');

// A. Simulasi kegagalan appendRow saat inisialisasi akun user
userSheet.failOnAppendRow = true;
assert.throws(
  () => initKepalaSekolahUser(userSS, { username: 'kepsek_teladan', password: 'PasswordKuat123!', nama: 'H. Sudirman, M.Pd.' }),
  /SIMULATED_API_ERROR/
);

// Ambil snapshot setelah kegagalan
const snapUserAfterFailure = userSS.createSnapshot();
// ASSERTION MENDALAM: Kegagalan appendRow TIDAK BOLEH mengubah isi sheet user (harus persis sama dengan snapUserBefore)
assert.deepStrictEqual(
  snapUserAfterFailure,
  snapUserBefore,
  'Kondisi sheet user setelah appendRow gagal harus persis sama dengan kondisi sebelum dipanggil'
);

// B. Pulihkan API dan jalankan retry inisialisasi user
userSheet.failOnAppendRow = false;
const adminRes = initKepalaSekolahUser(userSS, {
  username: 'kepsek_teladan',
  password: 'PasswordKuat123!',
  nama: 'H. Sudirman, M.Pd.',
  nip: '197501012000031001'
});
assert.strictEqual(adminRes.success, true);
assert.strictEqual(adminRes.username, 'kepsek_teladan');

// Ambil snapshot setelah retry berhasil
const snapUserAfterSuccess = userSS.createSnapshot();
assert.strictEqual(snapUserAfterSuccess.user.rows.length, 2, 'Sheet user sekarang tepat 2 baris (1 header + 1 akun admin)');

const userRow = snapUserAfterSuccess.user.rows[1];
assert.strictEqual(userRow[1], 'H. Sudirman, M.Pd.');
assert.strictEqual(userRow[3], 'kepsek_teladan');
assert.strictEqual(userRow[4].length, 64, 'Password hash SHA-256');
assert.notStrictEqual(userRow[4], 'PasswordKuat123!', 'Password mentah TIDAK BOLEH tersimpan');
assert.strictEqual(userRow[6], 'kepala_sekolah');

// C. Percobaan registrasi dengan username duplikat (case-insensitive)
assert.throws(
  () => initKepalaSekolahUser(userSS, { username: 'KEPSEK_TELADAN', password: 'PasswordLain123!', nama: 'Lain' }),
  /sudah terdaftar/
);

// Ambil snapshot setelah upaya duplikat ditolak
const snapUserAfterDuplicateAttempt = userSS.createSnapshot();
// ASSERTION MENDALAM: Percobaan pendaftaran duplikat TIDAK BOLEH mengubah data yang ada
assert.deepStrictEqual(
  snapUserAfterDuplicateAttempt,
  snapUserAfterSuccess,
  'Percobaan registrasi username duplikat terbukti tidak mengubah data yang sudah ada'
);
console.log('   ✓ Lolos: Inisialisasi akun user aman, kegagalan appendRow dibuktikan via snapshot, dan duplikasi tidak mengubah data.');

console.log('\n======================================================');
console.log('SELURUH 11 SUITE PENGUJIAN OTOMATIS BERHASIL (100% PASS)');
console.log('======================================================\n');
