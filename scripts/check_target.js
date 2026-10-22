#!/usr/bin/env node
/**
 * ============================================================================
 * SISTEM ABSENSI & PENILAIAN SISWA SD (VERSI 2)
 * File: scripts/check_target.js
 * ============================================================================
 *
 * TUJUAN:
 * Utilitas pembacaan status target clasp aktif secara eksplisit dan aman (READ-ONLY).
 * Memverifikasi apakah .clasp.json mengarah ke lingkungan TEST atau PRODUKSI
 * sebelum developer mengeksekusi perintah clasp.
 *
 * BATASAN KESELAMATAN:
 * 1. 100% BEBAS EFEK SAMPING: Tidak mengubah file, tidak mengubah konfigurasi.
 * 2. TANPA JARINGAN: Tidak memanggil clasp push, clasp deploy, atau API luar.
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const CLASP_ACTIVE_PATH = path.join(ROOT_DIR, '.clasp.json');
const CLASP_TEST_PATH = path.join(ROOT_DIR, '.clasp.test.json');
const CLASP_PROD_PATH = path.join(ROOT_DIR, '.clasp.prod.json');
const CLASP_PROD_TEMPLATE = path.join(ROOT_DIR, '.clasp.prod.json.template');

const TEST_SCRIPT_ID = '17r8cFSyJY0M1EAZwBcsKDhjJq9wRE1hehz3GeU9OWIyYhF7n9GUA5pE3';
const TEST_PARENT_ID = '1tVY7hHpZNTHQ0c_9GEaM2-Gz4fOh8qccsCP0afRLBd8';
const OFFICIAL_PROD_SCRIPT_ID = '1Pr_NMaCNjNaC-GHIrC4mWLg6zHg-4YgvE7W2aG4ntHDmUy-da-pLFQHs';
const OFFICIAL_PROD_PARENT_ID = '1nMOUhC8sIoJBQBWZ_Muhkoo1dQnIhylSnfQGg9qgqxk';
const LEGACY_PROD_SCRIPT_ID = '1ZEJF7hKfdYC150HTNyrqxqY_4OPVGitIpa6GidaDCh_Nj2dfFRVqCjBN';

console.log('====================================================================');
console.log('       VERIFIKASI TARGET CLASP AKTIF (READ-ONLY INSPECTION)         ');
console.log('====================================================================\n');

if (!fs.existsSync(CLASP_ACTIVE_PATH)) {
  console.error('❌ PERINGATAN: File .clasp.json aktif tidak ditemukan pada root workspace.');
  console.error('   Silakan salin salah satu profil konfigurasi:');
  console.error('   - Untuk Test: cp .clasp.test.json .clasp.json');
  console.error('   - Untuk Prod: cp .clasp.prod.json .clasp.json\n');
  process.exit(1);
}

let activeConfig = null;
try {
  activeConfig = JSON.parse(fs.readFileSync(CLASP_ACTIVE_PATH, 'utf8'));
} catch (err) {
  console.error('❌ GAGAL MEMBACA .clasp.json: ' + err.message);
  process.exit(1);
}

const activeScriptId = activeConfig.scriptId || '(kosong)';
const activeParentId = activeConfig.parentId || '(kosong)';

console.log('1. Konfigurasi Aktif (.clasp.json):');
console.log(`   - Script ID : ${activeScriptId}`);
console.log(`   - Parent ID : ${activeParentId}`);
console.log(`   - Root Dir  : ${activeConfig.rootDir || '""'}`);

let detectedEnv = 'TIDAK DIKENAL / KUSTOM';
let envBadge = '⚠️';

if (activeScriptId === TEST_SCRIPT_ID) {
  detectedEnv = 'TEST ENVIRONMENT (Lingkungan Uji Coba)';
  envBadge = '🧪';
} else if (activeScriptId.includes('REPLACE_WITH') || activeScriptId === '') {
  detectedEnv = 'BELUM DIKONFIGURASI (Template / Placeholder)';
  envBadge = '⚠️';
}

let prodConfigStatus = 'Belum Dikonfigurasi (Gunakan template)';
if (fs.existsSync(CLASP_PROD_PATH)) {
  try {
    const prodConfig = JSON.parse(fs.readFileSync(CLASP_PROD_PATH, 'utf8'));
    const prodScript = prodConfig.scriptId || '';
    const prodParent = prodConfig.parentId || '';

    if (prodScript === TEST_SCRIPT_ID || prodParent === TEST_PARENT_ID) {
      prodConfigStatus = '❌ BAHAYA: .clasp.prod.json menggunakan ID Lingkungan TEST!';
    } else if (prodScript === LEGACY_PROD_SCRIPT_ID) {
      prodConfigStatus = `⚠️ PERINGATAN: Menggunakan legacy Script ID (${prodScript.substring(0, 8)}...)! Ganti ke container-bound ID resmi (${OFFICIAL_PROD_SCRIPT_ID.substring(0, 8)}...)`;
    } else if (prodScript.includes('REPLACE_WITH') || prodScript === '') {
      prodConfigStatus = '⚠️ Masih Placeholder (Belum diisi ID resmi)';
    } else {
      const isOfficialMatch = (prodScript === OFFICIAL_PROD_SCRIPT_ID && prodParent === OFFICIAL_PROD_PARENT_ID);
      prodConfigStatus = `Tersedia ✓ (Script: ${prodScript.substring(0, 8)}..., Parent: ${prodParent.substring(0, 8)}...)` +
        (isOfficialMatch ? ' [TARGET RESMI CONTAINER-BOUND COCOK ✓]' : ' [TARGET KUSTOM]');
      if (prodConfig.scriptId === activeScriptId) {
        detectedEnv = 'PRODUCTION ENVIRONMENT (Lingkungan Operasional Resmi)';
        envBadge = '🚀';
      }
    }
  } catch (e) {
    prodConfigStatus = '❌ Error format JSON: ' + e.message;
  }
}

console.log(`\n2. Status Identifikasi Lingkungan:`);
console.log(`   ${envBadge} Target Terdeteksi : ${detectedEnv}`);

if (activeScriptId === TEST_SCRIPT_ID) {
  console.log('   ✓ Aman untuk pengujian internal.');
  console.log('   ⚠️ JANGAN gunakan konfigurasi ini untuk deploy produksi.');
} else if (activeScriptId === OFFICIAL_PROD_SCRIPT_ID) {
  console.log('   ✓ Terverifikasi: Target aktif adalah Apps Script PRODUKSI Container-Bound Resmi.');
  if (activeParentId === OFFICIAL_PROD_PARENT_ID) {
    console.log('   ✓ Terverifikasi: Target parent adalah Spreadsheet PRODUKSI Resmi.');
  }
  console.log('   ✓ Trigger onOpen() akan mengaktifkan menu "⚙️ Sistem Absensi v2" di Google Sheets.');
  console.log('   ⚠️ PERINGATAN OPERASIONAL: Tindakan apa pun akan berdampak pada SISTEM PRODUKSI!');
} else if (activeScriptId === LEGACY_PROD_SCRIPT_ID) {
  console.log('   ⚠️ PERINGATAN: Target aktif adalah project legacy standalone (1ZEJF7h...). Menu tidak akan muncul di Google Sheets!');
} else if (activeScriptId !== '(kosong)' && (activeParentId === TEST_PARENT_ID || activeScriptId === TEST_SCRIPT_ID)) {
  console.log('   ❌ PERINGATAN KRITIS: Terdeteksi campuran ID Test dan non-Test!');
}

console.log('\n3. Ketersediaan Profil Konfigurasi:');
console.log(`   - Profil Test (.clasp.test.json)            : ${fs.existsSync(CLASP_TEST_PATH) ? 'Tersedia ✓' : 'Tidak Ada ❌'}`);
console.log(`   - Template Prod (.clasp.prod.json.template) : ${fs.existsSync(CLASP_PROD_TEMPLATE) ? 'Tersedia ✓' : 'Tidak Ada ❌'}`);
console.log(`   - Profil Prod Lokal (.clasp.prod.json)      : ${prodConfigStatus}`);

console.log('\n4. Panduan Peralihan Target Lingkungan Secara Eksplisit:');
console.log('   Untuk mengaktifkan target TEST:');
console.log('     cp .clasp.test.json .clasp.json');
console.log('   Untuk mengaktifkan target PRODUKSI:');
console.log('     cp .clasp.prod.json .clasp.json');
console.log('\n⚠️ PERHATIAN KEAMANAN:');
console.log('   Selalu jalankan "node scripts/check_target.js" SEBELUM menjalankan clasp push atau deploy!');
console.log('   Jangan pernah menjalankan clasp push saat target belum diverifikasi.\n');
console.log('====================================================================\n');
