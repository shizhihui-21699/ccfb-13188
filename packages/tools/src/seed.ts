/**
 * seed：生成迁移前的“遗留系统”——明文 PII 主库，
 * 并同步落一份多年代历史备份（含明文），用于演示迁移与备份修复。
 */
import { randomId } from '@shred/shared';
import { openSqlite, paths, ensureDir, tsCompact } from './common';
import { copyFileSync } from 'node:fs';
import { join } from 'node:path';

const DEMO_USERS = [
  { email: 'alice@example.com', full_name: 'Alice Zhang', phone: '13800000001', city: 'Beijing' },
  { email: 'bob@example.com', full_name: 'Bob Li', phone: '13800000002', city: 'Shanghai' },
  { email: 'carol@example.com', full_name: 'Carol Wang', phone: '13800000003', city: 'Shenzhen' },
  { email: 'dave@example.com', full_name: 'Dave Chen', phone: '13800000004', city: 'Hangzhou' },
  { email: 'erin@example.com', full_name: 'Erin Liu', phone: '13800000005', city: 'Chengdu' },
];

export function seed(): void {
  const db = openSqlite(paths.legacyDb);
  db.exec(`
    CREATE TABLE IF NOT EXISTS legacy_users (
      id TEXT PRIMARY KEY, email TEXT NOT NULL, full_name TEXT NOT NULL,
      phone TEXT NOT NULL, city TEXT, created_at TEXT NOT NULL
    );
  `);
  const count = (db.query('SELECT COUNT(*) AS n FROM legacy_users').get() as { n: number }).n;
  const now = new Date().toISOString();
  const insert = db.prepare(
    'INSERT INTO legacy_users (id, email, full_name, phone, city, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  );
  for (const u of DEMO_USERS) {
    insert.run(randomId('leg'), u.email, u.full_name, u.phone, u.city, now);
  }

  // 模拟“好几年的备份”：同一份明文库在不同年份目录各存一份
  ensureDir(paths.backupDir);
  for (const year of ['2022', '2023', '2024', '2025']) {
    const dir = join(paths.backupDir, `legacy-${year}`);
    ensureDir(dir);
    const target = join(dir, `app-plaintext-${year}.db`);
    copyFileSync(paths.legacyDb, target);
    console.log(`  备份(明文遗留): ${target}`);
  }

  db.close();
  console.log(`[seed] 遗留明文库已生成: ${paths.legacyDb}（既有记录 ${count} 条，新增 ${DEMO_USERS.length} 条）`);
  console.log(`[seed] 快照时间戳: ${tsCompact()}`);
}
