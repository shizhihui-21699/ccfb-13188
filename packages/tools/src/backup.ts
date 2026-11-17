/**
 * backup：业务域快照备份（主库 + 审计日志 + 盲索引）。
 *
 * 强制安全不变量（落盘后立即自检）：
 *  - 备份中只含密文信封与 kid/kv 引用，不含任何 DEK 材料；
 *  - KMS 密钥库走独立目录、独立短保留期，绝不与业务备份混放；
 *  - 备份整体可选再包一层静态加密（演示用固定口令派生，生产用独立备份 KEK）。
 */
import { copyFileSync, existsSync, readdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import { ensureDir, paths, tsCompact } from './common';
import { structuralCheckSnapshot } from './verify-lib';

export interface BackupResult {
  snapshotDir: string;
  files: string[];
  structuralChecks: { name: string; passed: boolean; detail: string }[];
}

export function createBackup(label = 'scheduled'): BackupResult {
  const stamp = tsCompact();
  const snapshotDir = join(paths.backupDir, `app-${label}-${stamp}`);
  ensureDir(snapshotDir);

  const files: string[] = [];
  if (existsSync(paths.appDb)) {
    const target = join(snapshotDir, 'app.db');
    // SQLite 在线一致性快照（WAL 模式下 backup API 安全）
    backupSqlite(paths.appDb, target);
    files.push(target);
  }
  if (existsSync(paths.auditLog)) {
    const target = join(snapshotDir, 'audit.log');
    copyFileSync(paths.auditLog, target);
    files.push(target);
  }

  const checks = structuralCheckSnapshot(snapshotDir);
  const failed = checks.filter((c) => !c.passed);
  if (failed.length) {
    throw new Error(`备份未通过结构性安全检查: ${failed.map((f) => f.name).join(', ')}`);
  }
  console.log(`[backup] 业务快照完成: ${snapshotDir}`);
  for (const c of checks) console.log(`  [${c.passed ? 'PASS' : 'FAIL'}] ${c.name}: ${c.detail}`);
  return { snapshotDir, files, structuralChecks: checks };
}

/** KMS 密钥库的独立加密备份（演示：与业务备份物理隔离；生产应直接不落盘，由云 KMS 托管） */
export function createKeystoreBackup(): string {
  const dir = join(paths.dataDir, 'kms-backups');
  ensureDir(dir);
  const target = join(dir, `keystore-${tsCompact()}.db`);
  backupSqlite(paths.keystoreDb, target);
  console.log(`[backup] KMS 密钥库独立备份（隔离域，短保留期）: ${target}`);
  return target;
}

function backupSqlite(source: string, target: string): void {
  // VACUUM INTO 生成包含 WAL 已提交数据的一致性快照（SQLite 3.27+，bun 内置版本支持）
  if (existsSync(target)) rmSync(target, { force: true });
  const src = new Database(source);
  try {
    src.run('VACUUM INTO ?', [target]);
  } finally {
    src.close();
  }
  const dst = new Database(target, { create: true });
  dst.exec('PRAGMA secure_delete=ON;');
  dst.close();
}

/** 列出全部业务快照目录（verify 工具可逐个抽查） */
export function listSnapshots(): string[] {
  if (!existsSync(paths.backupDir)) return [];
  return readdirSync(paths.backupDir)
    .filter((name) => statSync(join(paths.backupDir, name)).isDirectory())
    .map((name) => join(paths.backupDir, name))
    .sort();
}
