/**
 * rekey-backup：修复“加密粉碎无法覆盖”的历史明文副本。
 *
 * 背景：迁移开始之前生成的老备份里是明文 PII，DEK 销毁对它们无效。
 * 因此对每份历史快照执行就地加密化改造：
 *  1) 快照中的 legacy_users 明文行 → 按现网 DEK 转成 users 信封（已注销用户直接用 KMS 拒绝结果验证）；
 *  2) 原明文文件先复制到 quarantine/ 隔离目录（不再留在常规备份链），再覆盖原快照；
 *  3) 处理完成后重跑结构检查，确认快照内零明文 PII。
 *
 * 用法：bun run rekey-backup [--snapshot <dir>] [--all]
 */
import { copyFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import {
  base64urlDecode,
  encryptEnvelope,
  encryptString,
  importAesKey,
  KmsClient,
  type EnvelopeV1,
} from '@shred/shared';
import { ensureDir, kms, paths } from './common';
import { structuralCheckSnapshot } from './verify-lib';

interface LegacyRow {
  id: string;
  email: string;
  full_name: string;
  phone: string;
  city: string | null;
  created_at: string;
}

export async function rekeyBackup(opts: { snapshot?: string; all?: boolean }): Promise<void> {
  const client = kms();
  const snapshots = opts.all ? collectLegacySnapshots() : opts.snapshot ? [opts.snapshot] : [];
  if (!snapshots.length) {
    console.log('[rekey-backup] 未指定快照（--snapshot <dir> 或 --all）');
    return;
  }

  for (const snapshot of snapshots) {
    await remediateOne(client, snapshot);
  }
}

function collectLegacySnapshots(): string[] {
  if (!existsSync(paths.backupDir)) return [];
  return readdirSync(paths.backupDir)
    .filter((n) => n.startsWith('legacy-'))
    .map((n) => join(paths.backupDir, n))
    .flatMap((dir) => readdirSync(dir).filter((f) => f.endsWith('.db')).map((f) => join(dir, f)))
    .filter((f) => existsSync(f));
}

async function remediateOne(client: KmsClient, dbFile: string): Promise<void> {
  if (!existsSync(dbFile)) throw new Error(`快照不存在: ${dbFile}`);
  console.log(`[rekey-backup] 处理: ${dbFile}`);

  // 1) 明文原件隔离
  const quarantine = join(paths.backupDir, 'quarantine');
  ensureDir(quarantine);
  const quarantined = join(quarantine, dbFile.split('/').pop()!.replace(/\.db$/, `.quarantine-${Date.now()}.db`));
  copyFileSync(dbFile, quarantined);
  console.log(`  明文原件已隔离: ${quarantined}（按法务保留策略单独管控，建议到期物理销毁）`);

  const db = new Database(dbFile);
  db.exec('PRAGMA secure_delete=ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, key_id TEXT NOT NULL, key_version INTEGER NOT NULL,
      email_env TEXT NOT NULL, profile_env TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL,
      destroyed_at TEXT, certificate_id TEXT
    );
    CREATE TABLE IF NOT EXISTS blind_index (
      token TEXT NOT NULL, context TEXT NOT NULL, user_id TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'live', PRIMARY KEY (token, context)
    );
    CREATE TABLE IF NOT EXISTS search_index (
      token TEXT NOT NULL, user_id TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'live',
      PRIMARY KEY (token, user_id)
    );
  `);

  const rows = db.query('SELECT * FROM legacy_users').all() as LegacyRow[];
  let converted = 0;
  let skippedDestroyed = 0;

  for (const row of rows) {
    const keyId = `dek:user:${row.id}`;
    let state: 'active' | 'destroyed' = 'active';
    let emailEnv: EnvelopeV1 | null = null;
    let profileEnv: EnvelopeV1 | null = null;
    let kv = 0;

    try {
      const unwrapped = await client.unwrap(keyId);
      const dek = await importAesKey(base64urlDecode(unwrapped.dekB64), false);
      kv = unwrapped.version;
      emailEnv = await encryptString(dek, keyId, kv, row.email);
      profileEnv = await encryptEnvelope(dek, keyId, kv, {
        fullName: row.full_name,
        phone: row.phone,
        city: row.city ?? undefined,
      });
    } catch (err) {
      // 用户已注销（KMS 410）：该用户在现网已是粉碎状态。
      // 老备份里的明文必须就地消除——用一次性随机密钥加密后立即丢弃密钥，等效粉碎。
      const code = (err as { code?: string })?.code ?? '';
      const isDestroyed = code === 'KEY_DESTROYED' || code === 'KEY_VERSION_DESTROYED';
      if (!isDestroyed) throw err;
      state = 'destroyed';
      kv = 1;
      const ephemeral = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
      emailEnv = await encryptEnvelope(ephemeral, keyId, kv, { t: 's', value: row.email });
      profileEnv = await encryptEnvelope(ephemeral, keyId, kv, {
        fullName: row.full_name,
        phone: row.phone,
        city: row.city ?? undefined,
      });
      skippedDestroyed++;
    }

    db.run(
      `INSERT OR REPLACE INTO users (id, key_id, key_version, email_env, profile_env, state, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [row.id, keyId, kv, JSON.stringify(emailEnv), JSON.stringify(profileEnv), state, row.created_at],
    );
    converted++;
  }

  // 2) 明文表清零并 VACUUM 回收物理页
  db.exec('DELETE FROM legacy_users; VACUUM;');
  db.close();

  // 3) 重跑结构检查（老备份文件名不是 app.db，显式传入）
  const snapshotDir = dbFile.substring(0, dbFile.lastIndexOf('/'));
  const dbName = dbFile.substring(dbFile.lastIndexOf('/') + 1);
  const checks = structuralCheckSnapshot(snapshotDir, dbName);
  const failed = checks.filter((c) => !c.passed);
  console.log(`  转换 ${converted} 行（其中已注销用户 ${skippedDestroyed} 行以一次性密钥粉碎）`);
  for (const c of checks) console.log(`  [${c.passed ? 'PASS' : 'FAIL'}] ${c.name}: ${c.detail}`);
  if (failed.length) throw new Error(`快照修复后检查未通过: ${dbFile}`);
}
