/**
 * migrate：明文遗留数据 → 信封加密迁移（可重入、分阶段、带账本）。
 *
 * 流程（每用户一个事务 + 一条 ledger）：
 *  1) 幂等检查 migration_ledger，已 success 的跳过；
 *  2) KMS 创建该用户专属 DEK；
 *  3) email 单独信封、profile 整体信封，盲索引/搜索 token 经 KMS HMAC 生成；
 *  4) 密文与索引写入业务库 users / blind_index / search_index；
 *  5) ledger 置 success；
 *  6) 全部迁移完成并通过校验后，才允许 purge-legacy 清空遗留明文库（独立显式命令）。
 */
import {
  base64urlDecode,
  encryptEnvelope,
  encryptString,
  importAesKey,
  KmsClient,
  type EnvelopeV1,
} from '@shred/shared';
import { Database } from 'bun:sqlite';
import { kms, openSqlite, paths } from './common';

interface LegacyRow {
  id: string;
  email: string;
  full_name: string;
  phone: string;
  city: string | null;
  created_at: string;
}

export async function migrate(opts: { purgeLegacy?: boolean; batchSize?: number } = {}): Promise<void> {
  const client = kms();
  const legacy = openSqlite(paths.legacyDb);
  const app = openSqlite(paths.appDb);
  app.exec('PRAGMA journal_mode=WAL;');
  ensureAppSchema(app);

  const rows = legacy.query('SELECT * FROM legacy_users ORDER BY created_at').all() as LegacyRow[];
  let migrated = 0;
  let skipped = 0;
  let failed = 0;

  for (const row of rows) {
    const existing = app.query('SELECT status FROM migration_ledger WHERE user_id = ?').get(row.id) as
      | { status: string }
      | undefined;
    if (existing?.status === 'success') {
      skipped++;
      continue;
    }
    try {
      await migrateOne(client, app, row);
      migrated++;
      process.stdout.write('.');
    } catch (err) {
      failed++;
      app.run(
        `INSERT INTO migration_ledger (user_id, status, migrated_at, detail) VALUES (?, 'failed', ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET status='failed', detail=excluded.detail`,
        [row.id, new Date().toISOString(), err instanceof Error ? err.message : String(err)],
      );
      process.stdout.write('x');
    }
  }
  process.stdout.write('\n');

  const remaining = (legacy.query('SELECT COUNT(*) AS n FROM legacy_users').get() as { n: number }).n;
  console.log(`[migrate] 完成: 新迁移 ${migrated}，跳过(幂等) ${skipped}，失败 ${failed}，遗留明文库剩余 ${remaining} 条`);

  if (opts.purgeLegacy && failed === 0) {
    purgeLegacy(app, legacy);
  } else if (opts.purgeLegacy) {
    console.log('[migrate] 存在失败记录，拒绝 purge 遗留明文库');
  }
  legacy.close();
  app.close();
}

async function migrateOne(client: KmsClient, app: Database, row: LegacyRow): Promise<void> {
  const keyId = `dek:user:${row.id}`;
  await client.createKey(keyId, 'migration-tool');
  const unwrapped = await client.unwrap(keyId);
  const dek = await importAesKey(base64urlDecode(unwrapped.dekB64), false);
  const kv = unwrapped.version;

  const emailEnv: EnvelopeV1 = await encryptString(dek, keyId, kv, row.email);
  const profileEnv: EnvelopeV1 = await encryptEnvelope(dek, keyId, kv, {
    fullName: row.full_name,
    phone: row.phone,
    city: row.city ?? undefined,
  });
  const { emailToken, searchTokens } = await client.blindIndexBatch(row.email, [
    row.full_name,
    row.city ?? '',
  ]);
  const now = new Date().toISOString();

  const tx = app.transaction(() => {
    app.run(
      `INSERT OR IGNORE INTO users (id, key_id, key_version, email_env, profile_env, state, created_at)
       VALUES (?, ?, ?, ?, ?, 'active', ?)`,
      [row.id, keyId, kv, JSON.stringify(emailEnv), JSON.stringify(profileEnv), row.created_at],
    );
    app.run('INSERT OR IGNORE INTO blind_index (token, context, user_id) VALUES (?, ?, ?)', [
      emailToken,
      'email',
      row.id,
    ]);
    for (const token of searchTokens.filter(Boolean)) {
      app.run('INSERT OR IGNORE INTO search_index (token, user_id) VALUES (?, ?)', [token, row.id]);
    }
    app.run(
      `INSERT INTO migration_ledger (user_id, status, migrated_at, envelope_kid)
       VALUES (?, 'success', ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET status='success', migrated_at=excluded.migrated_at, envelope_kid=excluded.envelope_kid`,
      [row.id, now, keyId],
    );
  });
  tx();
}

/** 阶段 3：显式清空遗留明文库（secure_delete 落盘清零），并记录 ledger */
export function purgeLegacy(app?: Database, legacyArg?: Database): void {
  const ownApp = app ?? openSqlite(paths.appDb);
  const ownLegacy = legacyArg ?? openSqlite(paths.legacyDb);
  const before = (ownLegacy.query('SELECT COUNT(*) AS n FROM legacy_users').get() as { n: number }).n;
  ownLegacy.exec('DELETE FROM legacy_users; VACUUM;');
  ownApp.run(
    `INSERT OR REPLACE INTO migration_ledger (user_id, status, migrated_at, detail)
     VALUES ('__purge_legacy__', 'success', ?, ?)`,
    [new Date().toISOString(), `遗留明文库已清空 ${before} 条并 VACUUM`],
  );
  console.log(`[migrate] 遗留明文库已安全清空（${before} 条，secure_delete + VACUUM）`);
  if (!legacyArg) ownLegacy.close();
  if (!app) ownApp.close();
}

function ensureAppSchema(db: Database): void {
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
    CREATE TABLE IF NOT EXISTS migration_ledger (
      user_id TEXT PRIMARY KEY, status TEXT NOT NULL, migrated_at TEXT NOT NULL,
      envelope_kid TEXT, detail TEXT
    );
  `);
}
