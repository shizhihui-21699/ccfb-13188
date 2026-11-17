/**
 * 业务主库。
 * 关键不变量（verify 工具会在备份/快照上复查）：
 *  1) 任何表都不存储 DEK 明文或包裹 DEK，只存 kid/kv 引用与密文信封；
 *  2) users 表不含任何明文 PII（email/姓名/手机号均为信封 JSON）；
 *  3) 索引表只存 HMAC 盲 token（不可逆）；
 *  4) legacy_users 是迁移前的明文遗留表，迁移完成后由工具清空/保留只读。
 */
import { Database } from 'bun:sqlite';
import { ensureParentDir, appConfig } from './config';

export class AppDatabase {
  readonly db: Database;

  constructor() {
    ensureParentDir(appConfig.appDb);
    this.db = new Database(appConfig.appDb);
    this.db.exec('PRAGMA journal_mode=WAL;');
    this.db.exec('PRAGMA secure_delete=ON;');
    this.db.exec('PRAGMA foreign_keys=ON;');
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id              TEXT PRIMARY KEY,
        key_id          TEXT NOT NULL,
        key_version     INTEGER NOT NULL,
        email_env       TEXT NOT NULL,
        profile_env     TEXT NOT NULL,
        state           TEXT NOT NULL DEFAULT 'active',
        created_at      TEXT NOT NULL,
        destroyed_at    TEXT,
        certificate_id  TEXT
      );
      CREATE TABLE IF NOT EXISTS blind_index (
        token      TEXT NOT NULL,
        context    TEXT NOT NULL,
        user_id    TEXT NOT NULL REFERENCES users(id),
        state      TEXT NOT NULL DEFAULT 'live',
        PRIMARY KEY (token, context)
      );
      CREATE TABLE IF NOT EXISTS search_index (
        token      TEXT NOT NULL,
        user_id    TEXT NOT NULL REFERENCES users(id),
        state      TEXT NOT NULL DEFAULT 'live',
        PRIMARY KEY (token, user_id)
      );
      CREATE TABLE IF NOT EXISTS migration_ledger (
        user_id       TEXT PRIMARY KEY,
        status        TEXT NOT NULL,
        migrated_at   TEXT NOT NULL,
        envelope_kid  TEXT,
        detail        TEXT
      );
      CREATE TABLE IF NOT EXISTS legacy_users (
        id         TEXT PRIMARY KEY,
        email      TEXT NOT NULL,
        full_name  TEXT NOT NULL,
        phone      TEXT NOT NULL,
        city       TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_users_key ON users(key_id);
      CREATE INDEX IF NOT EXISTS idx_blind_user ON blind_index(user_id);
      CREATE INDEX IF NOT EXISTS idx_search_token ON search_index(token);
    `);
  }

  close(): void {
    this.db.close();
  }
}
