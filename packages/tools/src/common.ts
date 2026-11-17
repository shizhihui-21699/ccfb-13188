/** 工具包共享辅助：环境路径、HTTP 客户端、SQLite 打开参数 */
import { Database } from 'bun:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { KmsClient } from '@shred/shared';

/** 动态读取环境变量：测试环境会在模块加载后才注入自定义数据目录 */
export const paths = {
  get dataDir(): string {
    return process.env.SHRED_DATA_DIR ?? './data';
  },
  get legacyDb(): string {
    return process.env.SHRED_LEGACY_DB ?? './data/legacy/legacy.db';
  },
  get appDb(): string {
    return process.env.SHRED_APP_DB ?? './data/app/app.db';
  },
  get backupDir(): string {
    return process.env.SHRED_BACKUP_DIR ?? './data/backups';
  },
  get verifyDir(): string {
    return process.env.SHRED_VERIFY_DIR ?? './data/verifications';
  },
  get keystoreDb(): string {
    return process.env.SHRED_KEYSTORE_FILE ?? './data/kms/keystore.db';
  },
  get auditLog(): string {
    return process.env.SHRED_APP_AUDIT_LOG ?? './data/app/audit.log';
  },
};

export function kms(): KmsClient {
  return new KmsClient(process.env.KMS_BASE_URL ?? 'http://127.0.0.1:3100', process.env.KMS_TOKEN ?? 'dev-admin-token-change-me');
}

export function openSqlite(file: string, opts: { create?: boolean } = {}): Database {
  mkdirSync(dirname(file), { recursive: true });
  const db = new Database(file, { create: opts.create ?? true });
  db.exec('PRAGMA secure_delete=ON;');
  return db;
}

export function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true });
}

export function tsCompact(d = new Date()): string {
  return d.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
}
