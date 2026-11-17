import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const appConfig = {
  port: Number(process.env.APP_PORT ?? 3200),
  adminToken: process.env.SHRED_ADMIN_TOKEN ?? 'dev-admin-token-change-me',
  appDb: process.env.SHRED_APP_DB ?? './data/app/app.db',
  auditLog: process.env.SHRED_APP_AUDIT_LOG ?? './data/app/audit.log',
  legacyDb: process.env.SHRED_LEGACY_DB ?? './data/legacy/legacy.db',
  kmsBaseUrl: process.env.KMS_BASE_URL ?? 'http://127.0.0.1:3100',
  kmsToken: process.env.KMS_TOKEN ?? 'dev-admin-token-change-me',
  dekCacheTtlSeconds: Number(process.env.SHRED_DEK_CACHE_TTL_SECONDS ?? 60),
};

export function ensureParentDir(filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
}
