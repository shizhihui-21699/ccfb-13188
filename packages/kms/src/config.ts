/** KMS 配置：Bun 自动加载仓库根目录 .env */
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const kmsConfig = {
  port: Number(process.env.KMS_PORT ?? 3100),
  adminToken: process.env.KMS_TOKEN ?? 'dev-admin-token-change-me',
  dataDir: process.env.SHRED_DATA_DIR ?? './data',
  masterKeyFile: process.env.SHRED_MASTER_KEY_FILE ?? './data/kms/master.key',
  masterKeyB64: process.env.SHRED_MASTER_KEY_B64 ?? null,
  keystoreFile: process.env.SHRED_KEYSTORE_FILE ?? './data/kms/keystore.db',
  signingKeyFile: process.env.SHRED_SIGNING_KEY_FILE ?? './data/kms/signing.key',
};

export function ensureParentDir(filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
}
