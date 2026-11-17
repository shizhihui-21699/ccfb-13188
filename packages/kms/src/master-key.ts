/**
 * Master Key 管理（演示环境的本地实现）。
 *
 * 生产环境应把本模块替换为云 KMS / HSM 适配（AWS KMS、GCP KMS、阿里/HSM、HashiCorp Vault Transit）：
 * 代码其余部分只依赖 importMasterKey() 返回的 CryptoKey，替换点仅此一个文件。
 *
 * 本地模式：
 * - 32 字节随机密钥，文件权限 0600
 * - 优先环境变量 SHRED_MASTER_KEY_B64（容器/Secret 挂载场景）
 * - Master Key 只用于 HKDF 派生 Root KEK 与签名密钥包裹密钥，绝不直接触碰用户 DEK
 */
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { base64urlDecode, base64urlEncode } from '@shred/shared';
import { ensureParentDir, kmsConfig } from './config';

export async function loadOrCreateMasterKey(): Promise<CryptoKey> {
  let raw: Uint8Array<ArrayBuffer>;

  if (kmsConfig.masterKeyB64) {
    raw = base64urlDecode(kmsConfig.masterKeyB64);
    if (raw.length !== 32) throw new Error('SHRED_MASTER_KEY_B64 必须是 32 字节密钥的 base64url 编码');
  } else {
    const file = kmsConfig.masterKeyFile;
    if (existsSync(file)) {
      raw = base64urlDecode(readFileSync(file, 'utf8').trim());
    } else {
      raw = new Uint8Array(32);
      crypto.getRandomValues(raw);
      ensureParentDir(file);
      writeFileSync(file, base64urlEncode(raw), { mode: 0o600 });
      chmodSync(file, 0o600);
      console.log(`[kms] 已生成新的 Master Key: ${file} (权限 0600)`);
    }
  }

  return crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey', 'deriveBits']);
}

/** 域分离派生：同一 Master Key 在不同用途下派生出相互独立的子密钥 */
export async function deriveDomainKey(
  masterKey: CryptoKey,
  domain: string,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('shred-platform/v1'),
      info: new TextEncoder().encode(domain),
    },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    false,
    usages,
  );
}
