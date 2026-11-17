/**
 * 原语层：所有加密均基于 WebCrypto（Bun 内置实现，底层 BoringSSL）。
 * - 数据信封：AES-256-GCM，96-bit 随机 IV
 * - 密钥包裹：AES-256-GCM
 * - 盲索引/搜索：HMAC-SHA-256
 * - 哈希：SHA-256
 */
import { base64urlDecode, base64urlEncode, canonicalJSON, toBytes } from './encoding';
import { ENVELOPE_VERSION, type EnvelopeV1, type WrappedDek } from './types';

/** ArrayBuffer 支撑的字节数组（满足 WebCrypto BufferSource 的严格类型） */
export type Bytes = Uint8Array<ArrayBuffer>;

export const AES_GCM = { name: 'AES-GCM', length: 256 } as const;

export async function generateAesKey(extractable = true): Promise<CryptoKey> {
  return crypto.subtle.generateKey(AES_GCM, extractable, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
}

export async function exportRawKey(key: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

export async function importAesKey(raw: Bytes, extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, AES_GCM, extractable, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
}

export async function sha256(input: Bytes | string): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toBytes(input)));
}

/** DEK 指纹：销毁凭证中记录销毁的是哪一把密钥（密钥本体不留存） */
export async function keyFingerprint(rawDek: Bytes): Promise<string> {
  return base64urlEncode(await sha256(rawDek));
}

async function gcmEncrypt(key: CryptoKey, plaintext: Bytes, aad?: Bytes): Promise<{ iv: Bytes; ct: Bytes }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, ...(aad ? { additionalData: aad } : {}) }, key, plaintext),
  );
  return { iv, ct };
}

async function gcmDecrypt(key: CryptoKey, iv: Bytes, ct: Bytes, aad?: Bytes): Promise<Bytes> {
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, ...(aad ? { additionalData: aad } : {}) }, key, ct),
  );
}

/** 包裹 DEK：仅 KMS 调用，输出结构只允许存在于独立密钥库 */
export async function wrapDek(kek: CryptoKey, rawDek: Bytes, kekKid: string): Promise<WrappedDek> {
  const { iv, ct } = await gcmEncrypt(kek, rawDek);
  return { v: 1, kekKid, alg: 'A256GCM', iv: base64urlEncode(iv), ct: base64urlEncode(ct) };
}

export async function unwrapDek(kek: CryptoKey, wrapped: WrappedDek): Promise<Bytes> {
  return gcmDecrypt(kek, base64urlDecode(wrapped.iv), base64urlDecode(wrapped.ct));
}

/**
 * 业务数据信封加密。kid/kv 仅为引用，信封本身不含密钥材料，
 * 因此信封可以安全进入主库、搜索索引、日志和任何备份。
 */
export async function encryptEnvelope(
  dek: CryptoKey,
  keyId: string,
  keyVersion: number,
  plaintext: unknown,
): Promise<EnvelopeV1> {
  const data = toBytes(canonicalJSON(plaintext));
  // AAD 绑定密钥引用：密文被挪到其他用户/版本下会解密失败
  const aad = toBytes(`shred:v1:${keyId}:${keyVersion}`);
  const { iv, ct } = await gcmEncrypt(dek, data, aad);
  return {
    v: ENVELOPE_VERSION,
    kid: keyId,
    kv: keyVersion,
    alg: 'A256GCM',
    iv: base64urlEncode(iv),
    ct: base64urlEncode(ct),
  };
}

export async function decryptEnvelope<T = unknown>(dek: CryptoKey, envelope: EnvelopeV1): Promise<T> {
  const aad = toBytes(`shred:v1:${envelope.kid}:${envelope.kv}`);
  const raw = await gcmDecrypt(dek, base64urlDecode(envelope.iv), base64urlDecode(envelope.ct), aad);
  return JSON.parse(new TextDecoder().decode(raw)) as T;
}

/** 便捷方法：字符串字段信封（如 email 单独加密） */
export async function encryptString(dek: CryptoKey, keyId: string, kv: number, value: string): Promise<EnvelopeV1> {
  return encryptEnvelope(dek, keyId, kv, { t: 's', value });
}

export async function decryptString(dek: CryptoKey, envelope: EnvelopeV1): Promise<string> {
  const obj = await decryptEnvelope<{ t: string; value: string }>(dek, envelope);
  return obj.value;
}

/** HMAC 盲索引：搜索词不可逆，pepper 仅 KMS 持有 */
export async function hmacToken(pepper: Bytes, value: string, context: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', pepper, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, toBytes(`${context}:${value.trim().toLowerCase()}`)));
  return base64urlEncode(mac);
}

export async function generateHmacPepper(): Promise<Bytes> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}
