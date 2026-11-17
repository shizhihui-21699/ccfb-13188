/** ECDSA P-256 签名 / 验签：用于销毁凭证的可离线审计 */
import { base64urlDecode, base64urlEncode, canonicalJSON } from './encoding';

export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

/** 对不含 signature 字段的凭证主体做规范 JSON 签名 */
export async function signCertificateBody(privateKey: CryptoKey, body: unknown): Promise<string> {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(canonicalJSON(body)),
  );
  return base64urlEncode(new Uint8Array(sig));
}

export async function exportSpkiPublic(publicKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('spki', publicKey);
  return base64urlEncode(new Uint8Array(raw));
}

export async function importSpkiPublic(spkiB64url: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'spki',
    base64urlDecode(spkiB64url),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
}

/**
 * 验签：剥离 signature 字段后重算规范 JSON。
 * 返回 false 而非抛错，便于审计工具批量处理。
 */
export async function verifyCertificate(cert: { signature?: unknown; [k: string]: unknown }): Promise<boolean> {
  try {
    const sig = cert.signature as { alg: string; value: string; publicKey: string };
    if (!sig || sig.alg !== 'ES256') return false;
    const body = { ...cert };
    delete body.signature;
    const key = await importSpkiPublic(sig.publicKey);
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      base64urlDecode(sig.value),
      new TextEncoder().encode(canonicalJSON(body)),
    );
  } catch {
    return false;
  }
}

/** 签名私钥以 JWK 导出（再由 master key 包裹后落盘） */
export async function exportPrivateJwk(key: CryptoKey): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', key);
}

export async function importPrivateJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}
