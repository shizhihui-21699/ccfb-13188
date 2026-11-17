import { describe, expect, test } from 'bun:test';
import {
  base64urlDecode,
  base64urlEncode,
  canonicalJSON,
  decryptEnvelope,
  decryptString,
  encryptEnvelope,
  encryptString,
  generateAesKey,
  hmacToken,
  importAesKey,
  keyFingerprint,
  sha256,
  timingSafeEqual,
  unwrapDek,
  verifyCertificate,
  wrapDek,
  exportRawKey,
  generateSigningKeyPair,
  signCertificateBody,
  exportSpkiPublic,
} from '@shred/shared';

describe('编码与规范 JSON', () => {
  test('base64url 往返', () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
  });

  test('canonicalJSON 键排序确定', () => {
    const a = canonicalJSON({ z: 1, a: { y: 2, x: 3 }, arr: [1, { b: 2, a: 1 }] });
    const b = canonicalJSON({ arr: [1, { a: 1, b: 2 }], a: { x: 3, y: 2 }, z: 1 });
    expect(a).toBe(b);
  });

  test('常量时间比较', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true);
    expect(timingSafeEqual('abc', 'abd')).toBe(false);
    expect(timingSafeEqual('abc', 'ab')).toBe(false);
  });
});

describe('信封加密 AES-256-GCM', () => {
  test('对象与字符串信封往返', async () => {
    const dek = await generateAesKey();
    const env = await encryptEnvelope(dek, 'dek:user:t1', 1, { name: '张三', tags: ['a', 'b'] });
    expect(env.v).toBe(1);
    expect(env.kid).toBe('dek:user:t1');
    const decrypted = await decryptEnvelope<{ name: string }>(dek, env);
    expect(decrypted.name).toBe('张三');

    const sEnv = await encryptString(dek, 'dek:user:t1', 1, 'secret@example.com');
    expect(await decryptString(dek, sEnv)).toBe('secret@example.com');
  });

  test('AAD 绑定：篡改 kid/kv 后 GCM 认证失败', async () => {
    const dek = await generateAesKey();
    const env = await encryptEnvelope(dek, 'dek:user:t1', 1, { x: 1 });
    const tampered = { ...env, kid: 'dek:user:other' };
    await expect(decryptEnvelope(dek, tampered)).rejects.toThrow();
  });

  test('IV 随机：同一明文两次密文不同', async () => {
    const dek = await generateAesKey();
    const e1 = await encryptEnvelope(dek, 'k', 1, { x: 1 });
    const e2 = await encryptEnvelope(dek, 'k', 1, { x: 1 });
    expect(e1.iv).not.toBe(e2.iv);
    expect(e1.ct).not.toBe(e2.ct);
  });

  test('DEK 指纹稳定且唯一', async () => {
    const k1 = await generateAesKey();
    const k2 = await generateAesKey();
    const f1 = await keyFingerprint(await exportRawKey(k1));
    const f1Again = await keyFingerprint(await exportRawKey(k1));
    const f2 = await keyFingerprint(await exportRawKey(k2));
    expect(f1).toBe(f1Again);
    expect(f1).not.toBe(f2);
  });
});

describe('密钥包裹与盲索引', () => {
  test('wrap/unwrap 往返', async () => {
    const kek = await generateAesKey();
    const rawDek = await exportRawKey(await generateAesKey());
    const wrapped = await wrapDek(kek, rawDek, 'kek-1');
    expect(wrapped.ct).not.toContain(base64urlEncode(rawDek));
    const recovered = await unwrapDek(kek, wrapped);
    expect(recovered).toEqual(rawDek);
  });

  test('HMAC 盲索引确定性 + 不可逆性', async () => {
    const pepper = new Uint8Array(32);
    crypto.getRandomValues(pepper);
    const t1 = await hmacToken(pepper, 'alice@example.com', 'email');
    const t2 = await hmacToken(pepper, 'alice@example.com', 'email');
    const t3 = await hmacToken(pepper, 'alice@example.com', 'search');
    expect(t1).toBe(t2);
    expect(t1).not.toBe(t3);
    // 不同 pepper 产生不同 token
    const pepper2 = new Uint8Array(32);
    crypto.getRandomValues(pepper2);
    expect(await hmacToken(pepper2, 'alice@example.com', 'email')).not.toBe(t1);
  });

  test('sha256 向量', async () => {
    // NIST: sha256("abc") = ba7816bf... 的 base64url 编码
    const digest = base64urlEncode(await sha256('abc'));
    expect(digest).toBe('ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
  });
});

describe('ECDSA 凭证签名', () => {
  test('签名/验签往返，篡改即失败', async () => {
    const pair = await generateSigningKeyPair();
    const body = { certificateId: 'cert_1', keyId: 'dek:user:x', amount: 100 };
    const sig = await signCertificateBody(pair.privateKey, body);
    const cert = { ...body, signature: { alg: 'ES256' as const, value: sig, publicKey: await exportSpkiPublic(pair.publicKey) } };
    expect(await verifyCertificate(cert)).toBe(true);
    expect(await verifyCertificate({ ...cert, amount: 101 })).toBe(false);
  });

  test('导入的 DEK 默认可用且不可导出', async () => {
    const raw = await exportRawKey(await generateAesKey());
    const imported = await importAesKey(raw, false);
    expect(imported.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', imported)).rejects.toThrow();
  });
});
