import { beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ShredError, verifyCertificate } from '@shred/shared';

// 每个测试套件使用独立临时目录，避免污染开发数据
const dir = mkdtempSync(join(tmpdir(), 'shred-kms-'));
process.env.SHRED_DATA_DIR = dir;
process.env.SHRED_MASTER_KEY_FILE = join(dir, 'master.key');
process.env.SHRED_KEYSTORE_FILE = join(dir, 'keystore.db');
process.env.SHRED_SIGNING_KEY_FILE = join(dir, 'signing.key');

const { KmsService } = await import('../src/service');

describe('KMS 加密粉碎生命周期', () => {
  const service = new KmsService();

  beforeAll(async () => {
    await service.init();
  });

  test('创建 DEK 并可 unwrap', async () => {
    await service.createKey('dek:user:u1', 'tester');
    const unwrapped = await service.unwrap('dek:user:u1');
    expect(unwrapped.version).toBe(1);
    expect(unwrapped.fingerprint).toBeTruthy();
  });

  test('重复创建冲突', async () => {
    await expect(service.createKey('dek:user:u1', 'tester')).rejects.toMatchObject({ code: 'KEY_ALREADY_EXISTS' });
  });

  test('轮换产生新版本，旧版本仍可解旧密文', async () => {
    const { version } = await service.rotateKey('dek:user:u1', 'tester');
    expect(version).toBe(2);
    const v1 = await service.unwrap('dek:user:u1', 1);
    const v2 = await service.unwrap('dek:user:u1', 2);
    expect(v1.fingerprint).not.toBe(v2.fingerprint);
    const status = service.getStatus('dek:user:u1');
    expect(status.versions).toHaveLength(2);
  });

  test('销毁后 unwrap 被 410 拒绝，且 wrapped_dek 已清空', async () => {
    const cert = await service.destroy('dek:user:u1', '合规注销', 'legal');
    expect(cert.destroyedVersions).toHaveLength(2);
    expect(cert.destroyedVersions.every((v) => v.state === 'destroyed')).toBe(true);

    await expect(service.unwrap('dek:user:u1')).rejects.toMatchObject({ code: 'KEY_DESTROYED', status: 410 });
    // 整体密钥已销毁时，指定版本的请求同样在入口即被拒绝（不区分版本，最小信息暴露）
    await expect(service.unwrap('dek:user:u1', 1)).rejects.toMatchObject({ code: 'KEY_DESTROYED', status: 410 });

    const rows = service.store.listVersions('dek:user:u1');
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.wrapped_dek === null && r.state === 'destroyed')).toBe(true);
  });

  test('销毁凭证 ECDSA 验签通过', async () => {
    const cert = await service.destroy('dek:user:u1', '合规注销', 'legal');
    expect(cert.alreadyDestroyed).toBe(true); // 幂等重放
    expect(await verifyCertificate(cert as unknown as Record<string, unknown>)).toBe(true);
  });

  test('销毁后不允许轮换', async () => {
    await expect(service.rotateKey('dek:user:u1', 'tester')).rejects.toMatchObject({ code: 'KEY_DESTROYED' });
  });

  test('审计哈希链完整且可检测篡改', async () => {
    const ok = await service.auditChain();
    expect(ok.chainValid).toBe(true);
    expect(ok.count).toBeGreaterThanOrEqual(4);

    // 直接篡改库内一条审计记录
    service.store.db.run("UPDATE audit_log SET action = 'forged' WHERE seq = 1");
    const tampered = await service.auditChain();
    expect(tampered.chainValid).toBe(false);
    expect(tampered.brokenAt).toBe(1);
  });

  test('KEK 轮换重包裹存活 DEK，业务密文不受影响', async () => {
    await service.createKey('dek:user:u2', 'tester');
    const before = await service.unwrap('dek:user:u2');
    const result = await service.rotateRootKek('ops');
    expect(result.rewrapped).toBe(1);
    const after = await service.unwrap('dek:user:u2');
    expect(after.fingerprint).toBe(before.fingerprint); // DEK 本体不变
  });

  test('盲索引 pepper 持久化且 token 稳定', async () => {
    const t1 = await service.blindToken('a@b.com', 'email');
    const t2 = await service.blindToken('a@b.com', 'email');
    expect(t1).toBe(t2);
    expect(await service.blindToken('a@b.com', 'search')).not.toBe(t1);
  });

  test('ShredError 结构', () => {
    const e = new ShredError('X', 'msg', 410);
    expect(e.status).toBe(410);
  });

  test('清理临时目录', () => {
    service.store.close();
    rmSync(dir, { recursive: true, force: true });
    expect(true).toBe(true);
  });
});
