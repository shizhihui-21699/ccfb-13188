/**
 * HTTP 级集成测试：以独立子进程启动 KMS + app 两个真实服务，
 * 覆盖 建用户 → 搜索 → 备份 → 加密粉碎 → 验证 的完整链路。
 */
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, type Subprocess } from 'bun';

const dir = mkdtempSync(join(tmpdir(), 'shred-e2e-'));
// 必须在任何 tools 模块导入前设置环境（common.ts 与各模块在导入时读取）
Object.assign(process.env, {
  SHRED_DATA_DIR: dir,
  SHRED_MASTER_KEY_FILE: join(dir, 'kms', 'master.key'),
  SHRED_KEYSTORE_FILE: join(dir, 'kms', 'keystore.db'),
  SHRED_SIGNING_KEY_FILE: join(dir, 'kms', 'signing.key'),
  SHRED_APP_DB: join(dir, 'app', 'app.db'),
  SHRED_APP_AUDIT_LOG: join(dir, 'app', 'audit.log'),
  SHRED_LEGACY_DB: join(dir, 'legacy', 'legacy.db'),
  SHRED_BACKUP_DIR: join(dir, 'backups'),
  SHRED_VERIFY_DIR: join(dir, 'verifications'),
  KMS_PORT: '4110',
  APP_PORT: '4210',
  KMS_BASE_URL: 'http://127.0.0.1:4110',
  SHRED_LOG_STDOUT: '0',
});

const ROOT = join(import.meta.dir, '..', '..', '..');
const TOKEN = process.env.KMS_TOKEN ?? 'dev-admin-token-change-me';
const APP = 'http://127.0.0.1:4210';
const KMS_URL = 'http://127.0.0.1:4110';

// 环境就绪后再动态导入工具模块
const { createBackup } = await import('../src/backup');
const { runVerification } = await import('../src/verify-lib');
const { KmsClient } = await import('@shred/shared');
const { Database } = await import('bun:sqlite');

let kmsProc: Subprocess;
let appProc: Subprocess;

async function waitReady(url: string, timeoutMs = 8000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      /* 尚未启动 */
    }
    await new Promise((r) => setTimeout(r, 120));
  }
  throw new Error(`服务未就绪: ${url}`);
}

beforeAll(async () => {
  kmsProc = spawn({
    cmd: ['bun', 'run', join(ROOT, 'packages/kms/src/index.ts')],
    cwd: ROOT,
    env: process.env,
    stdout: 'ignore',
    stderr: 'pipe',
  });
  await waitReady(`${KMS_URL}/health`);
  appProc = spawn({
    cmd: ['bun', 'run', join(ROOT, 'packages/app/src/index.ts')],
    cwd: ROOT,
    env: process.env,
    stdout: 'ignore',
    stderr: 'pipe',
  });
  await waitReady(`${APP}/health`);
}, 20000);

afterAll(() => {
  appProc?.kill();
  kmsProc?.kill();
  rmSync(dir, { recursive: true, force: true });
});

async function api(path: string, init: RequestInit = {}): Promise<{ status: number; body: any }> {
  const res = await fetch(`${APP}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}`, ...(init.headers ?? {}) },
  });
  return { status: res.status, body: await res.json() };
}

describe('端到端：加密粉碎不可恢复链路', () => {
  let userId: string;
  let keyId: string;
  let certificateId: string;

  test('健康检查', async () => {
    expect((await (await fetch(`${KMS_URL}/health`)).json()).ok).toBe(true);
    expect((await (await fetch(`${APP}/health`)).json()).ok).toBe(true);
  });

  test('未鉴权请求被拒绝', async () => {
    const res = await fetch(`${APP}/v1/admin/users`);
    expect(res.status).toBe(401);
  });

  test('创建用户后可读取明文并可盲索引搜索', async () => {
    const created = await api('/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify({
        email: 'grace@example.com',
        profile: { fullName: 'Grace He', phone: '13700007777', city: 'Xian' },
      }),
    });
    expect(created.status).toBe(201);
    userId = created.body.userId;
    keyId = `dek:user:${userId}`;

    const got = await api(`/v1/admin/users/${userId}`);
    expect(got.status).toBe(200);
    expect(got.body.email).toBe('grace@example.com');
    expect(got.body.profile.fullName).toBe('Grace He');

    const lookup = await api('/v1/admin/lookup/email?email=grace@example.com');
    expect(lookup.body.result.userId).toBe(userId);

    const search = await api('/v1/admin/search?q=Grace%20He');
    expect(search.body.results.map((r: { userId: string }) => r.userId)).toContain(userId);
  });

  test('主库中不存在任何明文 PII', async () => {
    const db = new Database(process.env.SHRED_APP_DB!, { readonly: true });
    const row = db.query('SELECT email_env, profile_env FROM users WHERE id = ?').get(userId) as {
      email_env: string;
      profile_env: string;
    };
    expect(row.email_env).not.toContain('grace@example.com');
    expect(row.profile_env).not.toContain('Grace He');
    expect(row.email_env).toContain('"kid"');
    db.close();
  });

  test('注销前备份成功且通过结构检查', async () => {
    const result = createBackup('e2e');
    expect(result.structuralChecks.every((c) => c.passed)).toBe(true);
  });

  test('加密粉碎注销返回签名凭证，之后读取/搜索全部失效', async () => {
    const destroyed = await api(`/v1/admin/users/${userId}/destroy`, {
      method: 'POST',
      body: JSON.stringify({ reason: 'GDPR 删除请求', requestedBy: 'legal' }),
    });
    expect(destroyed.status).toBe(200);
    expect(destroyed.body.signature.alg).toBe('ES256');
    certificateId = destroyed.body.certificateId;

    const after = await api(`/v1/admin/users/${userId}`);
    expect(after.status).toBe(410);
    expect(after.body.error.code).toBe('USER_DESTROYED');

    const search = await api('/v1/admin/search?q=Grace%20He');
    expect(search.body.results).toEqual([]);

    const kms = new KmsClient(KMS_URL, TOKEN);
    await expect(kms.unwrap(keyId)).rejects.toMatchObject({ code: 'KEY_DESTROYED' });
  });

  test('重复注销幂等返回可识别错误且不产生新凭证', async () => {
    const again = await api(`/v1/admin/users/${userId}/destroy`, {
      method: 'POST',
      body: JSON.stringify({ reason: '重复请求', requestedBy: 'legal' }),
    });
    expect(again.status).toBe(410);
    expect(again.body.error.code).toBe('USER_ALREADY_DESTROYED');
    expect(again.body.error.message).toContain(certificateId);
  });

  test('活库 + 备份抽查结论为 unrecoverable', async () => {
    const kms = new KmsClient(KMS_URL, TOKEN);
    const report = await runVerification(kms, {
      keyId,
      certificateId,
      includeBackups: true,
      sampleSize: 10,
    });
    expect(report.conclusion).toBe('unrecoverable');
    expect(report.samples.length).toBeGreaterThan(0);
    expect(report.samples.every((s) => s.decryptAttempt === 'DECRYPTION_REFUSED')).toBe(true);
    expect(report.structuralChecks.find((c) => c.name === 'kms-key-destroyed')?.passed).toBe(true);
  });

  test('KMS 审计链有效', async () => {
    const kms = new KmsClient(KMS_URL, TOKEN);
    const chain = await kms.verifyChain();
    expect(chain.chainValid).toBe(true);
  });
});
