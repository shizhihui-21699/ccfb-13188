/**
 * KMS HTTP 服务入口。
 * 鉴权：除 /health 与 /v1/public-key 外全部要求 Bearer 令牌；
 * 生产环境应替换为 mTLS / 服务身份（SPIFFE 等），令牌仅用于演示与内网。
 */
import { Hono } from 'hono';
import { base64urlEncode, ShredError } from '@shred/shared';
import { kmsConfig } from './config';
import { KmsService } from './service';

const app = new Hono();
const service = new KmsService();

app.onError((err, c) => {
  if (err instanceof ShredError) {
    return c.json({ error: { code: err.code, message: err.message } }, err.status as 404);
  }
  console.error('[kms] unhandled error:', err);
  return c.json({ error: { code: 'INTERNAL', message: '内部错误' } }, 500);
});

app.use('/v1/*', async (c, next) => {
  if (c.req.path === '/v1/public-key') return next();
  const header = c.req.header('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token || token !== kmsConfig.adminToken) {
    return c.json({ error: { code: 'UNAUTHORIZED', message: '无效或缺失的 Bearer 令牌' } }, 401);
  }
  return next();
});

app.get('/health', (c) => c.json({ ok: true, service: 'kms' }));

app.get('/v1/public-key', (c) =>
  service.getPublicKeySpki().then((publicKey) => c.json({ alg: 'ES256' as const, publicKey })),
);

// ---------- 密钥生命周期 ----------

app.post('/v1/keys', async (c) => {
  const { keyId, actor } = await c.req.json<{ keyId: string; actor: string }>();
  if (!keyId || !actor) return c.json({ error: { code: 'BAD_REQUEST', message: 'keyId 与 actor 必填' } }, 400);
  const { version } = await service.createKey(keyId, actor);
  return c.json({ keyId, version, state: 'active' }, 201);
});

app.get('/v1/keys/:keyId', (c) => c.json(service.getStatus(c.req.param('keyId'))));

app.post('/v1/keys/:keyId/rotate', async (c) => {
  const { actor } = await c.req.json<{ actor: string }>();
  const result = await service.rotateKey(c.req.param('keyId'), actor ?? 'unknown');
  return c.json({ keyId: c.req.param('keyId'), ...result });
});

app.post('/v1/keys/:keyId/destroy', async (c) => {
  const { reason, requestedBy } = await c.req.json<{ reason: string; requestedBy: string }>();
  if (!reason || !requestedBy) {
    return c.json({ error: { code: 'BAD_REQUEST', message: 'reason 与 requestedBy 必填' } }, 400);
  }
  const cert = await service.destroy(c.req.param('keyId'), reason, requestedBy);
  return c.json(cert, 200);
});

app.get('/v1/keys/:keyId/unwrap', async (c) => {
  const versionParam = c.req.query('version');
  const version = versionParam ? Number(versionParam) : undefined;
  const { rawDek, version: v, fingerprint } = await service.unwrapRaw(c.req.param('keyId'), version);
  return c.json({
    keyId: c.req.param('keyId'),
    version: v,
    dekB64: base64urlEncode(rawDek),
    dekFingerprint: fingerprint,
  });
});

// ---------- KEK 运维 ----------

app.post('/v1/kek/rotate', async (c) => {
  const { actor } = await c.req.json<{ actor: string }>();
  return c.json(await service.rotateRootKek(actor ?? 'unknown'));
});

// ---------- 盲索引 ----------

app.post('/v1/blind-index', async (c) => {
  const { value, context } = await c.req.json<{ value: string; context: string }>();
  if (!value || !context) return c.json({ error: { code: 'BAD_REQUEST', message: 'value 与 context 必填' } }, 400);
  return c.json({ token: await service.blindToken(value, context) });
});

app.post('/v1/blind-index/batch', async (c) => {
  const { email, searchTerms } = await c.req.json<{ email: string; searchTerms: string[] }>();
  return c.json(await service.blindBatch(email, searchTerms ?? []));
});

// ---------- 审计 ----------

app.get('/v1/audit', async (c) => {
  const limit = Math.min(Number(c.req.query('limit') ?? 100), 1000);
  return c.json({ entries: service.listAudit(limit), ...(await service.auditChain()) });
});

app.get('/v1/audit/verify', async (c) => c.json(await service.auditChain()));

await service.init();

const server = Bun.serve({
  port: kmsConfig.port,
  fetch: app.fetch,
});
console.log(`[kms] 密钥托管服务已启动: http://127.0.0.1:${server.port}`);
