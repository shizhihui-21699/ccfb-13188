/**
 * 业务服务 HTTP 入口。
 * /v1/admin/* 为管理端使用，要求 Bearer 令牌；业务 API 同源同令牌仅为演示简化。
 */
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { KmsClient, ShredError } from '@shred/shared';
import { appConfig } from './config';
import { DekCache } from './dek-cache';
import { UserService } from './user-service';
import { logger } from './logger';

const app = new Hono();
const kms = new KmsClient(appConfig.kmsBaseUrl, appConfig.kmsToken);
const dekCache = new DekCache(kms, appConfig.dekCacheTtlSeconds);
const users = new UserService(kms, dekCache);

app.use('*', cors({ origin: '*', allowMethods: ['GET', 'POST', 'OPTIONS'], allowHeaders: ['content-type', 'authorization'] }));

app.onError((err, c) => {
  if (err instanceof ShredError) {
    return c.json({ error: { code: err.code, message: err.message } }, err.status as 404);
  }
  logger.error('app.unhandled', { message: err instanceof Error ? err.message : String(err) });
  return c.json({ error: { code: 'INTERNAL', message: '内部错误' } }, 500);
});

app.use('/v1/admin/*', async (c, next) => {
  const header = c.req.header('authorization') ?? '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token || token !== appConfig.adminToken) {
    return c.json({ error: { code: 'UNAUTHORIZED', message: '无效或缺失的 Bearer 令牌' } }, 401);
  }
  return next();
});

app.get('/health', (c) => c.json({ ok: true, service: 'app' }));

// ---------- 业务 / 管理 API ----------

app.post('/v1/admin/users', async (c) => {
  const body = await c.req.json<{ email: string; profile: { fullName: string; phone: string; city?: string }; actor?: string }>();
  if (!body?.email || !body?.profile?.fullName || !body?.profile?.phone) {
    return c.json({ error: { code: 'BAD_REQUEST', message: 'email、profile.fullName、profile.phone 必填' } }, 400);
  }
  const result = await users.createUser(
    { email: body.email, profile: body.profile },
    body.actor ?? 'admin-api',
  );
  return c.json(result, 201);
});

app.get('/v1/admin/users', (c) => c.json({ users: users.listUsers(Number(c.req.query('limit') ?? 50)) }));

app.get('/v1/admin/users/:id', (c) => users.getUser(c.req.param('id')).then((u) => c.json(u)));

app.get('/v1/admin/lookup/email', async (c) => {
  const email = c.req.query('email');
  if (!email) return c.json({ error: { code: 'BAD_REQUEST', message: 'email 查询参数必填' } }, 400);
  return c.json({ result: await users.findByEmail(email) });
});

app.get('/v1/admin/search', async (c) => {
  const term = c.req.query('q');
  if (!term) return c.json({ error: { code: 'BAD_REQUEST', message: 'q 查询参数必填' } }, 400);
  return c.json({ results: await users.search(term) });
});

/** 加密粉碎注销：返回 KMS 签名的销毁凭证 */
app.post('/v1/admin/users/:id/destroy', async (c) => {
  const body = await c.req.json<{ reason: string; requestedBy?: string }>();
  if (!body?.reason) return c.json({ error: { code: 'BAD_REQUEST', message: 'reason 必填' } }, 400);
  const cert = await users.destroyUser(c.req.param('id'), body.reason, body.requestedBy ?? 'admin-api');
  return c.json(cert);
});

const server = Bun.serve({ port: appConfig.port, fetch: app.fetch });
console.log(`[app] 业务服务已启动: http://127.0.0.1:${server.port}`);
