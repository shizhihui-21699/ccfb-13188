/**
 * demo：一键端到端法务合规演示（需要 KMS 与 app 服务已启动）。
 *
 * 时间线：
 *  1) 管理端创建用户（PII 落库前信封加密）
 *  2) 业务备份（模拟注销前的常规快照）
 *  3) 读取验证明文可用、盲索引可搜索
 *  4) 用户发起注销 → KMS 加密粉碎 → 拿到签名销毁凭证并落盘
 *  5) 再次读取/搜索：KMS 410 拒绝、索引 tombstone
 *  6) 对活库 + 全部历史备份抽查不可恢复性
 *  7) 审计哈希链校验 + 凭证离线验签
 */
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  verifyCertificate,
  type DestructionCertificate,
} from '@shred/shared';
import { ensureDir, kms, paths } from './common';
import { createBackup } from './backup';
import { runVerification } from './verify-lib';

const APP_BASE = process.env.APP_BASE_URL ?? 'http://127.0.0.1:3200';
const TOKEN = process.env.SHRED_ADMIN_TOKEN ?? 'dev-admin-token-change-me';

async function appApi(path: string, init: RequestInit = {}): Promise<{ status: number; body: any }> {
  const res = await fetch(`${APP_BASE}${path}`, {
    ...init,
    headers: { 'content-type': 'application/json', authorization: `Bearer ${TOKEN}`, ...(init.headers ?? {}) },
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

export async function demo(): Promise<void> {
  const client = kms();
  const section = (title: string) => console.log(`\n=== ${title} ===`);

  section('1. 创建用户（明文 PII 在写入前完成信封加密）');
  const email = `frank.${Date.now().toString(36)}@example.com`;
  const created = await appApi('/v1/admin/users', {
    method: 'POST',
    body: JSON.stringify({
      email,
      profile: { fullName: 'Frank Zhao', phone: '13900001111', city: 'Wuhan' },
      actor: 'demo-script',
    }),
  });
  if (created.status !== 201) throw new Error(`创建用户失败: ${JSON.stringify(created.body)}`);
  const userId: string = created.body.userId;
  const keyId = `dek:user:${userId}`;
  console.log(`  userId=${userId}\n  keyId=${keyId}`);

  section('2. 注销前业务备份（密文信封进入备份域，无密钥材料）');
  const backup = createBackup('pre-destruction');
  console.log(`  快照: ${backup.snapshotDir}`);

  section('3. 注销前：明文可读、盲索引可搜索');
  const before = await appApi(`/v1/admin/users/${userId}`);
  console.log(`  读取: ${JSON.stringify(before.body)}`);
  const search = await appApi(`/v1/admin/search?q=Frank Zhao`);
  console.log(`  搜索 "Frank Zhao": ${JSON.stringify(search.body)}`);

  section('4. 执行加密粉碎注销');
  const destroyed = await appApi(`/v1/admin/users/${userId}/destroy`, {
    method: 'POST',
    body: JSON.stringify({ reason: '用户行使删除权（法务要求彻底不可恢复）', requestedBy: 'legal-admin' }),
  });
  if (destroyed.status !== 200) throw new Error(`注销失败: ${JSON.stringify(destroyed.body)}`);
  const cert = destroyed.body as DestructionCertificate;
  ensureDir(join(paths.dataDir, 'certificates'));
  const certFile = join(paths.dataDir, 'certificates', `${cert.certificateId}.json`);
  writeFileSync(certFile, JSON.stringify(cert, null, 2));
  console.log(`  销毁凭证已签发: ${cert.certificateId}`);
  console.log(`  销毁版本: ${cert.destroyedVersions.map((v) => `v${v.version}(${v.dekFingerprint.slice(0, 12)}…)`).join(', ')}`);
  console.log(`  凭证文件: ${certFile}`);

  section('5. 注销后：读取与搜索全部失效');
  const after = await appApi(`/v1/admin/users/${userId}`);
  console.log(`  读取返回 ${after.status}: ${after.body.error?.code} - ${after.body.error?.message}`);
  const afterSearch = await appApi(`/v1/admin/search?q=Frank Zhao`);
  console.log(`  搜索返回: ${JSON.stringify(afterSearch.body)}（命中 0 条即索引已 tombstone）`);

  section('6. 活库 + 全部历史备份抽查不可恢复性');
  const report = await runVerification(client, {
    keyId,
    certificateId: cert.certificateId,
    certificatePath: certFile,
    includeBackups: true,
    sampleSize: 10,
  });
  for (const c of report.structuralChecks) console.log(`  [${c.passed ? 'PASS' : 'FAIL'}] ${c.name}: ${c.detail}`);
  for (const s of report.samples) {
    console.log(`  样本 ${s.source}/${s.recordLocator}: ${s.decryptAttempt} / 盲索引=${s.blindIndexStatus} / 通过=${s.passed}`);
  }
  console.log(`  最终结论: ${report.conclusion}`);

  section('7. 审计哈希链与凭证离线验签');
  const chain = await client.verifyChain();
  console.log(`  KMS 审计链: ${JSON.stringify(chain)}`);
  const sigOk = await verifyCertificate(cert as unknown as Record<string, unknown>);
  console.log(`  凭证 ECDSA P-256 验签: ${sigOk ? '通过' : '失败'}`);

  if (report.conclusion !== 'unrecoverable' || !sigOk || !chain.chainValid) {
    throw new Error('端到端演示存在未通过项');
  }
  console.log('\n✅ 全部检查通过：密钥销毁后，活存储与所有备份副本中的该用户数据均已密码学不可恢复。');
}
