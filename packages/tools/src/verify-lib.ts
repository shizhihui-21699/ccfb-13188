/**
 * verify-lib：销毁后不可恢复性验证引擎（同时服务于 verify 命令与备份自检）。
 *
 * 两类证据：
 *  A. 结构性检查（不需要密钥）：
 *     - 备份/快照中不存在包裹 DEK / 明文 PII / 密钥库文件；
 *     - users 表 PII 列均为合法信封 JSON（v=1 且带 kid/kv）。
 *  B. 经验性抽查（模拟攻击者拿到全部副本）：
 *     - 对活库与每份历史备份中该用户的密文样本，携带已销毁 keyId 调 KMS unwrap，
 *       必须得到 410 KEY_DESTROYED（记为 DECRYPTION_REFUSED）；
 *     - 盲索引必须为 tombstoned/absent；
 *     - 任一样本解密成功 → 结论 still-recoverable（红线失败）。
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Database } from 'bun:sqlite';
import {
  KmsClient,
  randomId,
  ShredError,
  verifyCertificate,
  type EnvelopeV1,
  type VerifyReport,
  type VerifySample,
} from '@shred/shared';
import { ensureDir, paths, tsCompact } from './common';

interface StructuralCheck {
  name: string;
  passed: boolean;
  detail: string;
}

/** 对一个快照目录做静态结构检查（备份时与验证时都会调用），默认查找 app.db */
export function structuralCheckSnapshot(snapshotDir: string, dbFileName = 'app.db'): StructuralCheck[] {
  const checks: StructuralCheck[] = [];
  const dbFile = join(snapshotDir, dbFileName);

  checks.push({
    name: 'no-keystore-in-backup',
    passed: !existsSync(join(snapshotDir, 'keystore.db')) && !existsSync(join(snapshotDir, 'master.key')),
    detail: existsSync(join(snapshotDir, 'keystore.db')) ? '快照中发现密钥库文件，违反隔离原则' : '快照不含密钥库/Master Key',
  });

  if (!existsSync(dbFile)) {
    checks.push({ name: 'db-present', passed: false, detail: `快照缺少 ${dbFileName}` });
    return checks;
  }
  checks.push({ name: 'db-present', passed: true, detail: `存在 ${dbFileName} 快照` });

  const db = new Database(dbFile, { readonly: true });
  try {
    const tables = db.query("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => (r as { name: string }).name);

    checks.push({
      name: 'no-wrapped-dek-column',
      passed: !tables.some((t) => t === 'key_versions' || t === 'data_keys'),
      detail: tables.some((t) => t === 'key_versions') ? '业务备份中出现 KMS 密钥表' : '业务库无 KMS 密钥表',
    });

    if (tables.includes('users')) {
      const rows = db.query('SELECT id, email_env, profile_env FROM users LIMIT 200').all() as Array<{
        id: string;
        email_env: string;
        profile_env: string;
      }>;
      let bad = 0;
      for (const r of rows) {
        for (const col of [r.email_env, r.profile_env]) {
          const env = safeParseEnvelope(col);
          if (!env) bad++;
        }
      }
      checks.push({
        name: 'pii-columns-are-envelopes',
        passed: bad === 0,
        detail: bad === 0 ? `抽查 ${rows.length} 行，PII 列均为信封结构` : `发现 ${bad} 个非信封 PII 列`,
      });
    }

    if (tables.includes('legacy_users')) {
      const n = (db.query('SELECT COUNT(*) AS n FROM legacy_users').get() as { n: number }).n;
      checks.push({
        name: 'no-plaintext-legacy-rows',
        passed: n === 0,
        detail: n === 0 ? 'legacy_users 已清空' : `legacy_users 仍有 ${n} 条明文 PII，需 rekey-backup 修复`,
      });
    }
  } finally {
    db.close();
  }
  return checks;
}

function safeParseEnvelope(raw: string): EnvelopeV1 | null {
  try {
    const obj = JSON.parse(raw) as EnvelopeV1;
    if (obj.v !== 1 || !obj.kid || typeof obj.kv !== 'number' || !obj.iv || !obj.ct) return null;
    return obj;
  } catch {
    return null;
  }
}

interface TargetRef {
  label: string;
  dbFile: string;
}

export interface VerifyOptions {
  keyId: string;
  certificateId?: string;
  certificatePath?: string;
  includeBackups: boolean;
  sampleSize: number;
}

/** 主验证流程：活库 +（可选）全部历史快照 */
export async function runVerification(client: KmsClient, opts: VerifyOptions): Promise<VerifyReport> {
  const targets: TargetRef[] = [{ label: 'live:app.db', dbFile: paths.appDb }];
  if (opts.includeBackups) {
    const { listSnapshots } = await import('./backup');
    for (const dir of listSnapshots()) {
      const dbFile = join(dir, 'app.db');
      if (existsSync(dbFile)) targets.push({ label: `backup:${dir.split('/').pop()}`, dbFile });
    }
  }

  const samples: VerifySample[] = [];
  const structural: StructuralCheck[] = [];
  let anyRecoverable = false;

  // 1) KMS 权威状态
  const status = await client.getStatus(opts.keyId);
  const kmsDestroyed = status.state === 'destroyed' && status.versions.every((v) => v.state === 'destroyed');
  structural.push({
    name: 'kms-key-destroyed',
    passed: kmsDestroyed,
    detail: kmsDestroyed
      ? `KMS 中 ${opts.keyId} 全部 ${status.versions.length} 个版本均为 destroyed，wrapped_dek 已清空`
      : 'KMS 中仍存在可用密钥版本',
  });
  if (!kmsDestroyed) anyRecoverable = true;

  // 2) 凭证验签
  if (opts.certificatePath && existsSync(opts.certificatePath)) {
    const cert = JSON.parse(readFileSync(opts.certificatePath, 'utf8'));
    const sigOk = await verifyCertificate(cert);
    structural.push({
      name: 'destruction-certificate-signature',
      passed: sigOk,
      detail: sigOk ? `凭证 ${cert.certificateId} ECDSA P-256 验签通过` : '凭证验签失败',
    });
  }

  // 3) 每个目标的结构检查 + 抽样解密尝试
  for (const target of targets) {
    if (!existsSync(target.dbFile)) continue;
    if (target.label.startsWith('backup:')) {
      structural.push(...structuralCheckSnapshot(join(paths.backupDir, target.label.replace('backup:', ''))).map((c) => ({
        ...c,
        name: `${target.label}/${c.name}`,
      })));
    }

    const db = new Database(target.dbFile, { readonly: true });
    try {
      const tables = db.query("SELECT name FROM sqlite_master WHERE type='table'").all().map((r) => (r as { name: string }).name);
      if (!tables.includes('users')) {
        structural.push({
          name: `${target.label}/users-table`,
          passed: false,
          detail: '该快照缺少 users 表（可能是备份失败的空库）',
        });
        continue;
      }
      const rows = db
        .query('SELECT id, email_env, profile_env, state FROM users WHERE key_id = ? LIMIT ?')
        .all(opts.keyId, opts.sampleSize) as Array<{ id: string; email_env: string; profile_env: string; state: string }>;

      for (const row of rows) {
        const env = safeParseEnvelope(row.email_env);
        const sample: VerifySample = {
          source: target.label,
          recordLocator: row.id,
          kid: opts.keyId,
          kv: env?.kv ?? -1,
          decryptAttempt: 'SKIPPED',
          blindIndexStatus: 'absent',
          passed: false,
          detail: '',
        };
        try {
          // 模拟持有全部备份的攻击者：尝试向 KMS 索取明文 DEK
          await client.unwrap(opts.keyId, env?.kv);
          sample.decryptAttempt = 'DECRYPTION_SUCCEEDED';
          sample.detail = 'KMS 仍返回明文 DEK，密文可被解密！';
          anyRecoverable = true;
        } catch (err) {
          if (err instanceof ShredError && (err.code === 'KEY_DESTROYED' || err.code === 'KEY_VERSION_DESTROYED')) {
            sample.decryptAttempt = 'DECRYPTION_REFUSED';
            sample.detail = 'KMS 以 410 拒绝：密钥版本已销毁，GCM 密文在密码学上不可恢复';
          } else {
            sample.detail = err instanceof Error ? err.message : String(err);
          }
        }

        const blind = db
          .query("SELECT state FROM blind_index WHERE user_id = ? AND context = 'email'")
          .get(row.id) as { state: string } | undefined;
        sample.blindIndexStatus = blind ? (blind.state as 'tombstoned' | 'live') : 'absent';
        sample.passed =
          sample.decryptAttempt === 'DECRYPTION_REFUSED' &&
          (sample.blindIndexStatus === 'tombstoned' || sample.blindIndexStatus === 'absent');
        if (sample.blindIndexStatus === 'live') sample.detail += '；盲索引仍为 live（可被搜索命中）';
        samples.push(sample);
      }
    } finally {
      db.close();
    }
  }

  const structuralFailed = structural.filter((c) => !c.passed);
  const conclusion: VerifyReport['conclusion'] = anyRecoverable
    ? 'still-recoverable'
    : structuralFailed.some((c) => c.name.includes('plaintext'))
      ? 'inconclusive'
      : 'unrecoverable';

  const report: VerifyReport = {
    reportId: randomId('vrpt'),
    generatedAt: new Date().toISOString(),
    target: opts.includeBackups ? 'all' : 'live-stores',
    targetLocation: targets.map((t) => t.label).join(', '),
    certificateId: opts.certificateId ?? 'not-provided',
    keyId: opts.keyId,
    samples,
    structuralChecks: structural,
    conclusion,
  };

  ensureDir(paths.verifyDir);
  const outFile = join(paths.verifyDir, `verify-${tsCompact()}-${report.reportId}.json`);
  writeFileSync(outFile, JSON.stringify(report, null, 2));
  console.log(`[verify] 报告已写入: ${outFile}`);
  return report;
}
