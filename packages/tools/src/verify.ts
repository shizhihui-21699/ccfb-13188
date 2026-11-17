/**
 * verify 命令入口：对已注销用户做活库 + 全部历史备份的不可恢复性抽查。
 */
import { existsSync, readFileSync } from 'node:fs';
import { kms } from './common';
import { runVerification } from './verify-lib';

export async function verify(args: string[]): Promise<void> {
  const keyId = args[0];
  if (!keyId) {
    console.log('用法: verify <keyId> [--cert <凭证文件>] [--no-backups] [--sample N]');
    process.exit(1);
  }
  const certIdx = args.indexOf('--cert');
  const certificatePath = certIdx >= 0 ? args[certIdx + 1] : undefined;
  const sampleIdx = args.indexOf('--sample');
  const sampleSize = sampleIdx >= 0 ? Number(args[sampleIdx + 1]) : 10;

  const report = await runVerification(kms(), {
    keyId,
    certificatePath,
    certificateId: certificatePath && existsSync(certificatePath)
      ? (JSON.parse(readFileSync(certificatePath, 'utf8')).certificateId as string)
      : undefined,
    includeBackups: !args.includes('--no-backups'),
    sampleSize,
  });

  console.log('\n========== 不可恢复性验证报告 ==========');
  console.log(`报告编号: ${report.reportId}`);
  console.log(`目标密钥: ${report.keyId}`);
  console.log(`覆盖范围: ${report.targetLocation}`);
  console.log('结构性检查:');
  for (const c of report.structuralChecks) {
    console.log(`  [${c.passed ? 'PASS' : 'FAIL'}] ${c.name}: ${c.detail}`);
  }
  console.log(`抽样记录: ${report.samples.length} 条`);
  for (const s of report.samples.slice(0, 20)) {
    console.log(
      `  - ${s.source} / ${s.recordLocator}: 解密尝试=${s.decryptAttempt}, 盲索引=${s.blindIndexStatus}, 通过=${s.passed}`,
    );
    if (s.detail) console.log(`      ${s.detail}`);
  }
  console.log(`最终结论: ${report.conclusion}`);
  if (report.conclusion !== 'unrecoverable') process.exitCode = 2;
}
