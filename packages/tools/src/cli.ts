/**
 * 运维 CLI 统一入口。
 * bun run cli.ts <command> [args]
 */
import { seed } from './seed';
import { migrate, purgeLegacy } from './migrate';
import { createBackup, createKeystoreBackup } from './backup';
import { verify } from './verify';
import { rekeyBackup } from './rekey-backup';
import { redactLogs } from './redact-logs';
import { demo } from './demo';

const [command, ...rest] = process.argv.slice(2);

async function main(): Promise<void> {
  switch (command) {
    case 'seed':
      seed();
      break;
    case 'migrate':
      await migrate({ purgeLegacy: rest.includes('--purge-legacy') });
      break;
    case 'purge-legacy':
      purgeLegacy();
      break;
    case 'backup':
      createBackup(rest[0] ?? 'scheduled');
      if (rest.includes('--with-keystore')) createKeystoreBackup();
      break;
    case 'backup-keystore':
      createKeystoreBackup();
      break;
    case 'verify':
      await verify(rest);
      break;
    case 'rekey-backup':
      await rekeyBackup({ snapshot: optionValue(rest, '--snapshot'), all: rest.includes('--all') });
      break;
    case 'redact-logs':
      redactLogs(optionValue(rest, '--file'));
      break;
    case 'demo':
      await demo();
      break;
    default:
      console.log(`
加密粉碎平台 - 运维工具
用法: bun run cli.ts <command> [args]

  seed                         生成明文遗留库与多年代明文备份
  migrate [--purge-legacy]     明文 → 信封加密迁移（可重入，带账本）
  purge-legacy                 显式清空遗留明文库（secure_delete + VACUUM）
  backup [label] [--with-keystore]  业务快照备份（强制结构安全自检）
  backup-keystore              KMS 密钥库独立隔离备份
  verify <keyId> [--cert f] [--no-backups] [--sample N]
                               销毁后活库+历史备份不可恢复抽查
  rekey-backup (--all | --snapshot <dir>)  修复历史明文备份
  redact-logs [--file f]       日志 PII 兜底扫描脱敏
  demo                         端到端法务合规演示
`);
  }
}

function optionValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}

main().catch((err) => {
  console.error('[cli] 失败:', err);
  process.exit(1);
});
