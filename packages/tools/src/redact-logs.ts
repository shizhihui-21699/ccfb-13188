/**
 * redact-logs：日志残留扫描与脱敏。
 * 正常路径下 SafeLogger 保证 PII 不落日志；本工具面向历史日志/第三方组件日志做兜底：
 * 扫描邮箱/手机号/身份证模式，命中行就地替换并输出统计。
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { paths } from './common';

const PII_PATTERNS: [RegExp, string][] = [
  [/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '<email>'],
  [/(?<!\d)1[3-9]\d{9}(?!\d)/g, '<phone>'],
  [/(?<!\d)\d{17}[\dXx](?!\d)/g, '<id-card>'],
];

export function redactLogs(file = paths.auditLog): { scanned: number; redactedLines: number } {
  if (!existsSync(file)) {
    console.log(`[redact] 日志不存在: ${file}`);
    return { scanned: 0, redactedLines: 0 };
  }
  const lines = readFileSync(file, 'utf8').split('\n');
  let redactedLines = 0;
  const out = lines.map((line) => {
    if (!line) return line;
    let next = line;
    for (const [re, replacement] of PII_PATTERNS) next = next.replace(re, replacement);
    if (next !== line) redactedLines++;
    return next;
  });
  writeFileSync(file, out.join('\n'));
  console.log(`[redact] 扫描 ${lines.length} 行，脱敏 ${redactedLines} 行: ${file}`);
  return { scanned: lines.length, redactedLines };
}
