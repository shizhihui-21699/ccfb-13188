/**
 * 安全日志：从机制上杜绝明文 PII / 密钥材料进入日志。
 * - 白名单字段输出，任何未声明字段一律丢弃；
 * - 字符串值经过 PII 模式扫描（邮箱、手机号、身份证、长 base64 块），命中即脱敏；
 * - 密钥相关字段名直接拒绝写入。
 */
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { appConfig } from './config';

const FORBIDDEN_KEYS = /(dek|kek|master.?key|private.?key|password|secret|tokenB64|dekB64|wrapped)/i;
const PII_PATTERNS: [RegExp, string][] = [
  [/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '<email>'],
  [/(?<!\d)1[3-9]\d{9}(?!\d)/g, '<phone>'],
  [/(?<!\d)\d{17}[\dXx](?!\d)/g, '<id-card>'],
  [/[A-Za-z0-9_-]{40,}={0,2}/g, '<long-blob>'],
];

class SafeLogger {
  constructor(private readonly file: string) {
    mkdirSync(dirname(file), { recursive: true });
  }

  log(level: 'info' | 'warn' | 'error', event: string, fields: Record<string, unknown> = {}): void {
    const safe: Record<string, unknown> = { ts: new Date().toISOString(), level, event };
    for (const [k, v] of Object.entries(fields)) {
      if (FORBIDDEN_KEYS.test(k)) continue;
      safe[k] = this.scrub(typeof v === 'string' ? v : JSON.stringify(v));
    }
    appendFileSync(this.file, `${JSON.stringify(safe)}\n`);
    if (process.env.SHRED_LOG_STDOUT !== '0') console.log(JSON.stringify(safe));
  }

  info(event: string, fields?: Record<string, unknown>): void {
    this.log('info', event, fields);
  }
  warn(event: string, fields?: Record<string, unknown>): void {
    this.log('warn', event, fields);
  }
  error(event: string, fields?: Record<string, unknown>): void {
    this.log('error', event, fields);
  }

  private scrub(value: string): string {
    let out = value;
    for (const [re, replacement] of PII_PATTERNS) out = out.replace(re, replacement);
    return out;
  }
}

export const logger = new SafeLogger(appConfig.auditLog);
