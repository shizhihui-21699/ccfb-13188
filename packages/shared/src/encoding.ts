/** 编码工具：base64url 与确定性规范 JSON（签名 / 哈希链依赖） */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/**
 * 统一返回 ArrayBuffer 支撑的 Uint8Array：
 * WebCrypto 的 BufferSource 类型拒绝 SharedArrayBuffer 支撑的视图，
 * 这里对非字符串输入复制到新的 ArrayBuffer 以同时满足类型与运行时安全。
 */
export function toBytes(input: string | Uint8Array | ArrayBuffer): Uint8Array<ArrayBuffer> {
  if (typeof input === 'string') return encoder.encode(input);
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new Uint8Array(input);
}

export function toText(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function base64urlEncode(input: Uint8Array | string): string {
  const bytes = toBytes(input);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlDecode(input: string): Uint8Array<ArrayBuffer> {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * 确定性规范 JSON：对象键递归按字典序排序，无多余空白。
 * 用于 ECDSA 签名与审计哈希链，保证任何语言/进程重算结果一致。
 */
export function canonicalJSON(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    out[key] = canonicalize((value as Record<string, unknown>)[key]);
  }
  return out;
}

/** 常量时间比较，防止令牌/摘要侧信道 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function randomId(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `${prefix}_${base64urlEncode(bytes)}`;
}
