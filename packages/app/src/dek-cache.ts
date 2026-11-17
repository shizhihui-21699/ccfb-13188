/**
 * 明文 DEK 内存缓存：减少每个请求都访问 KMS 的开销。
 * - 短 TTL（默认 60s），过期即丢弃引用等待 GC 回收；
 * - 注销时按 keyId 同步 purge，确保销毁后本进程立刻无法解密；
 * - 多实例部署时销毁通过 KMS 权威状态兜底（其他实例的缓存最长一个 TTL 后失效，
 *   且 KMS unwrap 对已销毁密钥返回 410，不会再续期）。
 */
import { base64urlDecode, importAesKey, type KmsClient } from '@shred/shared';

interface CacheEntry {
  key: CryptoKey;
  version: number;
  fingerprint: string;
  expiresAt: number;
}

export class DekCache {
  private readonly entries = new Map<string, CacheEntry>();

  constructor(
    private readonly kms: KmsClient,
    private readonly ttlSeconds: number,
  ) {}

  async get(keyId: string, version?: number): Promise<{ key: CryptoKey; version: number; fingerprint: string }> {
    const cacheKey = version ? `${keyId}#${version}` : `${keyId}#current`;
    const cached = this.entries.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return { key: cached.key, version: cached.version, fingerprint: cached.fingerprint };
    }
    const unwrapped = await this.kms.unwrap(keyId, version);
    const key = await importAesKey(base64urlDecode(unwrapped.dekB64), false);
    const entry: CacheEntry = {
      key,
      version: unwrapped.version,
      fingerprint: unwrapped.dekFingerprint,
      expiresAt: Date.now() + this.ttlSeconds * 1000,
    };
    this.entries.set(cacheKey, entry);
    return { key, version: entry.version, fingerprint: entry.fingerprint };
  }

  /** 注销路径调用：清空该用户所有版本的缓存条目 */
  purge(keyId: string): void {
    for (const key of this.entries.keys()) {
      if (key === keyId || key.startsWith(`${keyId}#`)) this.entries.delete(key);
    }
  }

  clear(): void {
    this.entries.clear();
  }
}
