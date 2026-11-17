/**
 * KMS HTTP 客户端：业务服务 / 工具统一通过它访问密钥托管。
 * 设计要点：unwrap 仅返回明文 DEK（仅在调用方内存短暂存在），
 * KMS 从不把包裹后的 DEK 暴露给业务域。
 */
import { ShredError, type DestructionCertificate, type KeyStatus } from './types';

export interface UnwrappedDek {
  keyId: string;
  version: number;
  /** base64url 编码的 32 字节 DEK，调用方用完即弃 */
  dekB64: string;
  dekFingerprint: string;
}

export interface BlindTokens {
  emailToken: string;
  searchTokens: string[];
}

export class KmsClient {
  constructor(
    private readonly baseUrl: string,
    private readonly token: string,
  ) {}

  private async call<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.token}`,
        ...(init.headers ?? {}),
      },
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new ShredError(body?.error?.code ?? 'KMS_ERROR', body?.error?.message ?? `KMS ${path} failed`, res.status);
    }
    return body as T;
  }

  createKey(keyId: string, actor: string) {
    return this.call<{ keyId: string; version: number; state: string }>('/v1/keys', {
      method: 'POST',
      body: JSON.stringify({ keyId, actor }),
    });
  }

  getStatus(keyId: string) {
    return this.call<KeyStatus>(`/v1/keys/${encodeURIComponent(keyId)}`);
  }

  /** 生成新版本 DEK（旧版本保留可解旧密文，注销时全部版本一起销毁） */
  rotateKey(keyId: string, actor: string) {
    return this.call<{ keyId: string; version: number }>(`/v1/keys/${encodeURIComponent(keyId)}/rotate`, {
      method: 'POST',
      body: JSON.stringify({ actor }),
    });
  }

  /** 加密粉碎：销毁该 keyId 全部版本，返回签名凭证；重复调用幂等 */
  destroyKey(keyId: string, reason: string, requestedBy: string) {
    return this.call<DestructionCertificate & { alreadyDestroyed: boolean }>(
      `/v1/keys/${encodeURIComponent(keyId)}/destroy`,
      { method: 'POST', body: JSON.stringify({ reason, requestedBy }) },
    );
  }

  unwrap(keyId: string, version?: number) {
    return this.call<UnwrappedDek>(
      `/v1/keys/${encodeURIComponent(keyId)}/unwrap${version ? `?version=${version}` : ''}`,
    );
  }

  blindIndex(value: string, context: string) {
    return this.call<{ token: string }>('/v1/blind-index', {
      method: 'POST',
      body: JSON.stringify({ value, context }),
    });
  }

  blindIndexBatch(email: string, searchTerms: string[]) {
    return this.call<BlindTokens>('/v1/blind-index/batch', {
      method: 'POST',
      body: JSON.stringify({ email, searchTerms }),
    });
  }

  getPublicKey() {
    return this.call<{ alg: 'ES256'; publicKey: string }>('/v1/public-key');
  }

  listAudit(limit = 100) {
    return this.call<{ entries: unknown[]; chainValid: boolean }>(`/v1/audit?limit=${limit}`);
  }

  verifyChain() {
    return this.call<{ chainValid: boolean; count: number; brokenAt: number | null }>('/v1/audit/verify');
  }
}
