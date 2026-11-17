/**
 * 全局共享类型定义。
 * 注意：信封 Envelope 是唯一允许出现在业务库 / 搜索索引 / 日志 / 备份中的密钥相关结构，
 * 其内部不含任何可解密材料（DEK 明文与密文都不在其中）。
 */

export const ENVELOPE_VERSION = 1 as const;

/** 业务数据信封：AES-256-GCM，加密时的 DEK 以 kid/kv 间接引用，密钥本体只在 KMS */
export interface EnvelopeV1 {
  v: 1;
  /** DEK 标识（对应用户主密钥 keyId） */
  kid: string;
  /** DEK 版本（支持密钥轮换，历史版本各自独立可销毁） */
  kv: number;
  alg: 'A256GCM';
  /** base64url，12 字节 IV */
  iv: string;
  /** base64url，密文 + 16 字节 GCM 认证标签 */
  ct: string;
}

/** KMS 内部使用的 DEK 包裹结构（仅存于独立密钥库，永不进入业务域与备份域） */
export interface WrappedDek {
  v: 1;
  kekKid: string;
  alg: 'A256GCM';
  iv: string;
  ct: string;
}

export type KeyState = 'active' | 'destroyed';

export interface KeyStatus {
  keyId: string;
  state: KeyState;
  currentVersion: number;
  versions: { version: number; state: KeyState; createdAt: string; destroyedAt: string | null }[];
}

/** 销毁凭证：由 KMS 用 ECDSA P-256 签名，可离线验签 */
export interface DestructionCertificate {
  certificateId: string;
  keyId: string;
  /** 被销毁的每个 DEK 版本及其销毁前指纹（SHA-256，证明销毁的是哪一把密钥） */
  destroyedVersions: {
    version: number;
    dekFingerprint: string;
    algorithm: 'AES-256-GCM';
    state: 'destroyed';
    destroyedAt: string;
  }[];
  reason: string;
  requestedBy: string;
  /** 销毁时密钥库最后一条审计记录的序号，支撑审计链连续性校验 */
  auditSequence: number;
  /** 审计链最后一条记录的哈希（前向哈希链锚点） */
  auditChainHead: string;
  issuedAt: string;
  signature: {
    alg: 'ES256';
    /** base64url，签名值 r||n */
    value: string;
    /** base64url，SPKI 公钥，验签时与 /v1/public-key 比对 */
    publicKey: string;
  };
}

export interface AuditEntry {
  seq: number;
  timestamp: string;
  action: string;
  keyId: string | null;
  actor: string;
  detail: Record<string, unknown>;
  /** 前一条记录的哈希（seq=0 时为固定创世值） */
  prevHash: string;
  /** 对本条记录（不含 hash 字段）规范 JSON 的 SHA-256 */
  hash: string;
}

export interface VerifyReport {
  reportId: string;
  generatedAt: string;
  target: 'live-stores' | 'backup-snapshot' | 'all';
  targetLocation: string;
  certificateId: string;
  keyId: string;
  samples: VerifySample[];
  /** 对目标的结构性安全结论（如备份中是否存在包裹 DEK / 明文 PII） */
  structuralChecks: { name: string; passed: boolean; detail: string }[];
  conclusion: 'unrecoverable' | 'still-recoverable' | 'inconclusive';
}

export interface VerifySample {
  source: string;
  recordLocator: string;
  kid: string;
  kv: number;
  /** 用已销毁 keyId 尝试解密的结果，必须为 DECRYPTION_REFUSED */
  decryptAttempt: 'DECRYPTION_REFUSED' | 'DECRYPTION_SUCCEEDED' | 'SKIPPED';
  blindIndexStatus: 'tombstoned' | 'absent' | 'live';
  passed: boolean;
  detail: string;
}

export class ShredError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 500,
  ) {
    super(message);
    this.name = 'ShredError';
  }
}
