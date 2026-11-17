/**
 * KMS 业务逻辑层：密钥生命周期、加密粉碎、销毁凭证、盲索引 pepper。
 * HTTP 层只做参数校验与鉴权，所有安全语义都在这里。
 */
import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import {
  base64urlDecode,
  base64urlEncode,
  exportPrivateJwk,
  exportRawKey,
  exportSpkiPublic,
  generateAesKey,
  generateHmacPepper,
  generateSigningKeyPair,
  hmacToken,
  importAesKey,
  importPrivateJwk,
  importSpkiPublic,
  keyFingerprint,
  randomId,
  signCertificateBody,
  unwrapDek,
  verifyCertificate,
  wrapDek,
  type DestructionCertificate,
  type KeyStatus,
  type WrappedDek,
} from '@shred/shared';
import { ShredError } from '@shred/shared';
import { ensureParentDir, kmsConfig } from './config';
import { deriveDomainKey, loadOrCreateMasterKey } from './master-key';
import { Keystore, newCertificateId, type KeyVersionRow } from './keystore';

const ROOT_KEK_FILE = () => kmsConfig.keystoreFile.replace(/\.db$/, '.rootkek');
const SIGNING_FILE = () => kmsConfig.signingKeyFile;

export class KmsService {
  readonly store = new Keystore();
  private masterKey!: CryptoKey;
  private rootKek!: CryptoKey;
  private rootKekId = 'root-kek-v1';
  private signingKey!: CryptoKeyPair;
  private blindPepper: Uint8Array<ArrayBuffer> | null = null;

  async init(): Promise<void> {
    this.masterKey = await loadOrCreateMasterKey();
    await this.loadOrCreateRootKek();
    await this.loadOrCreateSigningKey();
  }

  // ---------- Root KEK ----------

  private async loadOrCreateRootKek(): Promise<void> {
    const file = ROOT_KEK_FILE();
    const wrappingKey = await deriveDomainKey(this.masterKey, 'root-kek-wrap', ['encrypt', 'decrypt']);
    if (existsSync(file)) {
      const wrapped: WrappedDek = JSON.parse(readFileSync(file, 'utf8'));
      const raw = await unwrapDek(wrappingKey, wrapped);
      this.rootKek = await importAesKey(raw, true);
      this.rootKekId = wrapped.kekKid;
    } else {
      this.rootKek = await generateAesKey(true);
      const raw = await exportRawKey(this.rootKek);
      const wrapped = await wrapDek(wrappingKey, raw, this.rootKekId);
      ensureParentDir(file);
      writeFileSync(file, JSON.stringify(wrapped), { mode: 0o600 });
      chmodSync(file, 0o600);
      await this.store.audit('kek.create', null, 'kms-system', { kekKid: this.rootKekId });
      console.log(`[kms] 已生成 Root KEK（Master Key 包裹后落盘）: ${file}`);
    }
  }

  /**
   * KEK 轮换：生成新 KEK，重新包裹所有存活 DEK（DEK 本体不变，业务密文无需重加密）。
   * 这是信封加密的关键运维能力。
   */
  async rotateRootKek(actor: string): Promise<{ oldKekId: string; newKekId: string; rewrapped: number }> {
    const oldKekId = this.rootKekId;
    const newKek = await generateAesKey(true);
    const newRaw = await exportRawKey(newKek);
    const wrappingKey = await deriveDomainKey(this.masterKey, 'root-kek-wrap', ['encrypt', 'decrypt']);
    const newKekId = `root-kek-${randomId('k').slice(-10)}`;

    // 异步密码学运算在事务外完成，收集结果后用一个同步事务落盘
    const keyIds = this.store.db
      .query("SELECT key_id FROM data_keys WHERE state = 'active'")
      .all()
      .map((r) => (r as { key_id: string }).key_id);

    const updates: { keyId: string; version: number; wrapped: WrappedDek }[] = [];
    for (const keyId of keyIds) {
      for (const v of this.store.listVersions(keyId).filter((v) => v.state === 'active')) {
        const oldWrapped: WrappedDek = JSON.parse(v.wrapped_dek!);
        const rawDek = await unwrapDek(this.rootKek, oldWrapped);
        updates.push({ keyId, version: v.version, wrapped: await wrapDek(newKek, rawDek, newKekId) });
      }
    }

    const persistTx = this.store.db.transaction(() => {
      for (const u of updates) this.store.rewriteWrappedDek(u.keyId, u.version, u.wrapped);
    });
    persistTx();

    const persisted = await wrapDek(wrappingKey, newRaw, newKekId);
    writeFileSync(ROOT_KEK_FILE(), JSON.stringify(persisted), { mode: 0o600 });
    chmodSync(ROOT_KEK_FILE(), 0o600);

    this.rootKek = newKek;
    this.rootKekId = newKekId;
    await this.store.audit('kek.rotate', null, actor, { oldKekId, newKekId, rewrapped: updates.length });
    return { oldKekId, newKekId, rewrapped: updates.length };
  }

  // ---------- 签名密钥（凭证） ----------

  private async loadOrCreateSigningKey(): Promise<void> {
    const file = SIGNING_FILE();
    const wrapKey = await deriveDomainKey(this.masterKey, 'signing-key-wrap', ['encrypt', 'decrypt']);
    if (existsSync(file)) {
      const payload = JSON.parse(readFileSync(file, 'utf8')) as { wrapped: WrappedDek; publicSpki: string };
      // 私钥 JWK 用 wrapKey 加密后存储；公钥以 SPKI 明文随文件保存（公钥本就公开）
      const raw = await unwrapDek(wrapKey, payload.wrapped);
      const jwk = JSON.parse(new TextDecoder().decode(raw)) as JsonWebKey;
      const priv = await importPrivateJwk(jwk);
      const pub = await importSpkiPublic(payload.publicSpki);
      this.signingKey = { privateKey: priv, publicKey: pub };
    } else {
      this.signingKey = await generateSigningKeyPair();
      const jwk = await exportPrivateJwk(this.signingKey.privateKey);
      const raw = new TextEncoder().encode(JSON.stringify(jwk));
      const wrapped = await wrapDek(wrapKey, raw, 'signing-jwk-v1');
      const publicSpki = await exportSpkiPublic(this.signingKey.publicKey);
      ensureParentDir(file);
      writeFileSync(file, JSON.stringify({ wrapped, publicSpki }), { mode: 0o600 });
      chmodSync(file, 0o600);
      console.log(`[kms] 已生成凭证签名密钥 ECDSA P-256: ${file}`);
    }
  }

  async getPublicKeySpki(): Promise<string> {
    return exportSpkiPublic(this.signingKey.publicKey);
  }

  // ---------- 用户 DEK 生命周期 ----------

  async createKey(keyId: string, actor: string): Promise<{ version: number }> {
    if (this.store.keyExists(keyId)) throw new ShredError('KEY_ALREADY_EXISTS', `keyId ${keyId} 已存在`, 409);
    const rawDek = await exportRawKey(await generateAesKey(true));
    const wrapped = await wrapDek(this.rootKek, rawDek, this.rootKekId);
    const fingerprint = await keyFingerprint(rawDek);
    const now = new Date().toISOString();
    const version = this.store.createKey(keyId, wrapped, fingerprint, now);
    await this.store.audit('key.create', keyId, actor, { version, dekFingerprint: fingerprint });
    return { version };
  }

  async rotateKey(keyId: string, actor: string): Promise<{ version: number }> {
    this.requireActive(keyId);
    const latest = this.store.getLatestVersion(keyId)!;
    const newVersion = latest.version + 1;
    const rawDek = await exportRawKey(await generateAesKey(true));
    const wrapped = await wrapDek(this.rootKek, rawDek, this.rootKekId);
    const fingerprint = await keyFingerprint(rawDek);
    this.store.addVersion(keyId, newVersion, wrapped, fingerprint, new Date().toISOString());
    await this.store.audit('key.rotate', keyId, actor, { version: newVersion, dekFingerprint: fingerprint });
    return { version: newVersion };
  }

  getStatus(keyId: string): KeyStatus {
    if (!this.store.keyExists(keyId)) throw new ShredError('KEY_NOT_FOUND', `keyId ${keyId} 不存在`, 404);
    const versions = this.store.listVersions(keyId);
    const latest = versions[versions.length - 1];
    return {
      keyId,
      state: this.store.isDestroyed(keyId) ? 'destroyed' : 'active',
      currentVersion: latest.version,
      versions: versions.map((v) => ({
        version: v.version,
        state: v.state as 'active' | 'destroyed',
        createdAt: v.created_at,
        destroyedAt: v.destroyed_at,
      })),
    };
  }

  /** 取明文 DEK：密钥已销毁则拒绝（加密粉碎生效点）。返回非可导出 CryptoKey 供进程内使用 */
  async unwrap(keyId: string, version?: number): Promise<{ dek: CryptoKey; version: number; fingerprint: string }> {
    const { rawDek, version: v, fingerprint } = await this.unwrapRaw(keyId, version);
    return { dek: await importAesKey(rawDek, false), version: v, fingerprint };
  }

  /** 取原始 DEK 字节（仅 HTTP unwrap 端点使用，调用方负责短期持有与丢弃） */
  async unwrapRaw(keyId: string, version?: number): Promise<{ rawDek: Uint8Array<ArrayBuffer>; version: number; fingerprint: string }> {
    if (!this.store.keyExists(keyId)) throw new ShredError('KEY_NOT_FOUND', `keyId ${keyId} 不存在`, 404);
    if (this.store.isDestroyed(keyId)) {
      throw new ShredError('KEY_DESTROYED', `keyId ${keyId} 已销毁，数据在密码学上不可恢复`, 410);
    }
    const row: KeyVersionRow = version
      ? (this.store.getVersion(keyId, version) ?? this.throwVersionMissing(keyId, version))
      : this.store.getLatestVersion(keyId)!;
    if (row.state === 'destroyed' || !row.wrapped_dek) {
      throw new ShredError('KEY_VERSION_DESTROYED', `keyId ${keyId} v${row.version} 已销毁`, 410);
    }
    const rawDek = await unwrapDek(this.rootKek, JSON.parse(row.wrapped_dek) as WrappedDek);
    return { rawDek, version: row.version, fingerprint: row.dek_fingerprint };
  }

  /**
   * 加密粉碎 + 凭证签发。
   * 幂等：已销毁时重新签发一张引用同一销毁事实的凭证（不重复删数据）。
   */
  async destroy(keyId: string, reason: string, requestedBy: string): Promise<DestructionCertificate & { alreadyDestroyed: boolean }> {
    if (!this.store.keyExists(keyId)) throw new ShredError('KEY_NOT_FOUND', `keyId ${keyId} 不存在`, 404);
    const alreadyDestroyed = this.store.isDestroyed(keyId);

    let destroyedRows: KeyVersionRow[];
    let auditSeq: number;
    let chainHead: string;
    const now = new Date().toISOString();

    if (alreadyDestroyed) {
      // 幂等重放：不改变密钥状态，仅记录一次销毁请求事件
      const entry = await this.store.audit('key.destroy.replay', keyId, requestedBy, { reason });
      destroyedRows = this.store.listVersions(keyId);
      auditSeq = entry.seq;
      chainHead = entry.hash;
    } else {
      // 先异步预计算哈希链审计条目，再与 wrapped_dek 清空在同一同步事务原子提交
      const activeVersions = this.store.listVersions(keyId).filter((v) => v.state === 'active');
      const entry = await this.store.buildAuditEntry(
        'key.destroy',
        keyId,
        requestedBy,
        { reason, destroyedVersions: activeVersions.map((v) => ({ version: v.version, dekFingerprint: v.dek_fingerprint })) },
        now,
      );
      destroyedRows = this.store.destroyKeyWithAudit(keyId, entry, now);
      auditSeq = entry.seq;
      chainHead = entry.hash;
    }

    const cert = await this.buildCertificate({
      keyId,
      rows: this.store.listVersions(keyId).filter((v) => v.state === 'destroyed'),
      reason,
      requestedBy,
      auditSeq,
      chainHead,
      issuedAt: now,
      alreadyDestroyed,
    });

    return cert;
  }

  private async buildCertificate(args: {
    keyId: string;
    rows: KeyVersionRow[];
    reason: string;
    requestedBy: string;
    auditSeq: number;
    chainHead: string;
    issuedAt: string;
    alreadyDestroyed: boolean;
  }): Promise<DestructionCertificate & { alreadyDestroyed: boolean }> {
    const publicKey = await this.getPublicKeySpki();
    // alreadyDestroyed 必须在签名前纳入主体，否则验签内容不一致
    const body = {
      certificateId: newCertificateId(),
      keyId: args.keyId,
      alreadyDestroyed: args.alreadyDestroyed,
      destroyedVersions: args.rows.map((r) => ({
        version: r.version,
        dekFingerprint: r.dek_fingerprint,
        algorithm: 'AES-256-GCM' as const,
        state: 'destroyed' as const,
        destroyedAt: r.destroyed_at ?? args.issuedAt,
      })),
      reason: args.reason,
      requestedBy: args.requestedBy,
      auditSequence: args.auditSeq,
      auditChainHead: args.chainHead,
      issuedAt: args.issuedAt,
    };
    const value = await signCertificateBody(this.signingKey.privateKey, body);
    return { ...body, signature: { alg: 'ES256', value, publicKey } };
  }

  /** 离线验签（管理端/法务工具可独立调用） */
  verifyCertificate(cert: DestructionCertificate): Promise<boolean> {
    return verifyCertificate(cert as unknown as Record<string, unknown>);
  }

  // ---------- 盲索引 ----------

  private async getBlindPepper(): Promise<Uint8Array<ArrayBuffer>> {
    if (this.blindPepper) return this.blindPepper;
    const existing = this.store.getSecret('blind-index-pepper');
    if (existing) {
      this.blindPepper = base64urlDecode(existing);
    } else {
      const pepper = await generateHmacPepper();
      this.store.putSecret('blind-index-pepper', base64urlEncode(pepper), new Date().toISOString());
      await this.store.audit('pepper.create', null, 'kms-system', { name: 'blind-index-pepper' });
      this.blindPepper = pepper;
    }
    return this.blindPepper;
  }

  async blindToken(value: string, context: string): Promise<string> {
    return hmacToken(await this.getBlindPepper(), value, context);
  }

  async blindBatch(email: string, searchTerms: string[]): Promise<{ emailToken: string; searchTokens: string[] }> {
    const pepper = await this.getBlindPepper();
    return {
      emailToken: await hmacToken(pepper, email, 'email'),
      searchTokens: await Promise.all(searchTerms.map((t) => hmacToken(pepper, t, 'search'))),
    };
  }

  // ---------- 审计 ----------

  auditChain() {
    return this.store.verifyChain();
  }
  listAudit(limit: number) {
    return this.store.listAudit(limit);
  }

  private requireActive(keyId: string): void {
    if (!this.store.keyExists(keyId)) throw new ShredError('KEY_NOT_FOUND', `keyId ${keyId} 不存在`, 404);
    if (this.store.isDestroyed(keyId)) throw new ShredError('KEY_DESTROYED', `keyId ${keyId} 已销毁`, 410);
  }

  private throwVersionMissing(keyId: string, version: number): never {
    throw new ShredError('VERSION_NOT_FOUND', `keyId ${keyId} v${version} 不存在`, 404);
  }
}
