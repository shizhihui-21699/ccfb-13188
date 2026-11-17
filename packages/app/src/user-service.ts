/**
 * 业务逻辑：用户资料的信封加密存储、盲索引搜索、注销编排。
 * 所有 PII 在写入主库之前已加密；服务自身不持有任何长期密钥。
 */
import {
  decryptEnvelope,
  decryptString,
  encryptEnvelope,
  encryptString,
  KmsClient,
  randomId,
  ShredError,
  type DestructionCertificate,
  type EnvelopeV1,
} from '@shred/shared';
import { AppDatabase } from './db';
import { DekCache } from './dek-cache';
import { appConfig } from './config';
import { logger } from './logger';

export interface UserProfile {
  fullName: string;
  phone: string;
  city?: string;
}

interface UserRow {
  id: string;
  key_id: string;
  key_version: number;
  email_env: string;
  profile_env: string;
  state: 'active' | 'destroyed';
  created_at: string;
  destroyed_at: string | null;
  certificate_id: string | null;
}

export class UserService {
  readonly db: AppDatabase;

  constructor(
    private readonly kms: KmsClient,
    private readonly dekCache: DekCache,
  ) {
    this.db = new AppDatabase();
  }

  private keyIdFor(userId: string): string {
    return `dek:user:${userId}`;
  }

  // ---------- 写入 ----------

  async createUser(input: { email: string; profile: UserProfile }, actor: string): Promise<{ userId: string }> {
    const userId = randomId('usr');
    const keyId = this.keyIdFor(userId);
    const now = new Date().toISOString();

    await this.kms.createKey(keyId, actor);
    const { key, version } = await this.dekCache.get(keyId);
    const { emailToken, searchTokens } = await this.kms.blindIndexBatch(input.email, [
      input.profile.fullName,
      input.profile.city ?? '',
    ]);

    const emailEnv = await encryptString(key, keyId, version, input.email);
    const profileEnv = await encryptEnvelope(key, keyId, version, input.profile);

    const tx = this.db.db.transaction(() => {
      this.db.db.run(
        `INSERT INTO users (id, key_id, key_version, email_env, profile_env, state, created_at)
         VALUES (?, ?, ?, ?, ?, 'active', ?)`,
        [userId, keyId, version, JSON.stringify(emailEnv), JSON.stringify(profileEnv), now],
      );
      this.db.db.run('INSERT INTO blind_index (token, context, user_id) VALUES (?, ?, ?)', [
        emailToken,
        'email',
        userId,
      ]);
      for (const token of searchTokens.filter(Boolean)) {
        this.db.db.run(
          `INSERT OR IGNORE INTO search_index (token, user_id) VALUES (?, ?)`,
          [token, userId],
        );
      }
    });
    tx();

    logger.info('user.create', { actor, userId, keyId, kv: version });
    return { userId };
  }

  // ---------- 读取 ----------

  async findByEmail(email: string): Promise<{ userId: string; state: string } | null> {
    const { token } = await this.kms.blindIndex(email, 'email');
    const row = this.db.db
      .query('SELECT user_id, state FROM blind_index WHERE token = ? AND context = ?')
      .get(token, 'email') as { user_id: string; state: string } | undefined;
    if (!row) return null;
    return { userId: row.user_id, state: row.state };
  }

  async getUser(userId: string): Promise<{
    userId: string;
    state: string;
    email: string;
    profile: UserProfile;
    createdAt: string;
  }> {
    const row = this.requireUser(userId);
    if (row.state === 'destroyed') {
      throw new ShredError('USER_DESTROYED', `用户 ${userId} 已注销，密文数据在密码学上不可恢复`, 410);
    }
    const { key } = await this.dekCache.get(row.key_id, row.key_version);
    const email = await decryptString(key, JSON.parse(row.email_env) as EnvelopeV1);
    const profile = await decryptEnvelope<UserProfile>(key, JSON.parse(row.profile_env) as EnvelopeV1);
    return { userId, state: row.state, email, profile, createdAt: row.created_at };
  }

  async search(term: string): Promise<{ userId: string; state: string }[]> {
    const { token } = await this.kms.blindIndex(term, 'search');
    const rows = this.db.db
      .query(
        `SELECT s.user_id AS user_id, u.state AS state
         FROM search_index s JOIN users u ON u.id = s.user_id
         WHERE s.token = ? AND s.state = 'live'`,
      )
      .all(token) as { user_id: string; state: string }[];
    return rows.map((r) => ({ userId: r.user_id, state: r.state }));
  }

  // ---------- 加密粉碎注销 ----------

  /**
   * 注销编排（顺序保证可审计）：
   *  1) 活存储索引立即 tombstone（搜索不可命中）
   *  2) purge 本实例 DEK 缓存
   *  3) 调 KMS 销毁全部版本 DEK，拿到签名销毁凭证 —— 从此所有副本密文不可解密
   *  4) 主库用户行置 destroyed 并登记凭证号（密文行保留为不可恢复的密文证据）
   */
  async destroyUser(userId: string, reason: string, requestedBy: string): Promise<DestructionCertificate> {
    const row = this.requireUser(userId);
    if (row.state === 'destroyed') {
      // 幂等：返回已登记的凭证摘要，不重复销毁
      const status = await this.kms.getStatus(row.key_id);
      throw new ShredError(
        'USER_ALREADY_DESTROYED',
        `用户 ${userId} 已注销（凭证 ${row.certificate_id ?? '未知'}，密钥状态 ${status.state}）`,
        410,
      );
    }

    const now = new Date().toISOString();

    const indexTx = this.db.db.transaction(() => {
      this.db.db.run("UPDATE blind_index SET state = 'tombstoned' WHERE user_id = ?", [userId]);
      this.db.db.run("UPDATE search_index SET state = 'tombstoned' WHERE user_id = ?", [userId]);
    });
    indexTx();

    this.dekCache.purge(row.key_id);

    const cert = await this.kms.destroyKey(row.key_id, reason, requestedBy);

    const finalTx = this.db.db.transaction(() => {
      this.db.db.run(
        `UPDATE users SET state = 'destroyed', destroyed_at = ?, certificate_id = ? WHERE id = ?`,
        [now, cert.certificateId, userId],
      );
    });
    finalTx();

    logger.info('user.destroy', {
      actor: requestedBy,
      userId,
      keyId: row.key_id,
      certificateId: cert.certificateId,
      reason,
      alreadyDestroyed: cert.alreadyDestroyed,
    });
    return cert;
  }

  listUsers(limit = 50): Array<{ userId: string; keyId: string; state: string; createdAt: string; certificateId: string | null }> {
    const rows = this.db.db
      .query('SELECT id, key_id, state, created_at, certificate_id FROM users ORDER BY created_at DESC LIMIT ?')
      .all(limit) as Array<{ id: string; key_id: string; state: string; created_at: string; certificate_id: string | null }>;
    return rows.map((r) => ({ userId: r.id, keyId: r.key_id, state: r.state, createdAt: r.created_at, certificateId: r.certificate_id }));
  }

  private requireUser(userId: string): UserRow {
    const row = this.db.db.query('SELECT * FROM users WHERE id = ?').get(userId) as UserRow | undefined;
    if (!row) throw new ShredError('USER_NOT_FOUND', `用户 ${userId} 不存在`, 404);
    return row;
  }

  close(): void {
    this.db.close();
  }
}

export { appConfig };
