/**
 * 独立密钥库（KMS 专用 SQLite）。
 *
 * 安全边界：
 * - 该数据库是全平台唯一存放 DEK 材料（且为 KEK 包裹后的密文）的地方；
 * - 业务库、搜索索引、日志、业务备份中永远不出现 wrapped_dek 列的内容；
 * - 开启 secure_delete，删除记录时同步清零磁盘页内容；
 * - 该库的备份走独立的加密备份域与短保留期（见 README / tools）。
 */
import { Database } from 'bun:sqlite';
import { base64urlEncode, canonicalJSON, randomId, sha256 } from '@shred/shared';
import type { AuditEntry, WrappedDek } from '@shred/shared';
import { ensureParentDir, kmsConfig } from './config';

export interface KeyVersionRow {
  key_id: string;
  version: number;
  wrapped_dek: string | null;
  dek_fingerprint: string;
  state: 'active' | 'destroyed';
  created_at: string;
  destroyed_at: string | null;
}

const GENESIS_HASH = 'SHA256-GENESIS-shred-platform-v1';

export class Keystore {
  readonly db: Database;

  constructor() {
    ensureParentDir(kmsConfig.keystoreFile);
    this.db = new Database(kmsConfig.keystoreFile);
    // 安全相关 PRAGMA：WAL 提升并发；secure_delete 清零被删页；mmap 关闭减少换页残留
    this.db.exec('PRAGMA journal_mode=WAL;');
    this.db.exec('PRAGMA secure_delete=ON;');
    this.db.exec('PRAGMA foreign_keys=ON;');
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS data_keys (
        key_id       TEXT PRIMARY KEY,
        state        TEXT NOT NULL DEFAULT 'active',
        created_at   TEXT NOT NULL,
        destroyed_at TEXT
      );
      CREATE TABLE IF NOT EXISTS key_versions (
        key_id          TEXT NOT NULL REFERENCES data_keys(key_id),
        version         INTEGER NOT NULL,
        wrapped_dek     TEXT,
        dek_fingerprint TEXT NOT NULL,
        state           TEXT NOT NULL DEFAULT 'active',
        created_at      TEXT NOT NULL,
        destroyed_at    TEXT,
        PRIMARY KEY (key_id, version)
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp  TEXT NOT NULL,
        action     TEXT NOT NULL,
        key_id     TEXT,
        actor      TEXT NOT NULL,
        detail     TEXT NOT NULL,
        prev_hash  TEXT NOT NULL,
        hash       TEXT NOT NULL UNIQUE
      );
      CREATE TABLE IF NOT EXISTS secrets (
        name       TEXT PRIMARY KEY,
        value_b64  TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
  }

  // ---------- 密钥操作 ----------

  keyExists(keyId: string): boolean {
    return this.db.query('SELECT 1 FROM data_keys WHERE key_id = ?').get(keyId) !== null;
  }

  isDestroyed(keyId: string): boolean {
    const row = this.db.query('SELECT state FROM data_keys WHERE key_id = ?').get(keyId) as
      | { state: string }
      | undefined;
    return row?.state === 'destroyed';
  }

  createKey(keyId: string, wrapped: WrappedDek, fingerprint: string, now: string): number {
    const tx = this.db.transaction(() => {
      this.db.run('INSERT INTO data_keys (key_id, state, created_at) VALUES (?, ?, ?)', [keyId, 'active', now]);
      this.db.run(
        `INSERT INTO key_versions (key_id, version, wrapped_dek, dek_fingerprint, state, created_at)
         VALUES (?, 1, ?, ?, 'active', ?)`,
        [keyId, JSON.stringify(wrapped), fingerprint, now],
      );
    });
    tx();
    return 1;
  }

  addVersion(keyId: string, version: number, wrapped: WrappedDek, fingerprint: string, now: string): void {
    this.db.run(
      `INSERT INTO key_versions (key_id, version, wrapped_dek, dek_fingerprint, state, created_at)
       VALUES (?, ?, ?, ?, 'active', ?)`,
      [keyId, version, JSON.stringify(wrapped), fingerprint, now],
    );
  }

  getVersion(keyId: string, version: number): KeyVersionRow | undefined {
    return this.db
      .query('SELECT * FROM key_versions WHERE key_id = ? AND version = ?')
      .get(keyId, version) as KeyVersionRow | undefined;
  }

  getLatestVersion(keyId: string): KeyVersionRow | undefined {
    return this.db
      .query('SELECT * FROM key_versions WHERE key_id = ? ORDER BY version DESC LIMIT 1')
      .get(keyId) as KeyVersionRow | undefined;
  }

  listVersions(keyId: string): KeyVersionRow[] {
    return this.db
      .query('SELECT * FROM key_versions WHERE key_id = ? ORDER BY version')
      .all(keyId) as KeyVersionRow[];
  }

  /** KEK 轮换：用新 KEK 的包裹值重写所有仍存活版本 */
  rewriteWrappedDek(keyId: string, version: number, wrapped: WrappedDek): void {
    this.db.run('UPDATE key_versions SET wrapped_dek = ? WHERE key_id = ? AND version = ?', [
      JSON.stringify(wrapped),
      keyId,
      version,
    ]);
  }

  /**
   * 加密粉碎的核心事务（同步部分，审计条目由 service 层异步预计算后传入）：
   * 1) 清空每个版本的 wrapped_dek（secure_delete 触发磁盘页清零）
   * 2) 版本与主密钥置 destroyed（保留行与指纹用于审计与凭证）
   * 3) 同事务写哈希链审计记录
   * 返回被销毁版本的销毁前指纹清单。
   */
  destroyKeyWithAudit(keyId: string, auditEntry: AuditEntry, now: string): KeyVersionRow[] {
    const versions = this.listVersions(keyId).filter((v) => v.state === 'active');
    const tx = this.db.transaction(() => {
      for (const v of versions) {
        // 真正的密钥材料删除点：wrapped_dek 置 NULL，旧值被 secure_delete 清零
        this.db.run(
          `UPDATE key_versions SET wrapped_dek = NULL, state = 'destroyed', destroyed_at = ?
           WHERE key_id = ? AND version = ?`,
          [now, keyId, v.version],
        );
      }
      this.db.run(`UPDATE data_keys SET state = 'destroyed', destroyed_at = ? WHERE key_id = ?`, [now, keyId]);
      this.insertAuditEntry(auditEntry);
    });
    tx();
    return versions;
  }

  // ---------- 机密材料（blind-index pepper 等） ----------

  getSecret(name: string): string | undefined {
    const row = this.db.query('SELECT value_b64 FROM secrets WHERE name = ?').get(name) as
      | { value_b64: string }
      | undefined;
    return row?.value_b64;
  }

  putSecret(name: string, valueB64: string, now: string): void {
    this.db.run(
      `INSERT INTO secrets (name, value_b64, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET value_b64 = excluded.value_b64, updated_at = excluded.updated_at`,
      [name, valueB64, now],
    );
  }

  // ---------- 哈希链审计 ----------

  /**
   * 追加审计记录。
   * 哈希计算是异步 WebCrypto 操作，不能放进 SQLite 同步事务，
   * 因此先在事务外算出 prevHash/hash，再用同步事务原子落盘；
   * 调用方本身处于事务中时（如 destroyKey），请改用 appendAuditEntry 传入预计算条目。
   */
  async audit(
    action: string,
    keyId: string | null,
    actor: string,
    detail: Record<string, unknown>,
    now = new Date().toISOString(),
  ): Promise<AuditEntry> {
    const entry = await this.buildAuditEntry(action, keyId, actor, detail, now);
    const tx = this.db.transaction(() => this.insertAuditEntry(entry));
    tx();
    return entry;
  }

  /** 供调用方事务内使用：先异步预计算条目，再在其事务中调用 insertAuditEntry */
  async buildAuditEntry(
    action: string,
    keyId: string | null,
    actor: string,
    detail: Record<string, unknown>,
    now: string,
  ): Promise<AuditEntry> {
    const head = this.db.query('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1').get() as
      | { seq: number; hash: string }
      | undefined;
    const seq = (head?.seq ?? 0) + 1;
    const prevHash = head?.hash ?? GENESIS_HASH;
    const partial = { seq, timestamp: now, action, keyId, actor, detail, prevHash };
    const hash = base64urlEncode(await sha256(canonicalJSON(partial)));
    return { ...partial, hash };
  }

  /** 必须在调用方事务内执行的同步落盘 */
  insertAuditEntry(entry: AuditEntry): void {
    this.db.run(
      'INSERT INTO audit_log (seq, timestamp, action, key_id, actor, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [entry.seq, entry.timestamp, entry.action, entry.keyId, entry.actor, JSON.stringify(entry.detail), entry.prevHash, entry.hash],
    );
  }

  listAudit(limit: number): AuditEntry[] {
    const rows = this.db
      .query('SELECT seq, timestamp, action, key_id, actor, detail, prev_hash, hash FROM audit_log ORDER BY seq DESC LIMIT ?')
      .all(limit) as Array<{
      seq: number;
      timestamp: string;
      action: string;
      key_id: string | null;
      actor: string;
      detail: string;
      prev_hash: string;
      hash: string;
    }>;
    return rows
      .map((r) => ({
        seq: r.seq,
        timestamp: r.timestamp,
        action: r.action,
        keyId: r.key_id,
        actor: r.actor,
        detail: JSON.parse(r.detail) as Record<string, unknown>,
        prevHash: r.prev_hash,
        hash: r.hash,
      }))
      .reverse();
  }

  /** 全链重算：任一条被篡改即返回断点 */
  async verifyChain(): Promise<{ chainValid: boolean; count: number; brokenAt: number | null }> {
    const rows = this.db
      .query('SELECT seq, timestamp, action, key_id, actor, detail, prev_hash, hash FROM audit_log ORDER BY seq')
      .all() as Array<{
      seq: number;
      timestamp: string;
      action: string;
      key_id: string | null;
      actor: string;
      detail: string;
      prev_hash: string;
      hash: string;
    }>;
    let prev = GENESIS_HASH;
    for (const r of rows) {
      const partial = {
        seq: r.seq,
        timestamp: r.timestamp,
        action: r.action,
        keyId: r.key_id,
        actor: r.actor,
        detail: JSON.parse(r.detail) as Record<string, unknown>,
        prevHash: r.prev_hash,
      };
      const expected = base64urlEncode(await sha256(canonicalJSON(partial)));
      if (r.prev_hash !== prev || r.hash !== expected) {
        return { chainValid: false, count: rows.length, brokenAt: r.seq };
      }
      prev = r.hash;
    }
    return { chainValid: true, count: rows.length, brokenAt: null };
  }

  close(): void {
    this.db.close();
  }
}

export function newCertificateId(): string {
  return randomId('cert');
}
