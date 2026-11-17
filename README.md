# 加密粉碎（Crypto-Shredding）合规平台

用户注销后满足法务「数据彻底不可恢复」要求的完整实现：**每个用户的数据用其专属 DEK 加密，注销时销毁密钥，使主库、搜索索引、日志及所有历史备份中的该用户密文同时在密码学上失效**。

## 为什么不能靠逐条删除

- 数据散落在主库、搜索索引、日志、多年代备份中，备份只追加、不可逐条改；
- 删除数据库行也无法保证磁盘页、WAL、快照副本被物理清除；
- 加密粉碎把「删数据」转化为「删一把小密钥」：32 字节 DEK 一旦销毁，AES-256-GCM 密文在数学上不可恢复，与副本数量无关。

## 密钥体系（三级）

```
Master Key（0600 文件 / 生产替换为云 KMS·HSM）
   └─ HKDF 域分离派生
        ├─ Root KEK（AES-256-GCM，包裹所有用户 DEK，支持轮换重包裹）
        └─ 签名密钥包裹密钥（保护 ECDSA P-256 凭证签名私钥）

用户 DEK（每用户一把，支持多版本）── 只以 KEK 密文形式存在于独立密钥库
   └─ 业务数据信封（AES-256-GCM + AAD 绑定 kid/kv）
        └─ 可安全进入主库 / 搜索索引 / 日志 / 任意备份
```

**关键隔离不变量**

| 位置 | 允许出现 | 禁止出现 |
|---|---|---|
| 业务库 / 备份 | 密文信封、kid/kv 引用、HMAC 盲 token | DEK 明文、包裹 DEK、Master Key、KEK |
| KMS 独立密钥库 | KEK 包裹的 DEK、销毁指纹、哈希链审计 | 任何业务 PII |
| 日志 | 白名单字段（PII 模式自动脱敏） | 密钥材料、明文 PII |

密钥库开启 `PRAGMA secure_delete=ON`（删除时清零磁盘页），走**独立备份域 + 短保留期**，与业务备份物理隔离。

## 目录结构

```
packages/
  shared/   加密原语、信封、ECDSA 签名、KMS HTTP 客户端、类型
  kms/      独立密钥托管服务（Hono + Bun.serve，端口 3100）
  app/      业务服务：用户数据信封存储、盲索引搜索、注销编排（端口 3200）
  tools/    运维 CLI：seed / migrate / backup / verify / rekey-backup / redact-logs / demo
  admin/    Vue3 + Vite 管理端（端口 5300）
```

## 快速开始

```bash
bun install
cp .env.example .env

# 终端 1：KMS 密钥托管
bun run dev:kms
# 终端 2：业务服务
bun run dev:app
# 终端 3：管理端
bun run dev:admin   # 打开 http://localhost:5300，令牌 dev-admin-token-change-me

# 终端 4：一键完整法务演示（建用户→备份→注销→全副本抽查→凭证验签）
bun run demo
```

## 明文存量迁移与历史备份治理

```bash
bun run seed            # 造明文遗留库 + 2022~2025 四份明文老备份
bun run migrate         # 幂等迁移：建 DEK → 信封加密 → 盲索引 → 迁移账本
bun run migrate --purge-legacy   # 全部成功后清空遗留明文库（secure_delete+VACUUM）
bun run rekey-backup --all       # 修复迁移前的明文老备份（见下）
```

**老备份是加密粉碎唯一覆盖不到的角落**：迁移前快照里是明文，销毁 DEK 对其无效。`rekey-backup` 对每份历史快照：
1. 明文原件先移入 `backups/quarantine/` 单独管控；
2. 存活用户用现网 DEK 转为信封；**已注销用户用一次性随机密钥加密后立即丢弃密钥**（等效粉碎）；
3. 清空明文表 + VACUUM，重跑结构检查确认零明文。

## 注销流程（`POST /v1/admin/users/:id/destroy`）

1. 活存储盲索引/搜索索引立即 tombstone（搜索不可命中）；
2. purge 业务进程内 DEK 缓存；
3. 调 KMS 事务销毁该 keyId **全部历史版本** DEK（`wrapped_dek` 置 NULL + secure_delete）；
4. KMS 签发 **ECDSA P-256 签名销毁凭证**（含每版本销毁前 SHA-256 指纹、审计链序号与链头），落盘 `data/certificates/`；
5. 主库用户行置 `destroyed` 并登记凭证号（密文行保留为不可恢复证据）。

操作幂等；KMS 审计日志为 SHA-256 前向哈希链，任意篡改可被重算发现。

## 销毁后抽查（`bun run verify <keyId> --cert <凭证>`）

- **结构证据**：KMS 密钥全部 destroyed 且包裹值已清空、备份无密钥库文件、PII 列均为信封、无明文遗留行、凭证签名有效；
- **经验证据**：对活库与每份历史备份中的该用户密文，模拟持副本攻击者调 KMS unwrap，必须全部收到 `410 KEY_DESTROYED`（`DECRYPTION_REFUSED`）；
- 报告写入 `data/verifications/`，结论分 `unrecoverable / inconclusive / still-recoverable`。

> 说明：注销**之前**生成的快照里盲索引行可能仍标 live，但 HMAC token 无 KMS pepper 不可逆、不可关联，且对应密文已确认不可解密，不影响 `unrecoverable` 结论。

## 生产化清单（演示实现的替换点）

- [ ] Master Key / Root KEK 托管改为云 KMS 或 HSM（替换点仅 `packages/kms/src/master-key.ts`，接口不变）
- [ ] 服务间 Bearer 令牌改为 mTLS / 工作负载身份（SPIFFE 等）
- [ ] 管理端 SSO 接入与四人原则的销毁审批流
- [ ] 密钥库独立加密备份 + 短保留期策略落地（`backup-keystore`）
- [ ] 数据库静态加密卷、文件系统级 secure deletion 兜底
- [ ] 销毁凭证与验证报告对接法务存证（WORM 存储 / 时间戳服务）

## 测试

```bash
bun test                 # 32 个用例：密码学原语 + KMS 全生命周期 + HTTP 端到端
bun run typecheck        # 后端严格 TS 类型检查
bun run build:admin      # 管理端生产构建
```
