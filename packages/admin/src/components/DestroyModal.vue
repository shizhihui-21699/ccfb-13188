<script setup lang="ts">
import { ref } from 'vue';
import { appApi } from '../api';

/** 与 @shred/shared 的 DestructionCertificate 结构保持一致（管理端独立构建，不引内部包） */
interface DestructionCertificate {
  certificateId: string;
  keyId: string;
  destroyedVersions: {
    version: number;
    dekFingerprint: string;
    algorithm: string;
    state: string;
    destroyedAt: string;
  }[];
  reason: string;
  requestedBy: string;
  auditSequence: number;
  auditChainHead: string;
  issuedAt: string;
  signature: { alg: string; value: string; publicKey: string };
}

const props = defineProps<{ user: { userId: string; keyId: string } }>();
const emit = defineEmits<{ close: []; destroyed: [] }>();

const reason = ref('用户行使删除权，法务要求数据彻底不可恢复');
const requestedBy = ref('legal-admin');
const busy = ref(false);
const cert = ref<DestructionCertificate | null>(null);
const error = ref('');

async function confirmDestroy(): Promise<void> {
  busy.value = true;
  error.value = '';
  try {
    cert.value = await appApi.destroy(props.user.userId, reason.value, requestedBy.value);
    emit('destroyed');
  } catch (e) {
    error.value = (e as Error).message;
  } finally {
    busy.value = false;
  }
}

function downloadCert(): void {
  if (!cert.value) return;
  const blob = new Blob([JSON.stringify(cert.value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${cert.value.certificateId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <div class="modal-mask" @click.self="emit('close')">
    <div class="modal">
      <h3>加密粉碎注销</h3>
      <template v-if="!cert">
        <p class="muted">
          将销毁用户 <span class="mono">{{ user.userId }}</span> 对应密钥
          <span class="mono">{{ user.keyId }}</span> 的<strong>全部历史版本 DEK</strong>。
          销毁后主库、搜索索引、日志与所有备份中的密文都将无法解密，且不可撤销。
        </p>
        <div class="field">
          <label>注销原因（写入凭证与审计链）</label>
          <textarea v-model="reason" rows="3" />
        </div>
        <div class="field">
          <label>操作人</label>
          <input v-model="requestedBy" />
        </div>
        <p v-if="error" class="fail">{{ error }}</p>
        <div class="row" style="justify-content:flex-end">
          <button class="btn secondary" @click="emit('close')">取消</button>
          <button class="btn danger" :disabled="busy" @click="confirmDestroy">
            {{ busy ? '销毁中…' : '确认销毁密钥' }}
          </button>
        </div>
      </template>

      <template v-else>
        <p class="ok">✅ 销毁完成，已签发 ECDSA P-256 签名销毁凭证</p>
        <div class="cert-box">
          <div>凭证编号：<span class="mono">{{ cert.certificateId }}</span></div>
          <div style="margin-top:6px">销毁版本：
            <span v-for="v in cert.destroyedVersions" :key="v.version" class="mono badge destroyed" style="margin-right:6px">
              v{{ v.version }} · {{ v.dekFingerprint.slice(0, 16) }}…
            </span>
          </div>
          <div style="margin-top:6px">审计序号：{{ cert.auditSequence }} / 链头：<span class="mono">{{ cert.auditChainHead.slice(0, 24) }}…</span></div>
          <div style="margin-top:6px">签发时间：{{ cert.issuedAt }}</div>
        </div>
        <pre class="json">{{ JSON.stringify(cert, null, 2) }}</pre>
        <div class="row" style="justify-content:flex-end;margin-top:12px">
          <button class="btn secondary" @click="downloadCert">下载凭证 JSON</button>
          <button class="btn" @click="emit('close')">完成</button>
        </div>
      </template>
    </div>
  </div>
</template>
