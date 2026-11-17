<script setup lang="ts">
import { ref } from 'vue';
import { kmsApi } from '../api';
import Toast from '../components/Toast.vue';

const keyIdInput = ref('');
const status = ref<unknown>(null);
const publicKey = ref('');
const kekMsg = ref('');
const toast = ref<InstanceType<typeof Toast> | null>(null);

async function queryKey(): Promise<void> {
  try {
    status.value = await kmsApi.keyStatus(keyIdInput.value.trim());
  } catch (e) {
    status.value = { error: (e as Error).message };
  }
}

async function loadPublicKey(): Promise<void> {
  try {
    const body = await kmsApi.publicKey();
    publicKey.value = body.publicKey;
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  }
}

async function rotateKek(): Promise<void> {
  if (!confirm('确认轮换 Root KEK？所有存活 DEK 将被重新包裹（业务密文无需重加密）。')) return;
  try {
    kekMsg.value = JSON.stringify(await kmsApi.rotateKek('admin-ui'), null, 2);
    toast.value?.show('KEK 轮换完成', 'success');
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  }
}

loadPublicKey();
</script>

<template>
  <Toast ref="toast" />

  <div class="panel">
    <h2>密钥状态查询</h2>
    <p class="muted">keyId 形如 dek:user:&lt;userId&gt;，可在用户列表复制</p>
    <div class="row">
      <input v-model="keyIdInput" placeholder="dek:user:usr_xxx" @keyup.enter="queryKey" />
      <button class="btn" @click="queryKey">查询</button>
    </div>
    <pre v-if="status" class="json">{{ JSON.stringify(status, null, 2) }}</pre>
  </div>

  <div class="panel">
    <h2>凭证验签公钥（ECDSA P-256 / SPKI）</h2>
    <p class="muted">法务可用该公钥离线验证任意销毁凭证签名：bun run packages/tools/src/cli.ts verify ... 或内部验签接口。</p>
    <pre class="json">{{ publicKey }}</pre>
  </div>

  <div class="panel">
    <h2>Root KEK 运维</h2>
    <p class="muted">
      KEK 仅用于包裹用户 DEK，轮换时 DEK 本体与所有业务密文不变，只更新密钥库中的包裹密文。
      Master Key 生产环境应由云 KMS/HSM 托管，本地文件仅为演示实现。
    </p>
    <button class="btn secondary" @click="rotateKek">轮换 Root KEK</button>
    <pre v-if="kekMsg" class="json">{{ kekMsg }}</pre>
  </div>
</template>
