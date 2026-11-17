<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { kmsApi } from '../api';
import Toast from '../components/Toast.vue';

interface AuditRow {
  seq: number;
  timestamp: string;
  action: string;
  keyId: string | null;
  actor: string;
  detail: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

const entries = ref<AuditRow[]>([]);
const chainValid = ref<boolean | null>(null);
const chainInfo = ref<{ count: number; brokenAt: number | null } | null>(null);
const toast = ref<InstanceType<typeof Toast> | null>(null);

async function load(): Promise<void> {
  try {
    const body = await kmsApi.audit(200);
    entries.value = (body.entries ?? []).slice().reverse();
    chainValid.value = body.chainValid;
    chainInfo.value = { count: body.count, brokenAt: body.brokenAt };
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  }
}

async function verify(): Promise<void> {
  try {
    chainInfo.value = await kmsApi.verifyChain();
    chainValid.value = chainInfo.value.chainValid;
    toast.value?.show(
      chainInfo.value.chainValid ? `哈希链完整，共 ${chainInfo.value.count} 条` : `链在 seq=${chainInfo.value.brokenAt} 断裂`,
      chainInfo.value.chainValid ? 'success' : 'error',
    );
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  }
}

onMounted(load);
</script>

<template>
  <Toast ref="toast" />
  <div class="panel">
    <div class="row" style="justify-content:space-between">
      <h2 style="margin:0">KMS 哈希链审计日志</h2>
      <div class="row">
        <span v-if="chainValid !== null" class="badge" :class="chainValid ? 'active' : 'destroyed'">
          {{ chainValid ? '哈希链完整' : '哈希链被篡改' }}
        </span>
        <button class="btn secondary" @click="load">刷新</button>
        <button class="btn" @click="verify">重算校验</button>
      </div>
    </div>
    <p class="muted" v-if="chainInfo">共 {{ chainInfo.count }} 条记录，每条包含前一条的 SHA-256 哈希，任意篡改都会被重算发现。</p>
    <table>
      <thead>
        <tr><th>seq</th><th>时间</th><th>动作</th><th>keyId</th><th>操作人</th><th>详情</th><th>记录哈希</th></tr>
      </thead>
      <tbody>
        <tr v-for="e in entries" :key="e.seq">
          <td>{{ e.seq }}</td>
          <td class="muted">{{ new Date(e.timestamp).toLocaleString() }}</td>
          <td><span class="badge" :class="e.action.includes('destroy') ? 'destroyed' : 'warn'">{{ e.action }}</span></td>
          <td class="mono">{{ e.keyId ?? '—' }}</td>
          <td>{{ e.actor }}</td>
          <td class="mono muted">{{ JSON.stringify(e.detail) }}</td>
          <td class="mono muted">{{ e.hash.slice(0, 18) }}…</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
