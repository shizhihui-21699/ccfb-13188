<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { appApi } from '../api';
import Toast from '../components/Toast.vue';
import DestroyModal from '../components/DestroyModal.vue';

interface UserSummary {
  userId: string;
  keyId: string;
  state: 'active' | 'destroyed';
  createdAt: string;
  certificateId: string | null;
}

const users = ref<UserSummary[]>([]);
const loading = ref(false);
const detail = ref<unknown>(null);
const lookupEmail = ref('');
const searchTerm = ref('');
const searchResults = ref<unknown[]>([]);
const destroyTarget = ref<UserSummary | null>(null);

const newUser = ref({ email: '', fullName: '', phone: '', city: '' });
const toast = ref<InstanceType<typeof Toast> | null>(null);

async function load(): Promise<void> {
  loading.value = true;
  try {
    const body = await appApi.listUsers(100);
    users.value = body.users;
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  } finally {
    loading.value = false;
  }
}

async function createUser(): Promise<void> {
  try {
    await appApi.createUser({
      email: newUser.value.email,
      profile: { fullName: newUser.value.fullName, phone: newUser.value.phone, city: newUser.value.city || undefined },
      actor: 'admin-ui',
    });
    newUser.value = { email: '', fullName: '', phone: '', city: '' };
    toast.value?.show('用户已创建，PII 已用其专属 DEK 信封加密落库', 'success');
    await load();
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  }
}

async function openDetail(id: string): Promise<void> {
  try {
    detail.value = await appApi.getUser(id);
  } catch (e) {
    detail.value = { error: (e as Error).message };
  }
}

async function doLookup(): Promise<void> {
  try {
    const body = await appApi.lookupEmail(lookupEmail.value);
    detail.value = body;
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  }
}

async function doSearch(): Promise<void> {
  try {
    const body = await appApi.search(searchTerm.value);
    searchResults.value = body.results;
  } catch (e) {
    toast.value?.show((e as Error).message, 'error');
  }
}

function onDestroyed(): void {
  destroyTarget.value = null;
  load();
}

onMounted(load);
</script>

<template>
  <Toast ref="toast" />

  <div class="panel">
    <h2>新建用户（写入即加密）</h2>
    <div class="row">
      <input v-model="newUser.email" placeholder="邮箱" />
      <input v-model="newUser.fullName" placeholder="姓名" />
      <input v-model="newUser.phone" placeholder="手机号" />
      <input v-model="newUser.city" placeholder="城市（可选）" />
      <button class="btn" @click="createUser">创建</button>
    </div>
  </div>

  <div class="panel">
    <h2>盲索引检索（KMS HMAC，不可逆）</h2>
    <div class="row" style="margin-bottom:10px">
      <input v-model="lookupEmail" placeholder="按邮箱精确查找" @keyup.enter="doLookup" />
      <button class="btn secondary" @click="doLookup">邮箱查找</button>
      <input v-model="searchTerm" placeholder="按姓名/城市搜索" @keyup.enter="doSearch" />
      <button class="btn secondary" @click="doSearch">搜索</button>
      <button class="btn secondary" @click="detail = null; searchResults = []">清除</button>
    </div>
    <div v-if="searchResults.length">
      <table>
        <thead><tr><th>userId</th><th>状态</th></tr></thead>
        <tbody>
          <tr v-for="r in searchResults" :key="(r as any).userId">
            <td class="mono">{{ (r as any).userId }}</td>
            <td><span class="badge" :class="(r as any).state">{{ (r as any).state }}</span></td>
          </tr>
        </tbody>
      </table>
    </div>
    <pre v-if="detail" class="json">{{ JSON.stringify(detail, null, 2) }}</pre>
  </div>

  <div class="panel">
    <div class="row" style="justify-content:space-between">
      <h2 style="margin:0">用户列表</h2>
      <button class="btn secondary" @click="load" :disabled="loading">刷新</button>
    </div>
    <table>
      <thead>
        <tr><th>userId</th><th>keyId / 版本</th><th>状态</th><th>凭证</th><th>创建时间</th><th>操作</th></tr>
      </thead>
      <tbody>
        <tr v-for="u in users" :key="u.userId">
          <td class="mono">{{ u.userId }}</td>
          <td class="mono">{{ u.keyId }}</td>
          <td><span class="badge" :class="u.state">{{ u.state }}</span></td>
          <td class="mono">{{ u.certificateId ?? '—' }}</td>
          <td class="muted">{{ new Date(u.createdAt).toLocaleString() }}</td>
          <td>
            <div class="pill-list">
              <button class="btn secondary" @click="openDetail(u.userId)">查看解密</button>
              <button v-if="u.state === 'active'" class="btn danger" @click="destroyTarget = u">注销粉碎</button>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
    <p v-if="!users.length" class="muted">暂无用户</p>
  </div>

  <DestroyModal v-if="destroyTarget" :user="destroyTarget" @close="destroyTarget = null" @destroyed="onDestroyed" />
</template>
