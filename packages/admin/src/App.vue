<script setup lang="ts">
import { ref } from 'vue';
import { getToken, setToken } from './api';
import UsersView from './views/UsersView.vue';
import KeysView from './views/KeysView.vue';
import AuditView from './views/AuditView.vue';

const token = ref(getToken());
const tokenInput = ref('');
const tab = ref<'users' | 'keys' | 'audit'>('users');

function login(): void {
  if (tokenInput.value.trim()) {
    setToken(tokenInput.value.trim());
    token.value = tokenInput.value.trim();
  }
}
function logout(): void {
  sessionStorage.removeItem('shred-admin-token');
  token.value = '';
  tokenInput.value = '';
}
</script>

<template>
  <div v-if="!token" class="panel login-box">
    <h1>加密粉碎管理台</h1>
    <p class="subtitle">Crypto-Shredding 合规平台 · 请输入管理 Bearer 令牌</p>
    <div class="row">
      <input v-model="tokenInput" type="password" placeholder="SHRED_ADMIN_TOKEN（默认 dev-admin-token-change-me）"
             @keyup.enter="login" />
      <button class="btn" @click="login">登录</button>
    </div>
    <p class="muted" style="margin-top:14px;font-size:12px">
      令牌仅保存在当前会话 sessionStorage；生产环境应接入 SSO/mTLS。
    </p>
  </div>

  <template v-else>
    <div class="row" style="justify-content:space-between">
      <div>
        <h1>加密粉碎管理台</h1>
        <p class="subtitle">每用户独立 DEK · 注销即销毁密钥 · 全副本密码学不可恢复 · 签名销毁凭证</p>
      </div>
      <button class="btn secondary" @click="logout">退出</button>
    </div>

    <div class="tabs">
      <button :class="{ active: tab === 'users' }" @click="tab = 'users'">用户与注销</button>
      <button :class="{ active: tab === 'keys' }" @click="tab = 'keys'">密钥与凭证</button>
      <button :class="{ active: tab === 'audit' }" @click="tab = 'audit'">审计链</button>
    </div>

    <UsersView v-if="tab === 'users'" />
    <KeysView v-else-if="tab === 'keys'" />
    <AuditView v-else />
  </template>
</template>
