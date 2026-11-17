<script setup lang="ts">
import { ref } from 'vue';

const toast = ref<{ text: string; kind: 'info' | 'error' | 'success' } | null>(null);
let timer: ReturnType<typeof setTimeout> | undefined;

function show(text: string, kind: 'info' | 'error' | 'success' = 'info'): void {
  toast.value = { text, kind };
  clearTimeout(timer);
  timer = setTimeout(() => (toast.value = null), 6000);
}

defineExpose({ show });
</script>

<template>
  <div v-if="toast" class="toast" :class="toast.kind">{{ toast.text }}</div>
</template>
