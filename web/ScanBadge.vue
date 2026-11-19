<style scoped>
.scan-status{display:flex;flex-direction:column;align-items:flex-start;gap:6px;max-width:190px;min-width:100px;white-space:normal;margin-top:5px}
.scan-status .report-meta{padding:0;font-size:10px;line-height:1.7;overflow-wrap:anywhere}
</style>
<script setup lang="ts">
import { computed } from 'vue';
import { human } from './client.ts';
const props = defineProps<{ scan?: Record<string, any> }>();
const labels: Record<string,string> = { unscanned: '未扫描', pending: '等待扫描', scanning: '正在扫描', clean: '扫描通过', quarantined: '已隔离', error: '扫描未完成' };
const state = computed(() => props.scan?.state ?? 'unscanned');
const description = computed(() => props.scan?.code === 'SCAN_RESULT_EXPIRED' ? human('SCAN_RESULT_EXPIRED') : state.value === 'quarantined' ? '检测到威胁，下载与交付已阻止；文件仍保留并计入占用。' : state.value === 'error' ? human(String(props.scan?.code ?? 'SCANNER_UNAVAILABLE')) : state.value === 'clean' ? `通过当次本地扫描，仍需谨慎处理文件。${props.scan?.checked ? ' 检查时间：' + new Date(props.scan.checked).toLocaleString('zh-CN', {hour12:false}) : ''}` : '只有扫描通过后才能下载或交付；未扫描不代表安全。');
</script>
<template><div class="scan-status"><span :class="['badge', {red: state === 'quarantined' || state === 'error'}]" :title="description">{{ labels[state] ?? '未扫描' }}</span><small v-if="state === 'quarantined' || state === 'error'" class="report-meta">{{ description }}</small></div></template>
