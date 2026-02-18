<template>
  <div class="monitoring-header">
    <div class="status">
      <span class="monitoring-badge">● LIVE</span>
      <span class="interface-name">{{ interfaceName }}</span>
    </div>
    <button @click="$emit('stop')" class="stop-btn">Stop</button>
  </div>
</template>

<script lang="ts" setup>
defineProps<{
  interfaceName: string
}>()

defineEmits<{
  stop: []
}>()
</script>

<style scoped>
.monitoring-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px 0;
  border-bottom: 1px solid #3b4a5c;
  margin-bottom: 20px;
}

.status {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
  justify-content: center;
}

.monitoring-badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  background: #065f46;
  color: #10b981;
  border-radius: 12px;
  font-size: 12px;
  font-weight: 600;
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}

.interface-name {
  font-family: monospace;
  background: #2d3748;
  padding: 4px 8px;
  border-radius: 4px;
  color: #ffffff;
  font-size: 14px;
}

.stop-btn {
  padding: 8px 16px;
  background: #dc2626;
  border: none;
  border-radius: 4px;
  color: white;
  cursor: pointer;
  font-weight: 500;
  transition: background-color 0.2s;
}

.stop-btn:hover {
  background: #b91c1c;
}
</style>
