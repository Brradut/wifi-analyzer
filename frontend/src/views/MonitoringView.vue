<template>
  <div class="monitoring-view">
    <MonitoringHeader 
      :interface-name="interfaceName" 
      @stop="$emit('stop')"
    />
    
    <div v-if="networks.length" class="content">
      <ChannelGraph :networks="networks" />
      <NetworkTable :networks="networks" />
    </div>
    
    <div v-else class="waiting">
      <div class="spinner"></div>
      <p>Waiting for beacon frames...</p>
    </div>
  </div>
</template>

<script lang="ts" setup>
import MonitoringHeader from '../components/MonitoringHeader.vue'
import ChannelGraph from '../components/ChannelGraph.vue'
import NetworkTable from '../components/NetworkTable.vue'

interface NetworkInfo {
  ssid: string
  bssid: string
  channel: number
  frequency: number
  signalStrength: number
}

defineProps<{
  interfaceName: string
  networks: NetworkInfo[]
}>()

defineEmits<{
  stop: []
}>()
</script>

<style scoped>
.monitoring-view {
  max-width: 1000px;
  margin: 0 auto;
  padding: 20px;
  width: 100%;
  min-height: 100vh;
  padding-bottom: 40px;
}

.content {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.waiting {
  text-align: center;
  padding: 60px 20px;
  color: #9ca3af;
}

.spinner {
  width: 24px;
  height: 24px;
  border: 3px solid #3b4a5c;
  border-top: 3px solid #60a5fa;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 15px;
}

@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}
</style>
