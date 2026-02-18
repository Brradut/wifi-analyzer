<template>
  <div class="channel-graph">
    <h3>Channel Distribution</h3>
    <div class="graph-container">
      <div 
        v-for="item in channelDistribution" 
        :key="item.channel"
        class="bar-group"
      >
        <div class="bar-container">
          <div 
            class="bar" 
            :style="{ height: (item.count / maxChannelCount * 100) + '%' }"
          >
            <span class="bar-count">{{ item.count }}</span>
          </div>
        </div>
        <div class="bar-label">Ch {{ item.channel }}</div>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { computed } from 'vue'

interface NetworkInfo {
  ssid: string
  bssid: string
  channel: number
  frequency: number
  signalStrength: number
}

const props = defineProps<{
  networks: NetworkInfo[]
}>()

const channelDistribution = computed(() => {
  const distribution: Record<number, number> = {}
  props.networks.forEach(net => {
    distribution[net.channel] = (distribution[net.channel] || 0) + 1
  })
  return Object.entries(distribution)
    .map(([channel, count]) => ({ channel: Number(channel), count }))
    .sort((a, b) => a.channel - b.channel)
})

const maxChannelCount = computed(() => {
  return Math.max(...channelDistribution.value.map(item => item.count), 1)
})
</script>

<style scoped>
.channel-graph {
  padding: 20px;
  border-bottom: 1px solid #3b4a5c;
}

h3 {
  color: #f3f4f6;
  font-size: 14px;
  font-weight: 600;
  margin: 0 0 15px 0;
}

.graph-container {
  display: flex;
  align-items: flex-end;
  justify-content: center;
  gap: 8px;
  height: 150px;
  padding: 10px 0;
}

.bar-group {
  display: flex;
  flex-direction: column;
  align-items: center;
  flex: 1;
  max-width: 60px;
}

.bar-container {
  width: 100%;
  height: 120px;
  display: flex;
  align-items: flex-end;
  justify-content: center;
}

.bar {
  width: 100%;
  background: linear-gradient(180deg, #60a5fa 0%, #3b82f6 100%);
  border-radius: 4px 4px 0 0;
  position: relative;
  transition: all 0.3s ease;
  min-height: 20px;
  display: flex;
  align-items: flex-start;
  justify-content: center;
  padding-top: 5px;
}

.bar:hover {
  background: linear-gradient(180deg, #93c5fd 0%, #60a5fa 100%);
}

.bar-count {
  color: #ffffff;
  font-size: 11px;
  font-weight: 600;
}

.bar-label {
  color: #9ca3af;
  font-size: 11px;
  margin-top: 6px;
  font-weight: 500;
}
</style>
