<template>
  <div class="packet-sniffing">
    <div v-if="currentView === 'interface-selection'">
      <button @click="$emit('back')" class="back-btn">← Back</button>
      <div class="header">
        <h2>Select Network Interface</h2>
      </div>
      <p class="instructions">Choose an interface for packet capture:</p>
      <div class="interface-list">
        <button 
          v-for="if_name in interfaces" 
          :key="if_name"
          @click="selectInterface(if_name)"
          class="interface-btn"
        >
          {{ if_name }}
        </button>
      </div>
      <div v-if="!interfaces.length" class="loading">
        Loading interfaces...
      </div>
    </div>

    <div v-else-if="currentView === 'capturing'">
      <div class="capture-header">
        <div class="header-content">
          <h2>Packet Capture</h2>
          <div class="interface-name">Interface: {{ selectedInterface }}</div>
        </div>
        <button @click="stopCapture" class="stop-btn">
          Stop Capture
        </button>
      </div>
      
      <div v-if="packets.length" class="content">
        <PacketTable :packets="packets" />
      </div>
      
      <div v-else class="waiting">
        <div class="spinner"></div>
        <p>Waiting for packets...</p>
      </div>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { GetInterfaces, StartPacketCapture, StopPacketCapture } from '../../wailsjs/go/main/App'
import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime'
import PacketTable from '../components/PacketTable.vue'

interface PacketInfo {
  srcMac: string
  destMac: string
  ethType: string
  srcIPv4: string
  destIPv4: string
  srcIPv6: string
  destIPv6: string
  srcPort: number
  destPort: number
  payload: string
}

defineEmits<{
  back: []
}>()

const currentView = ref<'interface-selection' | 'capturing'>('interface-selection')
const interfaces = ref<string[]>([])
const selectedInterface = ref<string>('')
const packets = ref<PacketInfo[]>([])

async function loadInterfaces() {
  interfaces.value = await GetInterfaces(false)
}

function selectInterface(ifName: string) {
  selectedInterface.value = ifName
  currentView.value = 'capturing'
  startCapture()
}

async function startCapture() {
  packets.value = []
  
  EventsOn('packet:captured', (packet: PacketInfo) => {
    packets.value.push(packet)
    // Limit to last 1000 packets to avoid memory issues
    if (packets.value.length > 1000) {
      packets.value.shift()
    }
  })
  
  await StartPacketCapture(selectedInterface.value)
}

async function stopCapture() {
  await StopPacketCapture()
  EventsOff('packet:captured')
  currentView.value = 'interface-selection'
  packets.value = []
}

onMounted(() => {
  loadInterfaces()
})

onUnmounted(() => {
  EventsOff('packet:captured')
  if (currentView.value === 'capturing') {
    StopPacketCapture()
  }
})
</script>

<style scoped>
.packet-sniffing {
  max-width: 1200px;
  margin: 0 auto;
  padding: 40px 20px;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  padding-bottom: 80px;
}

.back-btn {
  padding: 8px 16px;
  background: #3b4a5c;
  border: 1px solid #4a5568;
  border-radius: 6px;
  color: #e1e5e9;
  cursor: pointer;
  font-size: 14px;
  transition: all 0.2s;
  margin-bottom: 20px;
  align-self: flex-start;
}

.back-btn:hover {
  background: #4a5568;
  border-color: #60758a;
}

.header {
  margin-bottom: 10px;
  text-align: center;
}

h2 {
  color: #ffffff;
  font-size: 24px;
  font-weight: 600;
  margin: 0;
}

.instructions {
  color: #b8c5d1;
  margin-bottom: 30px;
  text-align: center;
  font-size: 15px;
}

.interface-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-width: 500px;
  margin: 0 auto;
}

.interface-btn {
  padding: 16px 24px;
  background: #2d3748;
  border: 2px solid #3b4a5c;
  border-radius: 8px;
  color: #e1e5e9;
  cursor: pointer;
  font-size: 16px;
  font-family: monospace;
  transition: all 0.2s;
  text-align: center;
}

.interface-btn:hover {
  background: #374151;
  border-color: #60758a;
  transform: translateY(-1px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
}

.loading {
  color: #9ca3af;
  font-style: italic;
  text-align: center;
  margin-top: 20px;
}

.capture-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding: 15px 20px;
  background: #2d3748;
  border-radius: 8px;
  border: 1px solid #3b4a5c;
}

.header-content {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.interface-name {
  color: #60a5fa;
  font-size: 14px;
  font-family: monospace;
}

.stop-btn {
  padding: 10px 24px;
  background: #dc2626;
  border: none;
  border-radius: 6px;
  color: white;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.stop-btn:hover {
  background: #b91c1c;
}

.content {
  flex: 1;
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
