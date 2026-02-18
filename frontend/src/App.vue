<template>
  <div class="wifi-analyzer">
    <!-- Main Menu -->
    <MainMenu 
      v-if="currentView === 'main-menu'" 
      @select="handleFeatureSelect"
    />

    <!-- Interface Selector -->
    <InterfaceSelector
      v-else-if="currentView === 'interface-selector'"
      :interfaces="interfaces"
      @select="startMonitoring"
      @back="goToMainMenu"
    />

    <!-- Monitoring View -->
    <MonitoringView
      v-else-if="currentView === 'monitoring'"
      :interface-name="chosenInterface"
      :networks="networkList"
      @stop="stopMonitoring"
    />

    <!-- Packet Sniffing View -->
    <PacketSniffing
      v-else-if="currentView === 'packet-sniffing'"
      @back="goToMainMenu"
    />
  </div>
</template>

<script lang="ts" setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { GetInterfaces, StartMonitoring, StopMonitoring } from '../wailsjs/go/main/App'
import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import MainMenu from './views/MainMenu.vue'
import InterfaceSelector from './views/InterfaceSelector.vue'
import MonitoringView from './views/MonitoringView.vue'
import PacketSniffing from './views/PacketSniffing.vue'

interface NetworkInfo {
  ssid: string
  bssid: string
  channel: number
  frequency: number
  signalStrength: number
}

type ViewType = 'main-menu' | 'interface-selector' | 'monitoring' | 'packet-sniffing'

const currentView = ref<ViewType>('main-menu')
const interfaces = ref<string[]>([])
const chosenInterface = ref('')

// Keyed by BSSID so each network always keeps the latest reading
const networks = ref<Record<string, NetworkInfo>>({})

const networkList = computed(() =>
  Object.values(networks.value).sort((a, b) => b.signalStrength - a.signalStrength)
)

function handleFeatureSelect(feature: string) {
  if (feature === 'monitoring') {
    currentView.value = 'interface-selector'
  } else if (feature === 'sniffing') {
    currentView.value = 'packet-sniffing'
  }
}

function goToMainMenu() {
  currentView.value = 'main-menu'
  networks.value = {}
  chosenInterface.value = ''
}

async function startMonitoring(ifName: string) {
  chosenInterface.value = ifName
  networks.value = {}
  const res = await StartMonitoring(ifName)
  if (res === 'ok') {
    currentView.value = 'monitoring'
  } else {
    console.warn('StartMonitoring:', res)
  }
}

async function stopMonitoring() {
  await StopMonitoring()
  currentView.value = 'interface-selector'
}

function onNetworkFound(data: NetworkInfo) {
  // Always overwrite with the latest data for this BSSID
  networks.value[data.bssid] = { ...data }
}

onMounted(async () => {
  interfaces.value = await GetInterfaces(true)
  EventsOn('network:found', onNetworkFound)
})

onUnmounted(() => {
  EventsOff('network:found')
})
</script>

<style scoped>
.wifi-analyzer {
  color: #e1e5e9;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  min-height: 100vh;
  background: rgb(27, 38, 54);
  box-sizing: border-box;
}
</style>