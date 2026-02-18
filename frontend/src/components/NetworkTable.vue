<template>
  <div class="network-table">
    <div class="network-count">{{ networks.length }} networks found</div>
    <div class="table-container">
      <table class="networks-table">
        <thead>
          <tr>
            <th>SSID</th>
            <th>BSSID</th>
            <th>Ch</th>
            <th>Freq (MHz)</th>
            <th>Signal (dBm)</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="net in networks" :key="net.bssid" class="network-row">
            <td class="ssid">{{ net.ssid || '(hidden)' }}</td>
            <td class="bssid">{{ net.bssid }}</td>
            <td class="center">{{ net.channel }}</td>
            <td class="center">{{ net.frequency }}</td>
            <td class="center signal" :class="getSignalClass(net.signalStrength)">
              {{ net.signalStrength }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script lang="ts" setup>
interface NetworkInfo {
  ssid: string
  bssid: string
  channel: number
  frequency: number
  signalStrength: number
}

defineProps<{
  networks: NetworkInfo[]
}>()

function getSignalClass(signal: number): string {
  if (signal >= -50) return 'excellent'
  if (signal >= -60) return 'good'
  if (signal >= -70) return 'fair'
  return 'poor'
}
</script>

<style scoped>
.network-table {
  background: #2d3748;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #3b4a5c;
}

.network-count {
  background: #343c4a;
  padding: 10px 15px;
  color: #9ca3af;
  font-size: 13px;
  border-bottom: 1px solid #3b4a5c;
}

.table-container {
  overflow-x: auto;
}

.networks-table {
  width: 100%;
  border-collapse: collapse;
}

.networks-table th {
  background: #374151;
  color: #f3f4f6;
  font-weight: 600;
  padding: 12px 15px;
  text-align: left;
  font-size: 13px;
  border-bottom: 2px solid #4b5563;
}

.networks-table td {
  padding: 10px 15px;
  border-bottom: 1px solid #3b4a5c;
  font-size: 13px;
  color: #e1e5e9;
}

.network-row:hover {
  background: #343c4a;
}

.network-row:last-child td {
  border-bottom: none;
}

.ssid {
  font-weight: 500;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.bssid {
  font-family: monospace;
  color: #9ca3af;
  font-size: 12px;
}

.center {
  text-align: center;
}

.signal {
  font-weight: 600;
}

.signal.excellent { color: #10b981; }
.signal.good { color: #f59e0b; }
.signal.fair { color: #f97316; }
.signal.poor { color: #ef4444; }
</style>
