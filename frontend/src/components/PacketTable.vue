<template>
  <div class="packet-table">
    <div class="packet-count">{{ packets.length }} packets captured</div>
    <div class="table-container">
      <table class="packets-table">
        <thead>
          <tr>
            <th style="width: 50px">#</th>
            <th style="width: 120px">Type</th>
            <th>Addresses</th>
            <th style="width: 120px">Ports</th>
            <th style="width: 40px"></th>
          </tr>
        </thead>
        <tbody>
          <template v-for="(pkt, idx) in packets" :key="idx">
            <tr class="packet-row" @click="toggleExpanded(idx)">
              <td class="center">{{ idx + 1 }}</td>
              <td class="type" :class="getTypeClass(pkt.ethType)">{{ pkt.ethType }}</td>
              <td class="addresses">
                <div class="address-line">
                  <span class="label">MAC:</span>
                  <span class="mac">{{ pkt.srcMac }}</span>
                  <span class="arrow">→</span>
                  <span class="mac">{{ pkt.destMac }}</span>
                </div>
                <div v-if="getSourceIP(pkt) !== '-'" class="address-line">
                  <span class="label">IP:</span>
                  <span class="ip">{{ getSourceIP(pkt) }}</span>
                  <span class="arrow">→</span>
                  <span class="ip">{{ getDestIP(pkt) }}</span>
                </div>
              </td>
              <td class="center">{{ getPortInfo(pkt) }}</td>
              <td class="center expand-icon">
                <span v-if="pkt.payload">{{ expandedRows.has(idx) ? '▼' : '▶' }}</span>
              </td>
            </tr>
            <tr v-if="expandedRows.has(idx) && pkt.payload" class="expanded-row">
              <td colspan="5" class="payload-cell">
                <div class="payload-container">
                  <div class="payload-header">Packet Payload (ASCII)</div>
                  <pre class="payload-content">{{ toAscii(pkt.payload) }}</pre>
                </div>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { ref } from 'vue'

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

defineProps<{
  packets: PacketInfo[]
}>()

const expandedRows = ref(new Set<number>())

function toggleExpanded(idx: number) {
  if (expandedRows.value.has(idx)) {
    expandedRows.value.delete(idx)
  } else {
    expandedRows.value.add(idx)
  }
}

function toAscii(payload: string): string {
  if (!payload) return '(no payload)'
  
  let result = ''
  for (let i = 0; i < payload.length; i++) {
    const charCode = payload.charCodeAt(i)
    // Print readable ASCII characters, replace others with '.'
    if (charCode >= 32 && charCode <= 126) {
      result += payload[i]
    } else if (charCode === 10) {
      result += '\n'
    } else if (charCode === 13) {
      result += '\r'
    } else if (charCode === 9) {
      result += '\t'
    } else {
      result += '.'
    }
  }
  return result || '(no printable characters)'
}

function getSourceIP(pkt: PacketInfo): string {
  if (pkt.srcIPv4) return pkt.srcIPv4
  if (pkt.srcIPv6) return formatIPv6(pkt.srcIPv6)
  return '-'
}

function getDestIP(pkt: PacketInfo): string {
  if (pkt.destIPv4) return pkt.destIPv4
  if (pkt.destIPv6) return formatIPv6(pkt.destIPv6)
  return '-'
}

function formatIPv6(ipv6: string): string {
  if (!ipv6 || ipv6.length !== 32) return ipv6
  // Format as xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx
  const parts = []
  for (let i = 0; i < 32; i += 4) {
    parts.push(ipv6.substring(i, i + 4))
  }
  return parts.join(':')
}

function getPortInfo(pkt: PacketInfo): string {
  if (pkt.srcPort > 0 && pkt.destPort > 0) {
    return `${pkt.srcPort} → ${pkt.destPort}`
  }
  return '-'
}

function getTypeClass(ethType: string): string {
  if (ethType.includes('TCP')) return 'tcp'
  if (ethType.includes('UDP')) return 'udp'
  if (ethType.includes('ICMP')) return 'icmp'
  if (ethType.includes('ARP')) return 'arp'
  return 'other'
}
</script>

<style scoped>
.packet-table {
  background: #2d3748;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #3b4a5c;
}

.packet-count {
  background: #343c4a;
  padding: 10px 15px;
  color: #9ca3af;
  font-size: 13px;
  border-bottom: 1px solid #3b4a5c;
}

.table-container {
  overflow-x: auto;
  max-height: 600px;
  overflow-y: auto;
}

.packets-table {
  width: 100%;
  border-collapse: collapse;
}

.packets-table th {
  background: #374151;
  color: #f3f4f6;
  font-weight: 600;
  padding: 12px 15px;
  text-align: left;
  font-size: 13px;
  border-bottom: 2px solid #4b5563;
  position: sticky;
  top: 0;
  z-index: 10;
}

.packets-table td {
  padding: 10px 15px;
  border-bottom: 1px solid #3b4a5c;
  font-size: 13px;
  color: #e1e5e9;
  vertical-align: top;
}

.packet-row {
  cursor: pointer;
  transition: background 0.15s;
}

.packet-row:hover {
  background: #343c4a;
}

.packet-row:last-child td {
  border-bottom: none;
}

.expanded-row {
  background: #252e3a;
}

.expanded-row td {
  padding: 0;
}

.addresses {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.address-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}

.label {
  color: #9ca3af;
  font-weight: 500;
  min-width: 35px;
}

.arrow {
  color: #60758a;
  margin: 0 4px;
}

.expand-icon {
  color: #60758a;
  font-size: 10px;
  user-select: none;
}

.payload-cell {
  background: #1f2937;
  border-top: 1px solid #3b4a5c;
}

.payload-container {
  padding: 15px;
}

.payload-header {
  color: #9ca3af;
  font-size: 12px;
  font-weight: 600;
  margin-bottom: 10px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.payload-content {
  background: #0f1419;
  border: 1px solid #3b4a5c;
  border-radius: 4px;
  padding: 12px;
  margin: 0;
  color: #34d399;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.5;
  max-height: 300px;
  overflow-y: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.center {
  text-align: center;
}

.mac {
  font-family: 'Courier New', monospace;
  font-size: 12px;
}

.ip {
  font-family: 'Courier New', monospace;
  font-size: 12px;
}

.type {
  font-weight: 500;
  padding: 4px 8px;
  border-radius: 4px;
  text-align: center;
}

.type.tcp {
  background: #1e3a5f;
  color: #60a5fa;
}

.type.udp {
  background: #1e403a;
  color: #34d399;
}

.type.icmp {
  background: #4a2e3a;
  color: #f87171;
}

.type.arp {
  background: #4a3e2e;
  color: #fbbf24;
}

.type.other {
  background: #3a3a3a;
  color: #9ca3af;
}
</style>
