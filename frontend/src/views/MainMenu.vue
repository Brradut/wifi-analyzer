<template>
  <div class="main-menu">
    <h1>Wi-Fi Analyzer</h1>
    <p class="subtitle">Select a feature to get started</p>
    <div class="menu-options">
      <button @click="$emit('select', 'monitoring')" class="menu-btn">
        <span class="icon">📡</span>
        <span class="label">Network Monitoring</span>
        <span class="description">Scan and analyze Wi-Fi networks</span>
      </button>
      <button @click="$emit('select', 'sniffing')" class="menu-btn">
        <span class="icon">🔍</span>
        <span class="label">Packet Sniffing</span>
        <span class="description">Capture and analyze network packets</span>
      </button>
    </div>
  </div>
</template>

<script lang="ts" setup>
defineEmits<{
  select: [feature: string]
}>()
</script>

<style scoped>
.main-menu {
  max-width: 600px;
  margin: 0 auto;
  text-align: center;
  padding: 80px 20px;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

h1 {
  color: #ffffff;
  font-size: 32px;
  margin-bottom: 8px;
  font-weight: 600;
}

.subtitle {
  color: #b8c5d1;
  font-size: 16px;
  margin-bottom: 40px;
}

.menu-options {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.menu-btn {
  padding: 30px;
  background: #2d3748;
  border: 2px solid #3b4a5c;
  border-radius: 12px;
  color: #e1e5e9;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  text-align: center;
}

.menu-btn:hover {
  background: #374151;
  border-color: #60758a;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.icon {
  font-size: 48px;
  margin-bottom: 8px;
}

.label {
  font-size: 20px;
  font-weight: 600;
  color: #ffffff;
}

.description {
  font-size: 14px;
  color: #9ca3af;
}
</style>
