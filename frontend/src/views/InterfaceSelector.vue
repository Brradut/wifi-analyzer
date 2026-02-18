<template>
  <div class="interface-selector">
    <button @click="$emit('back')" class="back-btn">← Back</button>
    <div class="header">
      <h2>Select Network Interface</h2>
    </div>
    <p class="instructions">Choose a wireless interface to monitor:</p>
    <div class="interface-list">
      <button 
        v-for="if_name in interfaces" 
        :key="if_name"
        @click="$emit('select', if_name)"
        class="interface-btn"
      >
        {{ if_name }}
      </button>
    </div>
    <div v-if="!interfaces.length" class="loading">
      Loading interfaces...
    </div>
  </div>
</template>

<script lang="ts" setup>
defineProps<{
  interfaces: string[]
}>()

defineEmits<{
  select: [ifName: string]
  back: []
}>()
</script>

<style scoped>
.interface-selector {
  max-width: 500px;
  margin: 0 auto;
  padding: 40px 20px;
  display: flex;
  flex-direction: column;
  min-height: 100vh;
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
</style>
