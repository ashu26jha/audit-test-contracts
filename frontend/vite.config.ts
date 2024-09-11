import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: true, // Listen on all network interfaces
    port: 5173, // Use the port you want to expose
  },
  css: {
    modules: {
      localsConvention: 'camelCaseOnly',
    },
  },
});
