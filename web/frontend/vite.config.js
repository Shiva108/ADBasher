import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],

  build: {
    // Code splitting configuration
    rollupOptions: {
      output: {
        manualChunks: {
          // Separate vendor chunks for better caching
          "react-vendor": ["react", "react-dom"],
          router: ["react-router-dom"],
          websocket: ["socket.io-client"],
          ui: ["react-hot-toast", "lucide-react"],
        },
      },
    },

    // Minification settings
    minify: "terser",
    terserOptions: {
      compress: {
        drop_console: true, // Remove console.logs in production
        drop_debugger: true, // Remove debugger statements
        pure_funcs: ["console.log", "console.info", "console.debug"],
      },
    },

    // Source maps (disabled for smaller builds)
    sourcemap: false,

    // Chunk size warnings
    chunkSizeWarningLimit: 500, // KB

    // Target modern browsers
    target: "es2015",

    // CSS code splitting
    cssCodeSplit: true,
  },

  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: process.env.VITE_API_URL || "http://localhost:5000",
        changeOrigin: true,
      },
      "/socket.io": {
        target: process.env.VITE_SOCKET_URL || "http://localhost:5000",
        ws: true,
      },
    },
  },

  // Optimizations
  optimizeDeps: {
    include: ["react", "react-dom", "react-router-dom"],
  },
});
