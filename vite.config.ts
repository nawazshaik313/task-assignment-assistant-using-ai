import path from 'path';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');

  return {
    define: {
      'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY),
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      host: '0.0.0.0',
      port: Number(process.env.PORT) || 5173,

      // ✅ Allow your Render domain explicitly
      allowedHosts: ['task-assignment-assistant-using-ai.onrender.com']
    },
    preview: {
      host: '0.0.0.0',
      port: Number(process.env.PORT) || 4173
    }
  };
});
