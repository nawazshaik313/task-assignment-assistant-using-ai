import path from 'path';
import { defineConfig, loadEnv } from 'vite';

export default defineConfig(({ mode }) => {
  // Load any env vars in .env, even those without the VITE_ prefix
  const env = loadEnv(mode, process.cwd(), '');

  return {
    define: {
      // Expose your Gemini key to the client (same as before)
      'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
      'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
    },

    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.')
      }
    },

    // 👇 Added: make Vite bind to 0.0.0.0 and respect Render’s PORT
    server: {
      host: '0.0.0.0',
      port: Number(process.env.PORT) || 5173,   // Render sets PORT; locally defaults to 5173
      strictPort: false                         // Let Vite pick the next port if 5173 is busy
    },

    // Optional but handy for `vite preview` in CI or staging
    preview: {
      host: '0.0.0.0',
      port: Number(process.env.PORT) || 4173
    }
  };
});
