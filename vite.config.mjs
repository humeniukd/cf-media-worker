import { readFileSync } from "node:fs";
import { defineConfig } from 'vite';
import { cloudflare } from '@cloudflare/vite-plugin';

export default defineConfig({
  server: {
    https: {
      key: readFileSync('./key.pem'),
      cert: readFileSync('./cert.pem'),
    },
  },
  plugins: [
    cloudflare()
  ]
});
