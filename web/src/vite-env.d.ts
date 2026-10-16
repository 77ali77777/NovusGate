/// <reference types="vite/client" />

// The release number from package.json (vite.config.ts define).
declare const __APP_VERSION__: string

interface ImportMetaEnv {
  readonly VITE_WS_URL: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
