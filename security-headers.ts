import type { Plugin } from 'vite';

function buildCsp(supabaseUrl: string): string {
  const api = new URL(supabaseUrl).origin;
  const realtime = api.replace(/^https:/, 'wss:');
  const directives = [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval' https://bolt.new",
    "style-src 'self' https://fonts.googleapis.com",
    "img-src 'self' data: blob:",
    "font-src 'self' https://fonts.gstatic.com",
    // Model weights (Hugging Face) and the compiled model runtime (GitHub) for on-device Blackveil AI; download only.
    `connect-src 'self' ${api} ${realtime} https://huggingface.co https://*.huggingface.co https://*.hf.co https://raw.githubusercontent.com`,
    "media-src 'self' blob:",
    "worker-src 'self'",
    "manifest-src 'self'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    'upgrade-insecure-requests',
  ];
  return directives.join('; ');
}

const PERMISSIONS_POLICY = [
  'camera=(self)',
  'microphone=()',
  'geolocation=()',
  'payment=()',
  'usb=()',
  'midi=()',
  'magnetometer=()',
  'gyroscope=()',
  'accelerometer=()',
  'display-capture=()',
].join(', ');

export function securityHeaders(supabaseUrl: string): Plugin {
  return {
    name: 'blackveil-security-headers',
    apply: 'build',
    transformIndexHtml(_html, ctx) {
      // The published-site viewer renders owner HTML in a sandboxed srcdoc frame, which would inherit this CSP.
      if (ctx.filename.endsWith('site.html')) return [];
      return [
        { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: buildCsp(supabaseUrl) }, injectTo: 'head-prepend' },
        { tag: 'meta', attrs: { name: 'referrer', content: 'strict-origin-when-cross-origin' }, injectTo: 'head-prepend' },
      ];
    },
    generateBundle() {
      const lines = [
        // CSP comes from the <meta> tag in index.html; a header rule on /* would also cover site.html. X-Frame-Options covers framing.
        '/*',
        '  X-Frame-Options: DENY',
        '  X-Content-Type-Options: nosniff',
        '  Referrer-Policy: strict-origin-when-cross-origin',
        `  Permissions-Policy: ${PERMISSIONS_POLICY}`,
        '',
        '/manifest.webmanifest',
        '  Content-Type: application/manifest+json',
        '',
      ];
      this.emitFile({ type: 'asset', fileName: '_headers', source: lines.join('\n') });
    },
  };
}
