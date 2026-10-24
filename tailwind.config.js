/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        veil: {
          50:  '#f4f6f8',
          100: '#e6eaef',
          200: '#c4ccd6',
          300: '#9aa6b4',
          400: '#6b7685',
          500: '#475063',
          600: '#2f3647',
          700: '#1d222e',
          800: '#141823',
          900: '#0c0f16',
          950: '#070a10',
        },
        cyan: {
          DEFAULT: '#22d3ee',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 24px -6px rgba(34,211,238,.45)',
        'glow-red': '0 0 24px -6px rgba(239,68,68,.5)',
        card: '0 1px 0 0 rgba(255,255,255,.04) inset, 0 8px 30px -12px rgba(0,0,0,.6)',
      },
    },
  },
  plugins: [],
};
