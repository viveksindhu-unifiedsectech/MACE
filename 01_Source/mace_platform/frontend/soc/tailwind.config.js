/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        mace: {
          bg:      '#0a0c10',
          surface: '#0f1117',
          card:    '#161b24',
          border:  '#1e2535',
          accent:  '#00d4ff',
          red:     '#ff4d4f',
          amber:   '#faad14',
          green:   '#52c41a',
          purple:  '#7c3aed',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
      },
      keyframes: {
        glow: {
          '0%, 100%': { boxShadow: '0 0 4px #00d4ff40' },
          '50%': { boxShadow: '0 0 12px #00d4ff80, 0 0 24px #00d4ff30' },
        },
        slideIn: {
          from: { transform: 'translateX(100%)', opacity: '0' },
          to:   { transform: 'translateX(0)',    opacity: '1' },
        },
        fadeIn: {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        }
      }
    }
  },
  plugins: []
}
