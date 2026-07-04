/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html','./src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        adm: {
          bg: '#060810', surface: '#0c0f1a', card: '#111624',
          border: '#1a2236', accent: '#6366f1', text: '#e2e8f0', muted: '#64748b'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono','Fira Code','monospace'],
        sans: ['Inter','system-ui','sans-serif']
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.25s ease-out'
      },
      keyframes: {
        fadeIn: { from: { opacity: '0' }, to: { opacity: '1' } },
        slideUp: { from: { opacity: '0', transform: 'translateY(8px)' }, to: { opacity: '1', transform: 'translateY(0)' } }
      }
    }
  },
  plugins: []
}
