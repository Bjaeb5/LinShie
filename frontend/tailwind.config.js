/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        primary: { DEFAULT: '#1e3a5f', light: '#2e6da4', dark: '#152a45' },
        danger: '#e74c3c',
        warning: '#f39c12',
        success: '#27ae60',
      }
    }
  },
  plugins: []
}
