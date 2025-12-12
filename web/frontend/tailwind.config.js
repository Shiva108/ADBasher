/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'slate': {
          850: '#172033',
          950: '#0a0f1a',
        }
      }
    },
  },
  plugins: [],
}
