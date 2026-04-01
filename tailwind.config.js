/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './**/templates/**/*.html',
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#f9fafb',
          100: '#f3f4f6',
          200: '#e5e7eb',
          300: '#d1d5db',
          400: '#6b7280',
          500: '#111827',
          600: '#030712',
          700: '#030712',
          800: '#030712',
          900: '#030712',
        },
        secondary: {
          50: '#fafafa',
          100: '#f4f4f5',
          200: '#e4e4e7',
          300: '#d4d4d8',
          400: '#a1a1aa',
          500: '#71717a',
          600: '#52525b',
          700: '#3f3f46',
          800: '#27272a',
          900: '#18181b',
        },
        dark: {
          700: '#f4f4f5',
          800: '#ffffff',
          900: '#ffffff',
        },
        light: {
          100: '#111827',
          200: '#374151',
          300: '#6b7280',
          400: '#9ca3af',
        },
        'catalyst-blue': '#111827',
        'catalyst-blue-light': '#374151',
        'catalyst-teal': '#111827',
        'catalyst-teal-light': '#030712',
        'catalyst-purple': '#111827',
        'catalyst-purple-light': '#1f2937',
        'catalyst-gray': '#6b7280',
        'catalyst-gray-light': '#9ca3af',
        'catalyst-dark': '#fafafa',
        'catalyst-success': '#15803d',
        'catalyst-warning': '#b45309',
        'catalyst-error': '#dc2626',
      },
      boxShadow: {
        glow: '0 12px 32px rgba(17, 24, 39, 0.08)',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
