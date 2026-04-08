export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                accent: '#00f2ff',
                'accent-glow': 'rgba(0, 242, 255, 0.4)',
                danger: '#ff0055',
                success: '#00ffaa',
                dim: '#94a3b8',
                'text-main': '#e2e8f0',
            },
            fontFamily: {
                mono: ['JetBrains Mono', 'monospace'],
                sans: ['Outfit', 'sans-serif'],
            },
        },
    },
    plugins: [],
}
