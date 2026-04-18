# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install       # Install dependencies
npm run dev       # Start dev server (http://localhost:5173)
npm run build     # Production build (output: dist/)
npm run preview   # Preview production build
npm run lint      # Run ESLint
```

## Stack

- **React 19** with JSX (`.jsx` files)
- **Vite 8** for bundling and dev server
- **ESLint 9** with flat config (`eslint.config.js`), react-hooks and react-refresh plugins

## Architecture

Entry point chain: `index.html` → `src/main.jsx` (React `createRoot` + `StrictMode`) → `src/App.jsx`.

Styling uses plain CSS with custom properties for theming and `prefers-color-scheme` for dark mode. No router, state management library, or testing framework is configured yet — the project is currently at the Vite scaffold stage.
