# CADE Web UI

This directory will contain the **CADE web UI** — a React/TypeScript single-page application providing:

- **Live threat dashboard** — real-time threat score updates and alert feed
- **Attack graph visualization** — interactive directed graph of assets, vulnerabilities, and threat actor paths
- **Score history and trend charts** — temporal view of risk scores per asset and attack path
- **Explanation cards** — human-readable justification for each CADE detection

## Status

🚧 **Placeholder** — UI implementation is planned for v1.0. See [`docs/roadmap.md`](../docs/roadmap.md).

## Planned Stack

| Layer | Technology |
|---|---|
| Framework | React 18+ |
| Language | TypeScript |
| Graph visualization | D3.js or React Flow |
| State management | Zustand or Redux Toolkit |
| API client | Native `fetch` (no axios dependency) |
| Build tool | Vite |
| Testing | Vitest + React Testing Library |

## Getting Started (Future)

```bash
cd ui/
npm install
npm run dev
```

The UI expects the CADE API to be running at `http://localhost:8000` by default (configurable via `.env`).
