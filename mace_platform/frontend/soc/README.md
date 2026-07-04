# UnifiedSec MACE v2 — SOC Dashboard

**React 18 + TypeScript + Tailwind CSS + Recharts + Zustand + TanStack Query**

## Start development
```bash
npm install
npm run dev
# Opens on http://localhost:3000
```

## Build for production
```bash
npm run build
```

## Docker
```bash
docker build -t mace-soc --build-arg VITE_API_URL=/api/v1 .
docker run -p 3000:80 mace-soc
```

## Features
- 🔐 JWT auth with auto-refresh + multi-tenant login
- ⚡ Real-time incident push via WebSocket (`/api/v1/correlate/ws/{tenant_id}`)
- 📊 Live asset inventory — UTAG ACS scores, shadow IT, geo anomalies
- 🎯 CDCS score visualization — radar chart, domain breakdown, donut meters
- 📋 Regulatory calendar — 22 frameworks, SLA countdown, draft downloader
- 🔍 Incident detail — status workflow, assignment, evidence viewer, adaptive feedback
- 🌐 Multi-jurisdiction — US, UAE, EU, India, Canada
- 🌙 Dark theme throughout

## Environment
```
VITE_API_URL=/api/v1   # Backend API prefix (default)
```
