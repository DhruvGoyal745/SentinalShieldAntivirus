# Cross-Platform Architecture: AI App Builder
## Compatible with Windows, macOS, and Linux

---

## The Cross-Platform Challenge

Emergent.sh runs purely in the browser — it's already cross-platform. But to
build a BETTER product, we need cross-platform at THREE levels:

| Level | What it means | How |
|---|---|---|
| **1. The Platform itself** | Users on any OS can use the builder | Web app (browser-based) |
| **2. The Generated Apps** | Apps the AI builds work on any OS | Containerized output |
| **3. The Development Environment** | Your team can develop on any OS | Cross-platform toolchain |

---

## Level 1: The Platform (What Users See)

### Architecture Decision: 100% Browser-Based

```
┌──────────────────────────────────────────────────────┐
│  User's Browser (any OS)                              │
│  ┌──────────────────────────────────────────────────┐ │
│  │  Next.js 15 App                                  │ │
│  │  ┌────────┬────────────┬──────────┬────────────┐ │ │
│  │  │ Chat   │ Code       │ Preview  │ Terminal   │ │ │
│  │  │ Panel  │ Editor     │ (iframe) │ Output     │ │ │
│  │  │        │ (Monaco)   │          │            │ │ │
│  │  └────────┴────────────┴──────────┴────────────┘ │ │
│  └──────────────────────────────────────────────────┘ │
│  Works identically on Windows, macOS, Linux, ChromeOS │
└──────────────────────────────────────────────────────┘
         │
         │ HTTPS (SSE for streaming)
         ▼
┌──────────────────────────────────────────────────────┐
│  Cloud Backend (OS-agnostic)                          │
│  ┌─────────────────────────────────────────────────┐ │
│  │  Container Orchestration (Docker/K8s)            │ │
│  │  ┌───────────┐  ┌───────────┐  ┌─────────────┐ │ │
│  │  │ Platform  │  │ Agent     │  │ Sandbox     │ │ │
│  │  │ API       │  │ Runtime   │  │ Pool        │ │ │
│  │  │ (Node/Bun)│  │ (Node/Bun)│  │ (Linux VMs) │ │ │
│  │  └───────────┘  └───────────┘  └─────────────┘ │ │
│  └─────────────────────────────────────────────────┘ │
│  Runs on any Linux host / any cloud provider          │
└──────────────────────────────────────────────────────┘
```

### Why NOT a Desktop App?

| Approach | Pros | Cons |
|---|---|---|
| **Web-only (chosen)** | Zero install, instant updates, works everywhere, lower dev cost | Needs internet |
| Electron desktop app | Offline capable | 3x dev effort, 3 OS builds, auto-update pain, 200MB+ download |
| Tauri desktop app | Smaller binary | Still 3 OS builds, limited browser APIs, WebView inconsistencies |

**Decision: Web-only.** Emergent, Bolt.new, Lovable, Replit, v0 — every
successful AI builder is web-only. The code sandbox is cloud-based anyway,
so offline doesn't help.

### Optional: PWA (Progressive Web App) for Desktop Feel

Add to `next.config.js` later for installability on all OS:

```javascript
// next.config.js
const withPWA = require('next-pwa')({
  dest: 'public',
  register: true,
  skipWaiting: true,
});

module.exports = withPWA({
  // ... next config
});
```

This lets users "install" the web app to their dock/taskbar on:
- Windows (Chrome, Edge)
- macOS (Chrome, Safari 17+)
- Linux (Chrome, Chromium)
- ChromeOS (native)
- iOS/Android (home screen)

---

## Level 2: The Generated Apps (What Users Build)

This is the critical differentiator. When a user says "build me a todo app,"
the output must run on ANY platform the user wants.

### Output Targets

```
User's App Spec
       │
       ▼
┌──────────────────────────────────────────────┐
│  Agent Builds Code in Sandbox                 │
│  (always a web app: Next.js/React + API)      │
└──────────────────────┬───────────────────────┘
                       │
          ┌────────────┼────────────────┐
          ▼            ▼                ▼
   ┌────────────┐ ┌────────────┐ ┌──────────────┐
   │ Web Deploy │ │ Mobile     │ │ Desktop      │
   │            │ │ (Capacitor)│ │ (Tauri/PWA)  │
   │ Vercel     │ │            │ │              │
   │ Fly.io     │ │ iOS app    │ │ Win/Mac/Linux│
   │ Coolify    │ │ Android app│ │ installable  │
   └────────────┘ └────────────┘ └──────────────┘
```

### How Generated Apps Become Cross-Platform

**Web (default — always generated):**
- Next.js app → responsive by default → works on all browsers/OS
- Deployed via Docker container → runs on any host

**Mobile (Emergent does this — we should too):**
- Same web code + Capacitor.js wrapper
- Agent generates: `capacitor.config.ts` + native splash screens + icons
- User downloads the Xcode/Android Studio project OR we build it in cloud
- This is how Emergent offers "Build Full-Stack Web & Mobile Apps"

**Desktop (bonus, easy with PWA):**
- PWA manifest already makes it installable
- For serious desktop: Tauri wrapper (agent generates `tauri.conf.json`)
- 10MB binary vs 200MB Electron

### Container Strategy for Generated Apps

Every generated app gets a Dockerfile:

```dockerfile
# Agent-generated Dockerfile (universal, runs on any OS with Docker)
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
```

This container runs identically on:
- Windows (Docker Desktop / WSL2)
- macOS (Docker Desktop / OrbStack)
- Linux (native Docker)
- Any cloud (AWS, Azure, GCP, Fly.io, Railway, Coolify)

---

## Level 3: Development Environment (Your Team)

### Monorepo Structure

```
emergent-platform/
├── apps/
│   ├── web/                    # Next.js 15 frontend (cross-platform)
│   │   ├── app/                # App Router pages
│   │   ├── components/         # React components
│   │   ├── lib/                # Utilities
│   │   └── package.json
│   │
│   └── api/                    # Hono API server (runs on Bun/Node)
│       ├── src/
│       │   ├── routes/         # API routes
│       │   ├── services/       # Business logic
│       │   ├── agent/          # Agent runtime
│       │   └── index.ts        # Entry point
│       └── package.json
│
├── packages/
│   ├── db/                     # Drizzle ORM schema + migrations
│   │   ├── schema/
│   │   ├── migrations/
│   │   └── package.json
│   │
│   ├── shared/                 # Shared types, constants, utils
│   │   ├── types/
│   │   └── package.json
│   │
│   └── ui/                     # Shared UI components (shadcn/ui based)
│       ├── components/
│       └── package.json
│
├── docker/
│   ├── docker-compose.yml      # Local dev: Postgres + Redis
│   ├── Dockerfile.web          # Frontend container
│   └── Dockerfile.api          # API container
│
├── .github/
│   └── workflows/
│       ├── ci.yml              # Test + lint on every PR
│       └── deploy.yml          # Deploy on merge to main
│
├── turbo.json                  # Turborepo configuration
├── package.json                # Root workspace
├── .nvmrc                      # Node version pinning
└── README.md
```

### Cross-Platform Dev Toolchain

Every tool chosen works identically on Windows, macOS, and Linux:

| Tool | Purpose | Windows | macOS | Linux |
|---|---|---|---|---|
| **Node.js 22** | Runtime | ✅ native | ✅ native | ✅ native |
| **Bun** | Fast bundler + runtime | ✅ native | ✅ native | ✅ native |
| **pnpm** | Package manager | ✅ | ✅ | ✅ |
| **Docker** | Containers | ✅ Desktop/WSL2 | ✅ Desktop/OrbStack | ✅ native |
| **PostgreSQL** | Database | via Docker | via Docker | via Docker |
| **Redis** | Cache/pubsub | via Docker | via Docker | via Docker |
| **Turborepo** | Monorepo builds | ✅ | ✅ | ✅ |
| **VS Code** | Editor | ✅ | ✅ | ✅ |
| **GitHub Actions** | CI/CD | Linux runners | — | — |

### docker-compose.yml for Local Dev (Any OS)

```yaml
# docker/docker-compose.yml
version: '3.8'

services:
  postgres:
    image: pgvector/pgvector:pg17
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: emergent
      POSTGRES_USER: emergent
      POSTGRES_PASSWORD: emergent_dev
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U emergent"]
      interval: 5s
      timeout: 3s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

volumes:
  pgdata:
```

### One-Command Setup (Any OS)

```bash
# Works on Windows (PowerShell/Git Bash), macOS, Linux
git clone https://github.com/your-org/emergent-platform.git
cd emergent-platform
pnpm install
docker compose -f docker/docker-compose.yml up -d
pnpm db:migrate
pnpm dev
# → http://localhost:3000 (web)
# → http://localhost:4000 (api)
```

---

## Deployment Architecture (Multi-Cloud, Any OS Host)

```
                    ┌─────────────────────────────┐
                    │  Cloudflare / Vercel Edge    │
                    │  (CDN + WAF + DDoS)          │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────┴──────────────┐
                    │  Load Balancer               │
                    └──────┬──────────────┬───────┘
                           │              │
              ┌────────────┴───┐   ┌──────┴───────────┐
              │  Web (Next.js) │   │  API (Hono/Bun)   │
              │  Vercel /      │   │  Fly.io /          │
              │  Cloudflare    │   │  Railway /         │
              │  Pages         │   │  Azure Container   │
              └────────────────┘   │  Apps              │
                                   └──────┬────────────┘
                                          │
                           ┌──────────────┼──────────────┐
                           │              │              │
                    ┌──────┴─────┐ ┌──────┴────┐ ┌──────┴──────┐
                    │ PostgreSQL │ │ Redis     │ │ Blob Store  │
                    │ Neon /     │ │ Upstash / │ │ S3 / R2 /   │
                    │ Supabase / │ │ Redis     │ │ Azure Blob  │
                    │ Azure DB   │ │ Cloud     │ │             │
                    └────────────┘ └───────────┘ └─────────────┘

All services run in Linux containers — deployable to ANY cloud.
No Windows-specific or macOS-specific dependencies anywhere.
```

### Cloud Provider Options (All Equivalent)

| Component | Budget Option | Scale Option | Enterprise Option |
|---|---|---|---|
| **Frontend** | Vercel (free tier) | Vercel Pro ($20/mo) | Cloudflare Pages |
| **API** | Railway ($5/mo) | Fly.io ($10/mo) | Azure Container Apps |
| **Database** | Neon (free 0.5GB) | Supabase Pro ($25/mo) | Azure DB for Postgres |
| **Redis** | Upstash (free 10K/day) | Upstash Pro ($10/mo) | Azure Cache |
| **Blob Storage** | Cloudflare R2 (free 10GB) | R2 ($0.015/GB) | Azure Blob |
| **Sandboxes** | E2B ($0.05/min) | E2B ($0.05/min) | Self-hosted Firecracker |
| **TOTAL** | ~$15/mo | ~$70/mo | ~$300/mo |

---

## Key Decisions for Cross-Platform

### What We Avoid (Platform-Specific Traps)

| Trap | Why it breaks cross-platform | Our alternative |
|---|---|---|
| **Electron desktop app** | 3 OS builds, 3 update mechanisms, 3 CI pipelines | PWA (zero-install, auto-update) |
| **Native file system access** | Different APIs on each OS | Cloud sandbox (files live in container) |
| **Windows-only tools** (IIS, MSBuild) | Locks out macOS/Linux devs | Node.js/Bun + Docker (universal) |
| **Path separators** (`\` vs `/`) | Bugs on every cross-OS boundary | Always use `/` in code, normalize in lib |
| **Shell scripts** (.bat vs .sh) | Two scripts for everything | `package.json` scripts (pnpm handles OS) |
| **SQLite local file DB** | File locking differs across OS | PostgreSQL in Docker (identical everywhere) |
| **Hardcoded localhost ports** | Firewall rules differ | `.env` files + Docker networking |

### What We Embrace

| Choice | Cross-platform benefit |
|---|---|
| **TypeScript everywhere** | Same language, same types, frontend + backend |
| **Docker for all services** | "Works on my machine" eliminated |
| **pnpm workspaces** | Monorepo that works identically on all OS |
| **GitHub Actions (Linux runners)** | CI is OS-independent |
| **Environment variables** | No OS-specific config files |
| **Web Standards** (SSE, fetch, WebSocket) | Browser handles OS differences |

---

## Summary: Cross-Platform Strategy

```
YOUR PLATFORM:
  ✅ Web app — runs in any browser on any OS
  ✅ PWA — installable on Windows/macOS/Linux/mobile
  ✅ Cloud backend — Linux containers, any cloud
  ✅ Dev environment — Docker + Node.js, works on all OS

APPS YOUR USERS BUILD:
  ✅ Web — responsive, works everywhere
  ✅ Mobile — Capacitor wrapper for iOS/Android
  ✅ Desktop — PWA install or Tauri wrapper
  ✅ Self-hostable — Docker container, any OS

ZERO PLATFORM-SPECIFIC CODE ANYWHERE.
```
