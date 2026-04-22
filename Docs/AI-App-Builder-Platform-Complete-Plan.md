---
title: "AI-Powered App Builder Platform — Complete Architecture & Implementation Plan"
subtitle: "Production-Ready Architecture Modeled After Emergent.sh"
author: "Dhruv Goyal"
date: "April 2026"
---

\newpage

# Table of Contents

1. Executive Summary
2. Product Vision & Market Reference
3. System Architecture
4. Database Schema
5. Subscription & Credit Engine
6. Agent Runtime & Execution Loop
7. Intelligent Requirements Interview
8. Cross-Platform Strategy
9. Enterprise Readiness
10. Build Phases & Roadmap
11. Cost Projections
12. Key Architectural Decisions
13. Risk Mitigation

\newpage

# 1. Executive Summary

## What We're Building

An AI-powered application builder platform where users describe what they want in plain language, and AI agents design, code, and deploy a fully functional application — from concept to live URL in minutes.

## Target Users

| Segment | Example | Why They Need This |
|---------|---------|-------------------|
| Small Business Owners | Bakery owner wanting online ordering | Can't afford a developer, can't use code |
| IT Agencies | Agency building client sites faster | 10x productivity, lower project costs |
| Product Managers | PM prototyping features | Skip the "waiting for engineering" bottleneck |
| Operations Teams | Ops team needing internal tools | Build dashboards and workflows without IT tickets |
| Enterprise | Large org standardizing app creation | Controlled, auditable, policy-compliant app generation |

## Key Differentiators vs Competitors

| Feature | Emergent.sh | Bolt.new | Our Platform |
|---------|------------|---------|-------------|
| Guided requirements interview | ❌ Blank chat | ❌ Blank chat | ✅ 6-phase conversational interview |
| Non-technical user friendly | Partial | ❌ | ✅ Zero jargon, smart defaults |
| Web + Mobile output | ✅ | ❌ Web only | ✅ Web + Mobile + Desktop (PWA) |
| Cross-platform (all OS) | ✅ Browser | ✅ Browser | ✅ Browser + PWA + Docker |
| Credit-based billing | ✅ | ✅ | ✅ With cost transparency |
| Enterprise SSO | ✅ | ❌ | ✅ SAML + OIDC |
| Self-hostable output | ❌ | ❌ | ✅ Docker container export |
| SOC 2 compliance | ✅ Type II | ❌ | ✅ Planned |

\newpage

# 2. Product Vision & Market Reference

## Emergent.sh Analysis (Production Reference)

Emergent is a Y Combinator S24 company with 3M+ users that has validated the AI app builder market. Key findings from analyzing their production platform:

**Product Model:**

- Chat-based interface where users describe what they want
- AI agents handle design, coding, and deployment
- Output includes both web and mobile applications
- One-click deployment to production

**Monetization Model (Verified):**

| Plan | Price | Credits/Month | Key Features |
|------|-------|--------------|--------------|
| Free | $0 | 10 | Core features, public projects |
| Standard | $20/mo ($16.50 annual) | 100 | Private hosting, GitHub integration |
| Pro | $200/mo ($167 annual) | 750 | 1M context window, custom agents, priority support |
| Enterprise | Custom | Custom | SSO, dedicated infrastructure, SLA, audit logs |

**Technical Observations:**

- SOC 2 Type II certified
- Supports Google, GitHub, Apple, Email, and SSO authentication
- Credit-based billing (1 credit = 1 agent interaction turn)
- Serves SMBs, IT agencies, product managers, operations teams, and enterprises

## Our Advantage

The primary gap in Emergent and every competitor is the **cold start problem** — users are dropped into a blank chat with no guidance. Our platform solves this with a structured requirements interview that extracts a complete application specification through natural conversation, making it accessible to truly non-technical users.

\newpage

# 3. System Architecture

## 3.1 High-Level System Context

The platform consists of five tiers: Frontend, Platform API, Agent Runtime, Sandbox, and Data.

```
┌─────────────────────────────────────────────────────────────┐
│                     External Systems                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐ │
│  │  Stripe  │  │  GitHub  │  │ Auth0/   │  │ Cloud       │ │
│  │ Billing  │  │   API    │  │ Entra ID │  │ Providers   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬──────┘ │
│       │              │             │               │        │
│  ┌────┴──────────────┴─────────────┴───────────────┴──────┐ │
│  │              API Gateway / Load Balancer                │ │
│  │              (Cloudflare / Azure Front Door)            │ │
│  └────┬──────────────┬─────────────┬───────────────┬──────┘ │
│       │              │             │               │        │
│  ┌────┴─────┐  ┌─────┴────┐  ┌────┴─────┐  ┌─────┴──────┐ │
│  │ Web App  │  │ Platform │  │ Agent    │  │ Sandbox    │ │
│  │ (Next.js)│  │   API    │  │ Runtime  │  │ Cluster    │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## 3.2 Detailed Service Architecture

### Frontend Tier

```
Next.js 15 App Router + shadcn/ui + Tailwind CSS
├── Chat Panel (SSE streaming from agent)
├── Code Editor (Monaco, read-only inspect)
├── Live Preview (iframe proxied to sandbox port)
├── Deploy Dashboard (project management)
└── Interview UI (guided requirements gathering)
```

### Platform API Tier (Hono on Bun)

```
├── Auth Service
│   ├── OAuth (Google, GitHub, Apple)
│   ├── Email/Password
│   ├── SSO (SAML 2.0 + OIDC for enterprise)
│   ├── RBAC (owner, admin, member, viewer)
│   └── Team management
│
├── Project Service
│   ├── CRUD operations
│   ├── Fork/clone projects
│   ├── Version control (file snapshots)
│   └── Share/publish (public URL)
│
├── Billing Service
│   ├── Stripe subscriptions
│   ├── Credit tracking and deduction
│   ├── Usage metering
│   └── Webhook handling (payment events)
│
└── Agent Gateway
    ├── Route messages to agent runtime
    ├── SSE streaming to frontend
    ├── Job queuing (BullMQ)
    └── Retry and error handling
```

### Agent Runtime Tier

```
Agent Orchestrator (per-project stateful session)
├── Model Router
│   ├── Claude Sonnet 4 (primary — complex tasks)
│   ├── GPT-4o (fallback — UI work, edits)
│   └── DeepSeek-V3 (cost-optimized — simple tasks)
│
├── Tool Registry
│   ├── File Tools (write, edit, delete, read)
│   ├── Terminal Tools (run commands, npm, pip)
│   ├── Browser Tools (preview, screenshot via Playwright)
│   ├── Deploy Tools (Dockerfile gen, cloud CLI)
│   └── Integration Tools (Stripe setup, email config)
│
└── Context Manager
    ├── Sliding window (last N messages)
    ├── File tree injection (auto-refreshed)
    ├── Error injection (from last build)
    └── Vector memory retrieval (pgvector)
```

### Sandbox Tier

```
Sandbox Pool Manager
├── One sandbox per project
├── E2B MicroVMs (production) / Docker (dev)
├── Isolated filesystem (/workspace)
├── Running services (dev server :3000, database :5432)
├── Auto-hibernate after 5 min idle
├── Resume from S3 snapshot on next message
└── Network isolation (no host access)
```

### Data Tier

```
├── PostgreSQL + pgvector
│   ├── Users, teams, subscriptions
│   ├── Projects, files, conversations, messages
│   ├── Credit transactions, audit logs
│   └── Vector embeddings (semantic memory)
│
├── Redis
│   ├── Session state
│   ├── Rate limiting
│   ├── Pub/Sub (real-time events)
│   └── Agent state (active sessions)
│
└── Blob Storage (S3 / R2 / Azure Blob)
    ├── Project snapshots (workspace tarballs)
    ├── Uploaded assets (logos, images)
    └── Deployment artifacts
```

## 3.3 Monorepo Structure

```
emergent-platform/
├── apps/
│   ├── web/                    # Next.js 15 frontend
│   │   ├── app/                # App Router pages
│   │   │   ├── (auth)/         # Login, signup, OAuth callbacks
│   │   │   ├── (dashboard)/    # Project list, settings
│   │   │   ├── project/[id]/   # Chat + editor + preview
│   │   │   └── interview/[id]/ # Requirements interview UI
│   │   ├── components/         # React components
│   │   │   ├── chat/           # Chat panel, message bubbles
│   │   │   ├── editor/         # Monaco code editor
│   │   │   ├── interview/      # Interview UI components
│   │   │   ├── preview/        # Live preview iframe
│   │   │   └── shared/         # Buttons, cards, layouts
│   │   └── lib/                # API client, hooks, utils
│   │
│   └── api/                    # Hono API server (Bun runtime)
│       ├── src/
│       │   ├── routes/
│       │   │   ├── auth.ts
│       │   │   ├── projects.ts
│       │   │   ├── interviews.ts
│       │   │   ├── conversations.ts
│       │   │   ├── billing.ts
│       │   │   └── deployments.ts
│       │   ├── services/
│       │   │   ├── auth-service.ts
│       │   │   ├── project-service.ts
│       │   │   ├── credit-service.ts
│       │   │   └── sandbox-service.ts
│       │   ├── agent/
│       │   │   ├── orchestrator.ts
│       │   │   ├── model-router.ts
│       │   │   ├── tools/
│       │   │   │   ├── file-tools.ts
│       │   │   │   ├── terminal-tools.ts
│       │   │   │   ├── browser-tools.ts
│       │   │   │   └── deploy-tools.ts
│       │   │   └── interview-agent.ts
│       │   └── index.ts
│       └── package.json
│
├── packages/
│   ├── db/                     # Drizzle ORM schema + migrations
│   ├── shared/                 # Shared types, constants
│   └── ui/                     # Shared UI components (shadcn)
│
├── docker/
│   ├── docker-compose.yml      # Local dev: Postgres + Redis
│   ├── Dockerfile.web
│   └── Dockerfile.api
│
├── turbo.json
├── package.json
└── pnpm-workspace.yaml
```

\newpage

# 4. Database Schema

## 4.1 Identity & Access Management

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT UNIQUE NOT NULL,
    display_name    TEXT,
    avatar_url      TEXT,
    auth_provider   TEXT NOT NULL,
    auth_provider_id TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    last_login_at   TIMESTAMPTZ
);

CREATE TABLE teams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    owner_id        UUID REFERENCES users(id),
    plan            TEXT NOT NULL DEFAULT 'free',
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE team_members (
    team_id         UUID REFERENCES teams(id),
    user_id         UUID REFERENCES users(id),
    role            TEXT NOT NULL DEFAULT 'member',
    invited_at      TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
```

## 4.2 Subscription & Billing

```sql
CREATE TABLE subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id                 UUID REFERENCES teams(id) UNIQUE,
    stripe_customer_id      TEXT UNIQUE,
    stripe_subscription_id  TEXT UNIQUE,
    plan                    TEXT NOT NULL DEFAULT 'free',
    status                  TEXT NOT NULL DEFAULT 'active',
    credits_monthly         INT NOT NULL DEFAULT 10,
    credits_remaining       INT NOT NULL DEFAULT 10,
    current_period_start    TIMESTAMPTZ,
    current_period_end      TIMESTAMPTZ,
    created_at              TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE credit_transactions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID REFERENCES teams(id),
    project_id      UUID,
    amount          INT NOT NULL,
    reason          TEXT NOT NULL,
    model_used      TEXT,
    tokens_input    INT,
    tokens_output   INT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_credit_tx_team
    ON credit_transactions(team_id, created_at DESC);
```

## 4.3 Projects & Code

```sql
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID REFERENCES teams(id),
    created_by      UUID REFERENCES users(id),
    name            TEXT NOT NULL,
    description     TEXT,
    forked_from     UUID REFERENCES projects(id),
    visibility      TEXT NOT NULL DEFAULT 'private',
    tech_stack      JSONB DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'draft',
    sandbox_id      TEXT,
    preview_url     TEXT,
    deploy_url      TEXT,
    github_repo     TEXT,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE project_files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id) ON DELETE CASCADE,
    file_path       TEXT NOT NULL,
    content_hash    TEXT NOT NULL,
    size_bytes      INT,
    language        TEXT,
    version         INT NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE(project_id, file_path, version)
);

CREATE TABLE project_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    blob_url        TEXT NOT NULL,
    file_count      INT,
    size_bytes      BIGINT,
    trigger         TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now()
);
```

## 4.4 Agent Conversations

```sql
CREATE TABLE conversations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id),
    role            TEXT NOT NULL,
    content         TEXT,
    tool_calls      JSONB,
    model_used      TEXT,
    tokens_input    INT,
    tokens_output   INT,
    duration_ms     INT,
    credits_used    INT DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE agent_plans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    conversation_id UUID REFERENCES conversations(id),
    plan_markdown   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    approved_by     UUID REFERENCES users(id),
    approved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);
```

## 4.5 Requirements Interview

```sql
CREATE TABLE interviews (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    user_id         UUID REFERENCES users(id),
    current_phase   TEXT NOT NULL DEFAULT 'spark',
    archetype       TEXT,
    completed_at    TIMESTAMPTZ,
    spec_json       JSONB,
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE interview_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interview_id    UUID REFERENCES interviews(id),
    role            TEXT NOT NULL,
    content         TEXT NOT NULL,
    phase           TEXT NOT NULL,
    extracted_data  JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now()
);
```

## 4.6 Deployments

```sql
CREATE TABLE deployments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    snapshot_id     UUID REFERENCES project_snapshots(id),
    target          TEXT NOT NULL,
    provider        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    live_url        TEXT,
    build_log       TEXT,
    deployed_by     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ DEFAULT now(),
    completed_at    TIMESTAMPTZ
);
```

## 4.7 Vector Memory (pgvector)

```sql
CREATE TABLE project_memory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    chunk_type      TEXT NOT NULL,
    content         TEXT NOT NULL,
    embedding       vector(1536),
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_memory_embedding ON project_memory
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

\newpage

# 5. Subscription & Credit Engine

## 5.1 Plan Structure

| Plan | Monthly Price | Annual Price | Credits/Month | Key Features |
|------|-------------|-------------|--------------|--------------|
| **Free** | $0 | $0 | 10 | Core features, public projects only |
| **Standard** | $20 | $198/yr ($16.50/mo) | 100 | Private hosting, GitHub integration, buy extra credits |
| **Pro** | $200 | $2,004/yr ($167/mo) | 750 | 1M context window, custom agents, priority support |
| **Enterprise** | Custom | Custom | Custom | SSO, dedicated infra, SLA, audit logs |

## 5.2 Credit Economics

One credit equals one agent turn (one user message leading to a full agent response with tool execution).

**Cost per turn by model:**

| Model | Cost Per Turn | When Used |
|-------|-------------|-----------|
| Claude Sonnet 4 | ~$0.08 | Complex: new projects, architecture, debugging |
| GPT-4o | ~$0.06 | UI work, moderate edits |
| DeepSeek-V3 | ~$0.008 | Simple: renaming, style changes, small fixes |
| **Blended average** | **~$0.04** | Across all usage patterns |

**Revenue per credit:**

- Standard plan: $20 / 100 credits = $0.20 per credit
- Pro plan: $200 / 750 credits = $0.27 per credit
- **Gross margin: 80–85%**

## 5.3 Credit Deduction Flow

```
User sends message
        ↓
Check: team.credits_remaining > 0?
    ├── NO → Return HTTP 402, show upgrade modal
    ↓
    YES → Reserve 1 credit (optimistic deduction)
        ↓
Model Router selects model by task complexity
        ↓
Agent executes (multiple tool calls allowed per turn)
        ↓
On completion:
    • Record actual tokens in credit_transactions
    • If agent errored or produced nothing → refund credit
        ↓
Stream result to user via SSE
```

## 5.4 Stripe Integration Points

| Event | Action |
|-------|--------|
| `customer.subscription.created` | Create subscription record, set plan + credits |
| `customer.subscription.updated` | Update plan, adjust credits |
| `customer.subscription.deleted` | Downgrade to free, set credits to 10 |
| `invoice.payment_succeeded` | Reset monthly credits to plan allowance |
| `invoice.payment_failed` | Mark subscription as `past_due`, notify user |
| `checkout.session.completed` (one-time) | Add purchased credits to balance |

\newpage

# 6. Agent Runtime & Execution Loop

## 6.1 Context Window Assembly

Every agent turn assembles context in this priority order:

```
[SYSTEM] Project specification (immutable, always re-injected)
[SYSTEM] Current file tree (auto-refreshed from sandbox)
[SYSTEM] Active errors from last build attempt
[SYSTEM] Relevant memories from vector DB (semantic search)
[SYSTEM] User's plan tier capabilities and limits
─────────────────────────────────────────────────
[USER]   Last N messages (sliding window, N=10-20)
[ASST]   Last N agent responses
[TOOL]   Recent tool call results
```

## 6.2 Self-Correction Loop

```
Agent writes code (write_file / edit_file)
        ↓
Agent runs build: run_command("npm run build")
        ↓
    ┌── Build succeeds → continue to next task
    │
    └── Build fails → inject error into context
              ↓
        Agent analyzes error, fixes the file
              ↓
        Re-run build (retry counter +1)
              ↓
        If retry < 3 → loop back to fix
        If retry = 3 → ask user with error context
                        "I'm having trouble with X.
                         Here's what's happening: [error]
                         Can you help me decide what to do?"
```

## 6.3 Tool Definitions

**File Tools:**

| Tool | Parameters | Description |
|------|-----------|-------------|
| `write_file` | path, content | Create or overwrite a file |
| `edit_file` | path, search, replace | Surgical edit within a file |
| `read_file` | path | Read file contents |
| `delete_file` | path | Remove a file |
| `list_files` | directory | List files in directory |

**Terminal Tools:**

| Tool | Parameters | Description |
|------|-----------|-------------|
| `run_command` | command | Execute shell command, return stdout/stderr |

**Browser Tools:**

| Tool | Parameters | Description |
|------|-----------|-------------|
| `browser_preview` | url | Take screenshot, return to agent for visual verification |

**Deploy Tools:**

| Tool | Parameters | Description |
|------|-----------|-------------|
| `generate_dockerfile` | — | Generate optimized Dockerfile for the project |
| `deploy` | provider, config | Deploy to Vercel/Fly.io/Coolify |

**User Tools:**

| Tool | Parameters | Description |
|------|-----------|-------------|
| `ask_user` | question | Pause and ask user for input/decision |

## 6.4 Output Streaming

Every token and tool call is streamed to the frontend via Server-Sent Events:

| Event Type | Payload | UI Update |
|-----------|---------|-----------|
| `token` | `{text}` | Append to chat message |
| `tool_start` | `{name, args}` | Show "Running: write_file..." indicator |
| `tool_result` | `{name, result}` | Update file tree, show terminal output |
| `file_change` | `{path, action}` | Refresh file tree sidebar |
| `preview_ready` | `{url}` | Reload preview iframe |
| `error` | `{message}` | Show error state in chat |
| `done` | `{credits_used}` | Update credit counter |

\newpage

# 7. Intelligent Requirements Interview

## 7.1 The Problem

Non-technical users fail with AI app builders because:

1. They don't know HOW to describe what they want technically
2. They give vague prompts that produce poor results
3. They don't know what's POSSIBLE, so they can't ask for it
4. They forget critical requirements until it's too late

## 7.2 The Solution

A structured but natural conversation that extracts everything the agent needs to build the right app — without the user ever needing to think technically.

**Total: 10–15 questions, approximately 5 minutes.**
**Result: A complete specification that would take a developer 2 hours to write.**

## 7.3 Interview Phases

### Phase 1: THE SPARK — "What's the big idea?" (1–2 questions)

**Opening question (always the same):**

> "What do you want to build? Don't worry about technical details — just tell me the idea like you'd explain it to a friend."

The system classifies the response into an app archetype:

| Detected Archetype | Follow-up Question |
|---|---|
| Marketplace | "So people would list [items/services] and others would buy/book them?" |
| SaaS/Tool | "Would each customer have their own separate account with their own data?" |
| Content/Blog | "Will you be the only one publishing, or can others contribute too?" |
| E-commerce | "Are you selling physical products, digital downloads, or services?" |
| Internal Tool | "Is this just for your team, or will customers/partners use it too?" |
| Social/Community | "What's the main thing people DO here — post, chat, share, or collaborate?" |
| Portfolio/Landing | "Is this mainly to show information, or do visitors need to DO something?" |
| Booking/Scheduling | "What are people booking — appointments, rooms, equipment, or something else?" |

### Phase 2: THE AUDIENCE — "Who is this for?" (2–3 questions)

- **2a:** "Who are the main people using this?"
  - Extracts user roles without using that term
- **2b:** "Roughly how many users do you expect in the first few months?"
  - Determines scale requirements
- **2c (conditional):** "Should each company/team have their own separate space?"
  - Determines multi-tenancy needs

### Phase 3: THE JOURNEY — "Walk me through a typical day" (3–5 questions)

- **3a:** "A new customer arrives. What's the FIRST thing they should be able to do?"
- **3b:** "Now they're a returning customer. What do they come back for most?"
- **3c:** "On YOUR side — what do you need to see or manage daily?"
- **3d (conditional):** "Is there anything that needs to happen automatically?"

This naturally extracts onboarding flow, core CRUD operations, admin/dashboard needs, and automation requirements.

### Phase 4: THE DETAILS — "Let's nail down the specifics" (2–4 questions)

- **4a:** "What information do you need to keep track of?"
- **4b:** "Are there any rules I should know about?"
- **4c:** "Do you already use any tools for your business? Payments, email, calendar?"
- **4d (conditional):** "Do people need to sign up, or can they use it without an account?"

### Phase 5: THE LOOK — "How should it feel?" (1–2 questions)

- **5a:** Visual style selection with emoji cards:
  - 🎯 Clean and professional (like Stripe or Notion)
  - 🎨 Fun and colorful (like Canva or Duolingo)
  - 🖤 Dark and modern (like Linear or Vercel)
  - 🌿 Warm and friendly (like Airbnb or Etsy)
  - 📋 Simple and functional (like Google Docs)

Each maps to pre-built design tokens (fonts, colors, border radius, palette).

- **5b (optional):** "Do you have a brand color or logo?"

### Phase 6: THE PLAN — Confirmation

The system generates a visual spec card showing:

- App name and style
- What users can do (feature checklist)
- What admin can do (management features)
- Automatic behaviors (emails, notifications)
- Integrations (payments, email, etc.)

User either approves to start building, or requests changes (loops back to relevant phase).

## 7.4 Interview State Machine

```
States:
  SPARK     → Initial idea capture
  AUDIENCE  → User roles and scale
  JOURNEY   → Core workflows
  DETAILS   → Data, rules, integrations
  LOOK      → Visual preferences
  PLAN      → Show spec, await approval
  REVISION  → User wants changes
  APPROVED  → Start building

Transitions:
  SPARK    → has archetype?        → AUDIENCE
  AUDIENCE → has user roles?       → JOURNEY
  JOURNEY  → has 3+ workflows?     → DETAILS
  DETAILS  → has data model?       → LOOK
  LOOK     → has style?            → PLAN
  PLAN     → user approves?        → APPROVED
  PLAN     → user revises?         → REVISION → (relevant phase)
```

## 7.5 Spec Output Format

The interview produces TWO outputs:

1. **User-Facing Plan** — human-readable bullet points shown in the UI for approval
2. **Technical Spec (JSON)** — structured specification sent to the build agent containing: project name, archetype, tech decisions, design tokens, user roles, page definitions, data models, automations, business rules, and integrations

## 7.6 Smart Defaults

The system minimizes questions by making intelligent decisions:

| User Mentions | System Auto-Decides |
|---|---|
| "online store" / "sell" / "shop" | Stripe payments, product catalog, cart |
| "booking" / "appointment" | Calendar UI, time slots, confirmation email |
| "team" / "workspace" | Multi-user auth, permissions, shared data |
| "portfolio" / "showcase" | No auth needed, contact form |
| "dashboard" / "analytics" | Charts, date filters, data tables |
| "blog" / "content" | Markdown editor, categories, SEO |

\newpage

# 8. Cross-Platform Strategy

## 8.1 Three Levels of Cross-Platform

| Level | What It Means | Implementation |
|-------|--------------|----------------|
| The Platform itself | Users on any OS can use the builder | 100% browser-based web app |
| Generated Apps | Apps users build work on any OS | Containerized output + Capacitor for mobile |
| Development Environment | Your team develops on any OS | Node.js + Docker + pnpm |

## 8.2 Why Web-Only (Not Desktop)

Every successful AI builder (Emergent, Bolt.new, Lovable, Replit, v0.dev) is web-only because the code sandbox is cloud-based anyway, zero install means zero friction and higher conversion, one codebase avoids maintaining three OS builds, and instant updates avoid Electron auto-update complexity.

A Progressive Web App (PWA) manifest provides the "installed app" feel on all platforms with zero additional development effort.

## 8.3 Generated App Output Targets

| Target | Technology | Platforms |
|--------|-----------|-----------|
| **Web (default)** | Next.js → Docker container | Any browser, any OS |
| **Mobile** | Same code + Capacitor.js wrapper | iOS + Android |
| **Desktop PWA** | PWA manifest (auto-generated) | Windows, macOS, Linux, ChromeOS |
| **Self-hosted** | Docker container export | Any server with Docker |

## 8.4 Cross-Platform Development Toolchain

Every tool works identically on Windows, macOS, and Linux:

| Tool | Purpose |
|------|---------|
| Node.js 22 | Runtime |
| Bun | Fast bundler + API runtime |
| pnpm | Package manager + workspace management |
| Docker | Database + Redis + sandbox containers |
| Turborepo | Monorepo build orchestration |
| VS Code | Editor (with devcontainer support) |
| GitHub Actions | CI/CD (Linux runners) |

## 8.5 Deployment (OS-Agnostic)

All services run as Linux containers, deployable to any cloud:

| Component | Budget | Scale | Enterprise |
|-----------|--------|-------|-----------|
| Frontend | Vercel (free) | Vercel Pro ($20/mo) | Cloudflare Pages |
| API | Railway ($5/mo) | Fly.io ($10/mo) | Azure Container Apps |
| Database | Neon (free 0.5GB) | Supabase Pro ($25/mo) | Azure DB for Postgres |
| Redis | Upstash (free) | Upstash Pro ($10/mo) | Azure Cache for Redis |
| Blob Storage | Cloudflare R2 (free 10GB) | R2 ($0.015/GB) | Azure Blob Storage |
| Sandboxes | E2B ($0.05/min) | E2B ($0.05/min) | Self-hosted Firecracker |

\newpage

# 9. Enterprise Readiness

| Requirement | Implementation |
|---|---|
| **SOC 2 Type II** | Audit logs on every action, AES-256 encryption at rest, TLS 1.3 |
| **Multi-tenancy** | Team-based isolation, row-level security in Postgres |
| **SSO** | SAML 2.0 + OIDC via Auth0 or Entra ID |
| **Data Residency** | Regional sandbox clusters (US, EU, APAC) |
| **SLA** | 99.9% for Pro, 99.95% for Enterprise |
| **Audit Trail** | Every agent action logged: who, what, when, model, tokens |
| **IP Allowlisting** | Enterprise customers restrict by IP range |
| **Code Ownership** | Users own 100% of generated code, exportable via GitHub or download |
| **RBAC** | Owner, Admin, Member, Viewer roles with granular permissions |

\newpage

# 10. Build Phases & Roadmap

## Phase 1: Foundation (Weeks 1–3)

**Deliverable:** User signs up, chats with agent, sees files created.

- Authentication (Google + GitHub + email via Auth.js)
- PostgreSQL schema: users, teams, subscriptions, projects, conversations, messages
- Platform API: project CRUD, conversation endpoints
- Agent runtime: single model (Claude) + 3 tools (write_file, run_command, read_file)
- Sandbox: Docker container per project (local development)
- Frontend: Chat panel with SSE streaming + file tree sidebar
- Free tier: 10 credits, no billing integration yet

## Phase 2: Live Experience (Weeks 4–6)

**Deliverable:** User watches app being built live with preview.

- Live preview iframe (proxy to sandbox port 3000)
- Monaco code editor (read-only, inspect generated code)
- Browser tool (Playwright screenshot → agent visual verification)
- Self-correction loop (build error → auto-fix → retry)
- Project persistence (resume across sessions via snapshots)
- Model router: Claude primary, DeepSeek for simple tasks
- Credit tracking (in-memory, no billing yet)

## Phase 3: Monetization (Weeks 7–9)

**Deliverable:** Users pay, credits tracked, tiers enforced.

- Stripe integration: subscriptions + credit top-ups
- Credit engine: deduction per turn, refund on failure
- Plan enforcement: context window limits, model access by tier
- GitHub integration: push generated code to user's repo
- Project forking: clone someone's public project
- Team management: invite members, RBAC
- Landing page + pricing page
- **Requirements Interview system (the killer feature)**

## Phase 4: Production & Scale (Weeks 10–12)

**Deliverable:** Deployed, monitored, SOC 2-ready.

- One-click deploy: Vercel/Fly.io/Coolify integration
- Custom domain support for deployed apps
- E2B migration (Docker → E2B microVMs for isolation + speed)
- Observability: OpenTelemetry traces, Grafana dashboards
- Rate limiting + abuse prevention
- Vector memory (pgvector): agents remember project decisions
- Template gallery: "SaaS starter", "Blog", "E-commerce", etc.
- Enterprise SSO (SAML/OIDC)
- Audit logging for SOC 2 compliance

\newpage

# 11. Cost Projections

## At 10,000 Paying Users

**Revenue:**

| Segment | Users | Price | Monthly Revenue |
|---------|-------|-------|----------------|
| Free | 5,000 | $0 | $0 |
| Standard | 3,500 | $20/mo | $70,000 |
| Pro | 1,200 | $200/mo | $240,000 |
| Enterprise | 300 | $500/mo (avg) | $150,000 |
| **Total** | **10,000** | | **$460,000/mo** |

**Costs:**

| Item | Calculation | Monthly Cost |
|------|------------|-------------|
| LLM API (Standard) | 3,500 × 100 turns × $0.04 | $14,000 |
| LLM API (Pro) | 1,200 × 750 turns × $0.04 | $36,000 |
| LLM API (Enterprise) | 300 × 1,000 turns × $0.04 | $12,000 |
| E2B sandboxes | Per-second billing | $8,000 |
| PostgreSQL (managed) | | $2,000 |
| Redis | | $500 |
| Blob storage | | $1,000 |
| CDN + bandwidth | | $1,500 |
| **Total Cost** | | **$75,000/mo** |

**Gross Margin: $385,000/mo (83.7%)**

\newpage

# 12. Key Architectural Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Single agent vs multi-agent | **Single agent with tools** | Coordination overhead between multiple models dominates. One powerful model with good tools produces better results faster and cheaper. |
| Credit-based vs time-based billing | **Credits (per turn)** | Predictable costs for both user and platform. Emergent validated this model at 3M+ users. |
| Sandbox technology | **E2B MicroVMs** | Sub-second cold start, per-second billing, network isolation. Docker is fallback for self-hosted development. |
| Database | **PostgreSQL + pgvector** | Single database for relational + vector data. No need for separate Pinecone or Weaviate. |
| Model strategy | **Multi-model router** | Claude for complex tasks, DeepSeek for simple ones. 60% cost reduction vs Claude-only. |
| Real-time streaming | **SSE (not WebSocket)** | Simpler, works through CDNs/proxies, auto-reconnect built into EventSource API. |
| Frontend framework | **Next.js 15 App Router** | Server components for streaming, proven at scale, instant Vercel deployment. |
| Deploy targets | **Vercel + Fly.io + Coolify** | Covers all segments: Vercel (simple), Fly.io (containers), Coolify (self-host enterprise). |
| Desktop strategy | **PWA (not Electron/Tauri)** | Zero install, zero OS-specific builds, auto-update, identical experience everywhere. |

\newpage

# 13. Risk Mitigation

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|-----------|
| **Agent context drift** | High | Medium | Re-inject original spec as immutable system context every turn |
| **API contract conflicts** | Medium | High | OpenAPI spec as source of truth; agent validates against it |
| **Infinite fix loops** | High | Medium | Hard cap at 3 retries per task; escalate to user on 4th failure |
| **Token cost explosion** | Medium | High | Context slicing: each turn only gets relevant files + last N messages; use pgvector for retrieval |
| **Sequential slowness** | Medium | Medium | Parallelize independent tasks; only block at contract sync points |
| **Sandbox escapes** | Low | Critical | E2B microVMs with network isolation; no host mounts; ephemeral containers |
| **LLM provider outage** | Low | High | Multi-model router with automatic fallback chain: Claude → GPT-4o → DeepSeek |
| **User data loss** | Low | Critical | Auto-snapshot before every deployment; S3 backup with versioning |
| **Stripe webhook failures** | Medium | Medium | Idempotent webhook handlers; reconciliation job runs hourly |
| **Interview abandonment** | Medium | Low | Save interview state; resume on next visit; email reminder after 24h |

---

*Document Version: 1.0*
*Last Updated: April 2026*
*Author: Dhruv Goyal*
