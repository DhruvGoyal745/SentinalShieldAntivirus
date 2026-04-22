# Feature: Intelligent Requirements Interview

## The Problem

Non-technical users fail with AI app builders because:
1. They don't know HOW to describe what they want technically
2. They give vague prompts ("build me a business app") that produce garbage
3. They don't know what's POSSIBLE, so they can't ask for it
4. They forget critical requirements (auth, payments, mobile) until it's too late

## The Solution: Conversational Requirements Gathering

A structured but natural conversation that extracts everything the agent
needs to build the right app — without the user ever needing to think
technically.

---

## Interview Flow Architecture

```
User clicks "New Project"
         │
         ▼
┌─────────────────────────┐
│  Phase 1: THE SPARK     │  "What's the big idea?"
│  (1-2 questions)        │  Understand the core concept
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Phase 2: THE AUDIENCE  │  "Who is this for?"
│  (2-3 questions)        │  Users, scale, access model
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Phase 3: THE JOURNEY   │  "Walk me through a typical day using this"
│  (3-5 questions)        │  Core workflows, features
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Phase 4: THE DETAILS   │  "Let's nail down the specifics"
│  (2-4 questions)        │  Data, integrations, business rules
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Phase 5: THE LOOK      │  "How should it feel?"
│  (1-2 questions)        │  Style, brand, examples
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│  Phase 6: THE PLAN      │  "Here's what I'll build"
│  (confirmation)         │  Show spec, get approval
└────────────┬────────────┘
             │
             ▼
     Agent starts building
```

## Total: 10-15 questions, ~5 minutes
## Result: A complete spec that would take a developer 2 hours to write

---

## Phase-by-Phase Question Design

### Phase 1: THE SPARK (Understand the Core Idea)

Goal: Get from vague to concrete in 1-2 exchanges.

**Opening question (always the same):**
> "What do you want to build? Don't worry about technical details —
>  just tell me the idea like you'd explain it to a friend."

**Follow-up (AI-generated based on response):**
The system classifies the response into an app archetype and asks ONE
clarifying question:

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

**Example exchange:**
```
User: "I want to build something for my bakery"

AI: "Love it! So is this mainly for customers to order cakes and pastries
     online, or more of a website to showcase your bakery and attract
     foot traffic?"

User: "Customers should be able to order custom cakes and pick a
       delivery date"

AI: "Got it — a custom cake ordering system with delivery scheduling.
     Perfect. Let me ask a few more questions so I build exactly
     what you need."
```

### Phase 2: THE AUDIENCE (Who Uses This?)

Goal: Understand user types, scale, and access model.

**Question 2a:**
> "Who are the main people using this? For example, your [bakery] might
>  have customers placing orders AND you/your team managing those orders.
>  Who else might be involved?"

This extracts USER ROLES without using that term.

**Question 2b (conditional):**
> "Roughly how many [customers/users/team members] do you expect in the
>  first few months? Just a ballpark is fine."

| Response | System Infers |
|---|---|
| "Just me and 2 staff" | Small scale, simple auth, no multi-tenancy |
| "Maybe 100 customers" | Medium scale, need signup flow, basic dashboard |
| "Thousands" | Need pagination, search, performance planning |
| "Enterprise clients" | Multi-tenancy, SSO, admin portal |

**Question 2c (if B2B or teams detected):**
> "Should each [company/team/location] have their own separate space,
>  or does everyone share the same view?"

### Phase 3: THE JOURNEY (Core Workflows)

Goal: Extract the 3-5 main user workflows by having the user
tell a story.

**Question 3a:**
> "Let's walk through it. A new [customer] arrives at your app for the
>  first time. What's the FIRST thing they should be able to do?"

**Question 3b:**
> "Great. Now they're a returning [customer]. What do they come back to
>  do most often?"

**Question 3c:**
> "And on YOUR side — what do you need to see or manage on a daily basis?"

**Question 3d (if applicable):**
> "Is there anything that needs to happen automatically? For example,
>  sending a confirmation email, updating inventory, or reminding
>  someone about a deadline?"

This naturally extracts:
- Onboarding flow
- Core CRUD operations
- Admin/dashboard needs
- Automation/notification requirements

**Example:**
```
User: "Customer visits, browses cake designs, picks one, customizes
       it (flavor, size, message), picks a delivery date, and pays"

AI extracts:
  → Workflow 1: Browse catalog (gallery page with filters)
  → Workflow 2: Customize order (multi-step form)
  → Workflow 3: Schedule delivery (date picker with availability)
  → Workflow 4: Payment (Stripe checkout)
  → Workflow 5: Order confirmation (email + order tracking page)
```

### Phase 4: THE DETAILS (Data & Business Rules)

Goal: Nail down the specifics that differentiate this from a generic
template.

**Question 4a (data-focused):**
> "What information do you need to keep track of? For the bakery, I'm
>  guessing: cake designs, customer orders, delivery schedule. What else?"

**Question 4b (rules-focused):**
> "Are there any rules I should know about? Like: orders need 48 hours
>  notice, delivery only within 10 miles, no orders on Sundays?"

**Question 4c (integrations, asked simply):**
> "Do you already use any tools for your business? Things like:
>  - Taking payments (Stripe, Square, PayPal?)
>  - Sending emails (Mailchimp, Gmail?)
>  - A calendar or scheduling tool?
>  - Social media you'd want to connect?"

**Question 4d (conditional — only if relevant):**
> "Do you need people to sign up with an account, or should they be
>  able to [order/book/use it] without creating one?"

### Phase 5: THE LOOK (Visual Preferences)

Goal: Establish design direction without asking about CSS.

**Question 5a:**
> "How should your app feel? Pick the closest vibe:
>  🎯 Clean and professional (like Stripe or Notion)
>  🎨 Fun and colorful (like Canva or Duolingo)
>  🖤 Dark and modern (like Linear or Vercel)
>  🌿 Warm and friendly (like Airbnb or Etsy)
>  📋 Simple and functional (like Google Docs)"

This maps to pre-built design tokens:
| Choice | Tailwind Preset | Font | Radius | Palette |
|---|---|---|---|---|
| Clean/professional | Neutral grays | Inter | 8px | Blue accent |
| Fun/colorful | Vibrant | Poppins | 16px | Multi-color |
| Dark/modern | Dark mode | Geist | 6px | White accent |
| Warm/friendly | Earth tones | DM Sans | 12px | Warm orange |
| Simple/functional | Minimal | System | 4px | Gray accent |

**Question 5b (optional):**
> "Do you have a brand color or logo? If not, no worries — I'll
>  pick something that looks great."

### Phase 6: THE PLAN (Confirmation)

Goal: Show the user a human-readable summary and get approval.

The system generates a visual spec card:

```
┌─────────────────────────────────────────────────┐
│  📋 Your App Plan                                │
│                                                  │
│  NAME: Sweet Orders — Custom Cake Ordering       │
│  STYLE: Warm and friendly                        │
│                                                  │
│  WHAT USERS CAN DO:                              │
│  ✓ Browse your cake catalog with photos          │
│  ✓ Customize orders (flavor, size, message)      │
│  ✓ Pick a delivery date (48hr minimum)           │
│  ✓ Pay securely with Stripe                      │
│  ✓ Track their order status                      │
│  ✓ Create an account to reorder easily           │
│                                                  │
│  WHAT YOU CAN DO (Admin):                        │
│  ✓ Manage cake designs and prices                │
│  ✓ View and update order status                  │
│  ✓ See daily/weekly order summary                │
│  ✓ Block out dates when you're closed            │
│                                                  │
│  AUTOMATIC:                                      │
│  ⚡ Confirmation email on order                   │
│  ⚡ Reminder email day before delivery            │
│  ⚡ Low-stock alert when a design is popular      │
│                                                  │
│  INTEGRATIONS:                                   │
│  💳 Stripe (payments)                             │
│  📧 Email notifications                          │
│                                                  │
│  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Looks good!  │  │ I want to change a few   │  │
│  │ Start build  │  │ things first             │  │
│  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Technical Implementation

### Interview State Machine

```
States:
  SPARK       → Initial idea capture
  AUDIENCE    → User roles and scale
  JOURNEY     → Core workflows
  DETAILS     → Data, rules, integrations
  LOOK        → Visual preferences
  PLAN        → Show spec, await approval
  REVISION    → User wants changes (loop back)
  APPROVED    → Start building

Transitions:
  SPARK    → has_archetype?    → AUDIENCE
  AUDIENCE → has_user_roles?   → JOURNEY
  JOURNEY  → has_3+_workflows? → DETAILS
  DETAILS  → has_data_model?   → LOOK
  LOOK     → has_style?        → PLAN
  PLAN     → user_approves?    → APPROVED
  PLAN     → user_revises?     → REVISION → (relevant phase)
```

### System Prompt for Interview Agent

```
You are a friendly product consultant helping someone plan their app.

RULES:
1. Ask ONE question at a time. Never overwhelm with multiple questions.
2. Use the user's own words. If they say "bakery", you say "bakery",
   not "food service establishment".
3. Never use technical jargon. Say "sign up page" not "authentication
   flow". Say "payment" not "Stripe integration".
4. Offer examples from THEIR domain, not generic software examples.
5. If the user is vague, give 2-3 concrete options to choose from.
6. If the user doesn't know, make a smart default and say "I'll set
   it up like [X] — you can always change it later."
7. Keep it conversational. Max 3 sentences per response.
8. You are gathering requirements for phases: SPARK, AUDIENCE,
   JOURNEY, DETAILS, LOOK. Track which phase you're in.
9. When you have enough info, move to the next phase naturally.
10. After LOOK, generate the spec summary and show it for approval.

NEVER:
- Ask about databases, APIs, frameworks, or hosting
- Use words like "schema", "endpoint", "component", "deployment"
- Ask more than 15 questions total
- Let the interview take more than 5 minutes
```

### Spec Generation (Interview → Structured Output)

After the interview, the system generates TWO documents:

**1. User-Facing Plan (shown in UI):**
Human-readable bullet points (the spec card above)

**2. Technical Spec (sent to build agent):**
```json
{
  "project_name": "Sweet Orders",
  "archetype": "e-commerce",
  "tech_decisions": {
    "frontend": "nextjs",
    "backend": "nextjs-api-routes",
    "database": "postgres",
    "auth": "email-password",
    "payments": "stripe",
    "email": "resend"
  },
  "design": {
    "preset": "warm-friendly",
    "primary_color": "#F97316",
    "font": "DM Sans",
    "border_radius": "12px",
    "mode": "light"
  },
  "user_roles": [
    { "role": "customer", "auth": "signup", "count_estimate": "100-500" },
    { "role": "admin", "auth": "email-password", "count_estimate": "1-3" }
  ],
  "pages": [
    {
      "name": "Cake Catalog",
      "route": "/",
      "role": "customer",
      "description": "Grid of cake designs with photos, prices, and filter by category",
      "data": ["cakes"]
    },
    {
      "name": "Customize Order",
      "route": "/order/new",
      "role": "customer",
      "description": "Multi-step form: select cake → choose flavor/size/message → pick delivery date → checkout",
      "data": ["cakes", "orders"]
    },
    {
      "name": "Order Tracking",
      "route": "/orders/:id",
      "role": "customer",
      "description": "Order status timeline, delivery details, receipt",
      "data": ["orders"]
    },
    {
      "name": "Admin Dashboard",
      "route": "/admin",
      "role": "admin",
      "description": "Today's orders, weekly summary chart, pending orders list",
      "data": ["orders", "cakes"]
    },
    {
      "name": "Manage Cakes",
      "route": "/admin/cakes",
      "role": "admin",
      "description": "CRUD for cake designs with photo upload, pricing, availability toggle",
      "data": ["cakes"]
    },
    {
      "name": "Manage Schedule",
      "route": "/admin/schedule",
      "role": "admin",
      "description": "Calendar view to block dates, set delivery capacity per day",
      "data": ["schedule"]
    }
  ],
  "data_models": [
    {
      "name": "cakes",
      "fields": ["name", "description", "category", "base_price", "photo_url", "available"],
      "owner": "admin"
    },
    {
      "name": "orders",
      "fields": ["customer_id", "cake_id", "flavor", "size", "message", "delivery_date", "status", "total_price", "stripe_payment_id"],
      "owner": "customer",
      "statuses": ["pending", "confirmed", "baking", "ready", "delivered"]
    },
    {
      "name": "schedule",
      "fields": ["date", "is_blocked", "max_orders"],
      "owner": "admin"
    }
  ],
  "automations": [
    { "trigger": "order_created", "action": "send_confirmation_email" },
    { "trigger": "delivery_date_minus_1_day", "action": "send_reminder_email" },
    { "trigger": "order_count_high", "action": "notify_admin" }
  ],
  "business_rules": [
    "Orders require minimum 48 hours notice",
    "Delivery available within 10 miles only",
    "No orders accepted on Sundays"
  ],
  "integrations": ["stripe", "resend-email"]
}
```

This structured spec is what the BUILD agent receives. It's deterministic
and complete — no guessing required.

---

## Smart Defaults (Skip Questions When Possible)

The system should minimize questions by making intelligent defaults:

| If user says... | System auto-decides |
|---|---|
| "online store" / "sell" / "shop" | → Stripe payments, product catalog, cart |
| "booking" / "appointment" | → Calendar UI, time slots, confirmation email |
| "team" / "workspace" / "collaborate" | → Multi-user auth, permissions, shared data |
| "portfolio" / "showcase" | → No auth needed, static-ish, contact form |
| "dashboard" / "analytics" | → Charts, date range filter, data tables |
| "blog" / "content" | → Markdown editor, categories, SEO metadata |

When the system auto-decides, it TELLS the user:
> "Since you mentioned online orders, I'll set up secure card payments
>  with Stripe. Sound good?"

---

## Handling Edge Cases

### User is EXTREMELY vague
```
User: "I need an app"

AI: "I'd love to help! To get started, which of these sounds closest
     to what you need?

     🛒 An online store to sell products or services
     📅 A booking or scheduling system
     📊 A dashboard to track business data
     👥 A tool for your team to work together
     🌐 A website to showcase your brand
     💡 Something else — just describe it!"
```

### User gives a MASSIVE wall of text
```
The system:
1. Parses the text for all detectable requirements
2. Pre-fills as many phases as possible
3. Skips to the first phase with gaps
4. Says: "Wow, you've really thought this through! I picked up most
   of what you need. Let me confirm a few things..."
```

### User changes their mind mid-interview
```
User: "Actually, I don't want payments. Just a catalog."

AI: "No problem! I'll remove the payment part and keep it as a
     browsable catalog. Do customers still need to create accounts,
     or can anyone browse without signing up?"
```

### User asks a technical question
```
User: "Should I use React or Vue?"

AI: "I'll pick the best technology for your app — you won't need to
     worry about that part. I'll make sure it's fast, works on all
     devices, and is easy to update later. Is there anything else
     about how the app WORKS that you'd like to add?"
```

---

## Database Tables for Interview Feature

```sql
CREATE TABLE interviews (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id),
    user_id         UUID REFERENCES users(id),
    current_phase   TEXT NOT NULL DEFAULT 'spark',
    archetype       TEXT,
    completed_at    TIMESTAMPTZ,
    spec_json       JSONB,                   -- final structured spec
    created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE interview_messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interview_id    UUID REFERENCES interviews(id),
    role            TEXT NOT NULL,            -- 'user' or 'assistant'
    content         TEXT NOT NULL,
    phase           TEXT NOT NULL,            -- which interview phase
    extracted_data  JSONB DEFAULT '{}',       -- what was learned from this exchange
    created_at      TIMESTAMPTZ DEFAULT now()
);
```

---

## API Endpoints

```
POST /api/interviews
  → Creates a new interview, returns first question

POST /api/interviews/:id/respond
  Body: { "message": "user's answer" }
  → Returns next question OR spec summary

POST /api/interviews/:id/approve
  → Converts interview spec into project, starts build agent

POST /api/interviews/:id/revise
  Body: { "message": "I want to change the payment part" }
  → Routes back to relevant phase, returns follow-up question

GET /api/interviews/:id
  → Returns full interview state, messages, current phase, spec
```

---

## UI Components Needed

1. **Interview Chat Panel** — Same chat UI but with phase progress indicator
2. **Quick-Pick Cards** — Visual option cards for archetype selection (Phase 1)
3. **Style Picker** — Visual cards with color swatches for Phase 5
4. **Spec Summary Card** — The approval view with checkmarks and edit buttons
5. **Phase Progress Bar** — Shows "Step 3 of 6: Describing how it works"

---

## Metrics to Track

| Metric | Target | Why |
|---|---|---|
| Interview completion rate | >80% | Users shouldn't abandon mid-interview |
| Average questions asked | 10-12 | Fewer = better defaults; more = confusion |
| Time to spec approval | <5 min | Respect the user's time |
| Spec accuracy (user edits plan) | <20% edit rate | Interview should capture it right |
| Build success from spec | >90% | Spec quality directly impacts build quality |
