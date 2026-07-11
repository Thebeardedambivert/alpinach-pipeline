# alpinach-pipeline

Automation pipeline for generating and approving Swiss real-estate social-media
captions. Built on **n8n** (workflow orchestration) + **Supabase** (Postgres +
Edge Functions). This repo holds the versioned, deployable artifacts only —
credentials live in the n8n/Supabase environments, never here.

## Layout

```
workflows/
  02-caption-generation.json   n8n: generate captions (GPT-4o) and insert posts
  03-approval-email.json        n8n: issue an approval token, email the agent
migrations/
  0007_approval_rate_limit.sql  Postgres: check_approval_rate_limit RPC + grants
functions/
  approval/index.ts             Supabase Edge Function: token-based approve/reject
```

## Flow (M2 scope)

1. **02 — caption generation.** Pulls property data, generates a caption per
   platform with GPT-4o, and inserts `pending_approval` posts into Supabase.
2. **03 — approval email.** Calls `issue_approval_token(property, 48h)`, which
   returns a raw token (only its SHA-256 hash is stored) and marks the property
   `ready`, then emails the agent Approve / Reject links via Resend.
3. **04 — approval handler** (`functions/approval/index.ts`). Public,
   unauthenticated Edge Function served at `/functions/v1/approval`. The token
   *is* the credential. **GET never mutates** (renders a confirmation page —
   mail scanners prefetch links); **POST** redeems the token, rate-limited by IP
   via `check_approval_rate_limit`, and hands approved posts to the publish step.

## Conventions

- n8n credentials are referenced by ID as `REPLACE_WITH_..._CREDENTIAL_ID`
  placeholders. Set the real IDs after importing a workflow — no secret is ever
  committed.
- The Edge Function reads all keys from the environment
  (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `PUBLISH_WEBHOOK_URL`).
- `.gitignore` excludes `.env*`, `*.key`, `n8n-config.json`, and
  `*credentials*.json`. Keep it that way.
