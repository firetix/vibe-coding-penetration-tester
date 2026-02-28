# Vercel environment variables (Next.js frontend)

Frontend package location: `vibehack-web/`

Set these environment variables in Vercel for the frontend project:

## Required

- `NEXT_PUBLIC_SUPABASE_URL`
  - Supabase project URL (example: `https://xyzcompany.supabase.co`)
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
  - Supabase anon/public key for client-side auth
- `NEXT_PUBLIC_API_BASE_URL`
  - Railway API base URL used by the frontend API client (example: `https://vibe-api-production.up.railway.app`)

## Recommended Supabase dashboard config

In Supabase Auth settings, add Vercel domains to allow auth redirects:

- Site URL: `https://<your-vercel-domain>`
- Redirect URLs:
  - `https://<your-vercel-domain>/login`
  - `https://<your-vercel-domain>/signup`
  - `http://localhost:3000/login` (local dev)
  - `http://localhost:3000/signup` (local dev)

## Local development

Copy `vibehack-web/.env.example` to `vibehack-web/.env.local` and fill real values.
