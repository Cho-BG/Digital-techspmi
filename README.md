# SPMI Modern

Express application deployed as one Vercel Function, backed by Supabase PostgreSQL.

## Supabase setup

1. Create a Supabase project and run `supabase/migrations/001_initial_schema.sql` in the SQL editor. The migration is idempotent.
2. Copy `.env.example` to `.env` for local development and set `DATABASE_URL` to the Supabase transaction-pooler URL (port 6543). Keep `DATABASE_POOL_SIZE=1` on Vercel unless your Supabase connection budget supports a higher per-instance limit.
3. Set stable `SESSION_SECRET` and `TEACHER_PASSWORD_VAULT_KEY` values. Vercel production refuses to start without both. Local development creates ignored stable key files when they are omitted.
4. For an empty database, set `ADMIN_INITIAL_PASSWORD` and run `npm run admin:create`. Login is `admin/dpk`.
5. Run `npm start` and open `http://localhost:3000`.

## Existing SQLite data

Apply the schema first, set `DATABASE_URL`, back up both databases, then run from this directory:

```bash
npm run migrate:supabase -- ../Supabase/data.db --replace
```

The utility truncates application tables, copies matching SQLite columns while preserving IDs, reports and skips orphaned dependent rows, clears invalid nullable references, and resets PostgreSQL identity sequences. Run it once before accepting writes in production.

## Vercel deployment

Import this directory into Vercel and add `DATABASE_URL`, `SESSION_SECRET`, and `TEACHER_PASSWORD_VAULT_KEY` to Production environment variables. Deploy after applying the SQL migration and migrating data or creating an admin. `vercel.json` routes both static UI and API requests through the initialized Express handler; uploads are memory-only and limited to 4 MB to stay below Vercel's request-body limit.

Use Supabase's pooled URL for serverless traffic, not the direct database URL. The app does not run schema DDL during cold starts.
