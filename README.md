# Corporate Email Signup

A small Node.js starter that only accepts registration from configured corporate email domains. The restriction is enforced on the server, and an account remains unusable until the email address is verified.

## Features

- Exact domain allowlist via `ALLOWED_EMAIL_DOMAINS`
- Email verification tokens with 30-minute expiry
- Password hashing with Node.js `scrypt`
- Signed, HTTP-only session cookies
- Basic per-IP rate limiting
- Atomic local JSON persistence for demos
- No runtime dependencies

## Run locally

```bash
cp .env.example .env
set -a && source .env && set +a
npm test
npm start
```

Open `http://localhost:3000`. During local development, the verification link is printed to the terminal when `DEV_SHOW_VERIFICATION_LINK=true`.

## Configure your domain

Set one or more comma-separated domains:

```env
ALLOWED_EMAIL_DOMAINS=example.com,subsidiary.example
```

The comparison is exact. Allowing `example.com` does not allow `sub.example.com` or lookalike domains.

## Before production

This repository is a secure learning starter, not a drop-in identity provider. Before production:

1. Replace the JSON store with PostgreSQL or another transactional database.
2. Connect a transactional email provider and send the verification link instead of logging it.
3. Put the app behind HTTPS and a trusted reverse proxy.
4. Store `SESSION_SECRET` in a secret manager and rotate it periodically.
5. Add CSRF protection, audit logging, account recovery, and organization-admin approval if required.
6. Consider a managed identity provider such as Microsoft Entra External ID, Auth0, Clerk, or Supabase Auth.

## Design references

The implementation follows widely used patterns from Node.js `crypto`/HTTP APIs and OWASP authentication guidance. It was written specifically for this repository rather than copied wholesale from another project. Related open-source authentication starters considered during research include Supabase's main repository and Auth0's B2B SaaS starter; those larger projects require external services, so this version keeps the core domain-registration logic runnable on its own.

## License

MIT
