# Browser session tokens

## Goal

Let a browser open one sandbox's terminal and `private` preview URLs
without holding an API key.

## Design

- `POST /v1/sandboxes/{id}/session-tokens` (`sandboxes:write`) returns an
  HS256 JWT and `expires_at`. `ttl_s` is 1 to 900 (default 900).
- Claims: `sub` (sandbox), `tenant`, `kid` (issuing key), `iat`, `exp`,
  `jti`. Only the fixed `{"alg":"HS256","typ":"JWT"}` header is accepted.
- The key is `<data-dir>/session.key` (32 random bytes, mode 0600) on the
  primary or single host. The primary sends it in the fleet config, so
  workers check tokens for calls and previews forwarded to them.
- A token is accepted only if the issuing key is still active, so revoking
  the key ends its tokens.
- Terminal: `GET /v1/sandboxes/{id}/pty` takes the token as
  `?session_token=` or as a bearer token. No other route accepts it.
- Private preview: `?spawnbox_session=<token>` is traded for an HttpOnly
  `spawnbox_session` cookie and a redirect without the parameter. The
  cookie is checked on each request and removed on every port, so apps
  never see it.
- Each token records `sandbox.session_token_created` with its `jti`.

## Test

Unit: sign and verify, expiry, wrong key, tampered claims, `alg: none`.

Live, on a primary and a worker:

- Terminal by query and by bearer token on both hosts.
- Refused: other API routes, another sandbox, tampered, expired, and a
  revoked key's token.
- Private preview: link to cookie redirect, cookie opens the app, the app
  does not see the session cookie, bad cookie and another sandbox's link
  refused.
- `token` previews still work.
