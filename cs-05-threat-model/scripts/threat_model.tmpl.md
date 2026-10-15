# STRIDE threat model: File Browser

**Target:** [filebrowser/filebrowser](https://github.com/filebrowser/filebrowser) at commit
`833d908884d5c801f30f5c098d7977177eb3a36b` (2026-07-28), about 15,600 lines of Go plus a Vue
frontend. A self-hosted web file manager with logins, file uploads, share links, a REST
API and an optional command runner.
**Method:** three parallel read-only subagents explored (1) architecture and trust
boundaries, (2) entry points and auth flows, (3) storage and secrets. Their reports were
merged here, and every `path:LINE` citation below was re-checked against the source
(`python scripts/check_citations.py <checkout>`). Findings are from static reading; nothing
was exploited or run. Where a claim is inferred rather than read, it says so.

## 0. Read this first: the project is end-of-life

On startup the server logs that File Browser "is being wound down" and was archived on
2026-09-01, "after which there will be no further releases and no security fixes"
([[cmd/root.go|being wound down]], [[cmd/root.go|no security fixes]]). Every unmitigated
threat below is therefore permanent for this codebase. The practical mitigation for the
whole model is to put the app behind a hardened reverse proxy, minimise what it can reach,
and plan a migration (T0).

## 1. Architecture and data-flow diagram

One Go process serves the SPA and a JSON API (gorilla/mux). State lives in a Bolt database;
files live on the host filesystem under a per-user scope. See the diagram; boundaries B1 to
B6 are explained in section 2.

```mermaid
flowchart LR
  subgraph Internet
    U[Browser / SPA]
    A[Anonymous visitor<br/>share link]
  end
  RP[Reverse proxy<br/>optional, TLS]
  subgraph Host["File Browser process"]
    H[HTTP server + mux<br/>CSP middleware]
    AU[Auth providers<br/>json / proxy / hook / none]
    API[API handlers<br/>resources, tus, raw,<br/>preview, search, shares]
    RUN[Command runner<br/>websocket + hooks]
    SFS[ScopedFs<br/>symlink confinement + rules]
  end
  DB[(Bolt DB<br/>users, settings,<br/>JWT key, shares)]
  FS[(Host filesystem<br/>user scope)]
  CACHE[(Preview cache<br/>+ tus state)]
  REDIS[(Redis<br/>optional)]
  OS[[Host OS<br/>exec.Command]]
  U -- "B1 HTTP(S)" --> RP
  A -- "B1 HTTP(S)" --> RP
  RP -- "B2 + identity header" --> H
  H --> AU
  AU --> DB
  H -- "B3 JWT / share hash" --> API
  API --> DB
  API -- "B4 scope" --> SFS --> FS
  API --> CACHE
  CACHE -.-> REDIS
  API -- "B5" --> RUN --> OS
  OS --> FS
```

## 2. Trust boundaries

| ID | Boundary | What changes | Evidence |
|---|---|---|---|
| B1 | Internet to listener | Plain TCP by default, TLS optional, unix socket possible with mode 0666 by default | [[cmd/root.go|"socketPerm", 0666]], [[cmd/root.go|os.Chmod(server.Socket]] |
| B2 | Reverse proxy to app | In proxy-auth mode the app trusts a username header from whoever connects | [[auth/proxy.go|r.Header.Get(a.Header)]] |
| B3 | Anonymous to authenticated | JWT (HS256, required expiry, 2 h) from `X-Auth`, or an `auth` cookie on GET only; user reloaded from DB each request | [[http/auth.go|X-Auth]], [[http/auth.go|WithExpirationRequired]], [[http/auth.go|d.user, err = d.store.Users.Get]], [[http/auth.go|time.Hour * 2]] |
| B3b | Share link to owner's files | Hash lookup, optional password or `?token=`, then runs as the share owner | [[http/public.go|link, err := d.store.Share.GetByHash]], [[http/public.go|!user.Perm.Share]] |
| B4 | User scope to host filesystem | `ScopedFs` resolves symlinks and rejects escapes unless `FollowExternalSymlinks` is set | [[files/scoped.go|func NewFs]], [[files/scoped.go|EvalSymlinks]] |
| B5 | App to spawned processes | Websocket commands and event hooks call `exec.Command`; off by default | [[cmd/root.go|"disableExec", true]], [[http/commands.go|exec.Command(command[0]]] |
| B6 | Normal user to admin | Admin-only user and settings routes; settings include shell and commands | [[http/settings.go|var settingsPutHandler = withAdmin]], [[http/users.go|NonModifiableFieldsForNonAdmin =]] |

Assets worth protecting: the files in each user's scope; the JWT signing key (one key signs
every user's token); password hashes (bcrypt, [[users/password.go|bcrypt.DefaultCost]]); share
tokens; the host itself (via the command runner).

## 3. Threats, ranked

Likelihood (L) and impact (I) are 1 (low) to 5 (high), judged for an internet-facing
instance with default settings unless noted. Risk = L x I.

| # | STRIDE | Threat | L | I | Risk |
|---|---|---|---|---|---|
| T0 | all | No security fixes will ever ship (project archived) | 5 | 4 | 20 |
| T1 | S | Login and share-password brute force: no rate limiting | 4 | 4 | 16 |
| T2 | S, E | Proxy-auth header spoofing impersonates any user, including admin | 3 | 5 | 15 |
| T3 | I | Admin password written to logs at first start | 3 | 4 | 12 |
| T4 | E | Command runner bypass or injection when exec is enabled | 2 | 5 | 10 |
| T5 | I, E | JWT signing key stored in plaintext in the DB (forge any token) | 2 | 5 | 10 |
| T6 | E, I | XSS steals the long-lived token (localStorage, non-HttpOnly cookie) | 2 | 5 | 10 |
| T7 | E, I | Symlink / TOCTOU escape from a user's scope | 2 | 5 | 10 |
| T8 | I | Share links: 48-bit ids, bypass token in the URL | 3 | 3 | 9 |
| T9 | R | No audit trail for successful actions | 4 | 2 | 8 |
| T10 | D | Few server timeouts and no quotas: slow-body and disk-fill DoS | 3 | 3 | 9 |
| T11 | I, T | Deployment defaults: weak Redis password, `latest` tags, plain HTTP, 0666 socket | 3 | 3 | 9 |
| T12 | T | Clickjacking: no frame-ancestors or X-Frame-Options | 3 | 2 | 6 |
| T13 | E | Stolen token cannot be revoked before it expires | 2 | 3 | 6 |

### T0. End-of-life project (cross-cutting)
**Evidence:** [[cmd/root.go|no security fixes]]. **Mitigation:** treat every other row as
unfixable upstream. Run it only behind an authenticating reverse proxy with network
restrictions, keep the container image pinned and rebuilt from a fork you control if you
must patch, and schedule a move to a maintained alternative.

### T1. Online password guessing (Spoofing)
`loginHandler` decodes the body and delegates to the configured authenticator with no
attempt counter, delay or lockout ([[http/auth.go|func loginHandler]]); a search of `http/`,
`auth/` and `cmd/` for limiter code found none. The only brakes are bcrypt cost, a minimum
password length of 12 ([[settings/settings.go|DefaultMinimumPasswordLength]]) and a
common-password list ([[users/password.go|commonPasswords]]). Share passwords have the same
gap: the bcrypt check at [[http/public.go|X-SHARE-PASSWORD]] is unthrottled. A dummy bcrypt
compare for unknown users ([[auth/json.go|dummyHash is used]]) does prevent username
enumeration by timing.
**Mitigation:** rate-limit `/api/login` and `/api/public/*` at the reverse proxy (per-IP
and per-username), alert on bursts of 401s, require long unique passwords for admins.

### T2. Proxy-auth header spoofing (Spoofing, Elevation)
In proxy mode the username comes straight from a configurable header
([[auth/proxy.go|r.Header.Get(a.Header)]]); unknown names are auto-created
([[auth/proxy.go|ErrNotExist]]) as non-admin without Execute ([[auth/proxy.go|Perm.Execute = false]]).
Auto-creation is safe-ish, but a header naming an existing admin logs the caller in as that
admin. Nothing in the code restricts which source IP may send the header.
**Mitigation:** do not enable proxy auth unless the app listens only on loopback or a
private network reachable solely by the proxy; make the proxy overwrite or strip the header
on every request; prefer the JSON auth method otherwise.

### T3. Initial admin password in logs (Information disclosure)
Quick setup without `--password` generates a password and prints it:
[[cmd/root.go|randomly generated password]]. Container log stores, CI logs and support
bundles then hold an admin credential.
**Mitigation:** pass a pre-hashed `--password` ([[cmd/root.go|hashed password for the first user]]),
or change the admin password on first login and purge the first log lines.

### T4. Command runner bypass or injection (Elevation of privilege)
Exec is disabled by default ([[cmd/root.go|"disableExec", true]]) and each command needs
`Execute` plus an allow-listed name ([[http/commands.go|!d.server.EnableExec || !d.user.Perm.Execute]],
[[http/commands.go|slices.Contains(d.user.Commands, name)]]). The allow-list checks only the first
parsed word ([[runner/commands.go|cmd = parts[0]]]). When a shell is configured the whole raw string is
handed to it ([[runner/parser.go|command = append(command, raw)]]), so by reading the code an input
such as `allowedcmd ; other` (spaces around the `;`) passes the name check and the shell runs both.
This was not exercised. Event hooks expand `$FILE`, `$DESTINATION` and `$USERNAME`, which hold
user-controlled names, and fall back to any environment variable
([[runner/runner.go|return os.Getenv(key)]]). Children inherit the full environment
([[runner/runner.go|os.Environ()]]), and the auth hook receives the plaintext password
([[auth/hook.go|PASSWORD=%s]]).
**Mitigation:** leave exec disabled; if needed, do not configure a shell, allow only fixed
binaries that accept no dangerous flags, and run the container with no secrets in its
environment and a read-only root filesystem.

### T5. Plaintext JWT key (Information disclosure, Elevation)
One 512-bit key signs all tokens ([[settings/settings.go|Key                   []byte]]) and is persisted
unencrypted in the Bolt settings bucket ([[storage/bolt/config.go|func (s settingsBackend) Save]]). The
database file is mode 0640 ([[cmd/utils.go|databasePermissions = 0640]]). Anyone who can read the DB or
a backup of it can mint an admin token, since tokens are validated only by signature and expiry
([[http/auth.go|WithExpirationRequired]]). There is no rotation mechanism that I found.
**Mitigation:** restrict the DB volume to the service user, exclude it from broad backups or
encrypt them, and rotate the key (re-initialise config) after any suspected exposure.

### T6. Token theft via XSS (Elevation, Information disclosure)
The SPA stores the JWT in `localStorage` ([[frontend/src/utils/auth.ts|localStorage.setItem]]) and in a
cookie set from JavaScript, so it cannot be HttpOnly ([[frontend/src/utils/auth.ts|document.cookie]]). Any script
execution in the app origin yields a 2 h admin-capable token. Uploaded files can be served inline
([[http/raw.go|"inline") == "true"]]), but that response carries `script-src 'none'` and nosniff
([[http/raw.go|script-src 'none']]), which blocks script from uploaded HTML or SVG; markup injection and
phishing pages remain possible. The server injects a JSON blob into the index page
([[http/static.go|template.JS]]); its escaping was not reviewed.
**Mitigation:** serve user content from a separate origin if you can, keep the CSP at the proxy
as well, shorten token lifetime, and review `static.go` escaping before trusting it.

### T7. Scope escape through symlinks (Elevation, Information disclosure)
`ScopedFs` is the main confinement and resolves symlinks before access
([[files/scoped.go|EvalSymlinks]]). The checks are path based, so a swap between check and use is a
theoretical TOCTOU (inferred, not demonstrated). The `FollowExternalSymlinks` option turns the
protection off entirely ([[files/scoped.go|if followExternal]]).
**Mitigation:** never enable the option; give the process a dedicated user who can read only the
served tree; mount that tree separately and avoid symlinks in it.

### T8. Weak share-link identifiers (Information disclosure)
Link ids are 6 random bytes ([[http/share.go|make([]byte, 6)]]), about 48 bits, which is a
large but enumerable space with no throttling (see T1). Password-protected links also have a
96-byte bypass token ([[http/share.go|make([]byte, 96)]]) accepted from the query string
([[http/public.go|ConstantTimeCompare]]), which leaks into proxy logs, browser history and Referer
headers. Expiry is enforced when links are read ([[share/storage.go|link.Expire != 0 && link.Expire <= time.Now().Unix()]]).
Shares re-check that the owner still has Share and Download rights, and re-root the file system
([[http/public.go|files.NewFs(d.user.Fs, basePath]]).
**Mitigation:** always set a password and an expiry on shares; strip query strings from proxy
logs; rate-limit `/api/public/`.

### T9. Weak audit trail (Repudiation)
Requests are logged only when the status is 400 or higher
([[http/data.go|status >= 400]]), with the client IP from `realip` ([[http/data.go|realip.FromRequest]]),
which trusts forwarding headers. Successful uploads, deletes, shares and settings changes leave no
record, so a malicious or compromised user cannot be traced.
**Mitigation:** log all state-changing requests at the reverse proxy (method, path, user, IP) and
ship them off-host.

### T10. Denial of service (Denial of service)
The server sets only a header-read timeout ([[cmd/root.go|ReadHeaderTimeout]]), so slow request
bodies are not bounded by the app. Resumable uploads are accepted up to a declared length
([[http/tus_handlers.go|cache.Register(file.RealPath()]]) with no per-user quota that I found (inferred).
**Mitigation:** set body and idle timeouts and size limits at the proxy, put the served tree on a
filesystem with quotas, and cap concurrent connections per IP.

### T11. Risky deployment defaults (Tampering, Information disclosure)
The sample compose file ships a fixed Redis credential
([[compose.yaml|FB_REDIS_CACHE_URL=redis://default:filebrowser]]), unpinned images
([[compose.yaml|filebrowser/filebrowser:latest]]) and a plain-HTTP published port
([[compose.yaml|8000:80]]). The unix socket defaults to mode 0666
([[cmd/root.go|"socketPerm", 0666]]). The image does run as a non-root user ([[Dockerfile|USER user]]).
**Mitigation:** change the Redis password, pin images by digest, terminate TLS in front, and set
`--socketPerm 0660`.

### T12. Clickjacking (Tampering)
The CSP is `default-src 'self'; style-src 'unsafe-inline';` ([[http/http.go|Content-Security-Policy]])
with no `frame-ancestors`, and no Go code sets X-Frame-Options or HSTS (searched all `*.go`
files). The app can be framed by another site.
**Mitigation:** add `X-Frame-Options: DENY` (or `frame-ancestors 'none'`) and HSTS at the proxy.

### T13. No token revocation (Elevation)
A stolen token works until it expires (2 h, [[http/auth.go|time.Hour * 2]]). Permissions are re-read
from the user record on each request, so deleting or demoting the user takes effect at once
([[http/auth.go|d.user, err = d.store.Users.Get]]), but there is no per-token revocation list.
**Mitigation:** keep token lifetime short and disable the user on suspected theft.

## 4. Things I checked that look fine
- JWT algorithm is pinned to HS256 and expiry is required ([[http/auth.go|WithExpirationRequired]]).
- Cookie auth is accepted on GET only, with state changes needing the custom header
  ([[http/auth.go|http.MethodGet]]); the cookie is `SameSite=Strict`.
- Signup is off by default and signed-up users are never admin or Execute
  ([[http/auth.go|!d.settings.Signup]], [[http/auth.go|Perm.Execute = false]]).
- Share list responses omit the password hash and bypass token ([[http/share.go|omits the server-side secrets]]);
  token compare is constant time ([[http/public.go|ConstantTimeCompare]]).
- Mutating resource routes require both a permission and a path-rule check
  ([[http/resource.go|!d.user.Perm.Create || !d.Check(r.URL.Path)]]).

## 5. Not verified
- Whether the preview cache ([[http/preview.go|func previewCacheKey]]) can serve one user's thumbnail to
  another; the key is the real path, mtime and size, and the order of the permission check versus the
  cache lookup was not traced.
- How `img/service.go` invokes external tools for thumbnails.
- Escaping in the Vue frontend (only `auth.ts` was read).
- Any behaviour at runtime; no exploit or dynamic test was attempted.
