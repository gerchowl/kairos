# Self-host hardening — containers

The operator checklist that the automated gates cannot do. Kairos is
dependency-light and has no opinion about your infrastructure, so the things
below are *your* decisions; this file states them so they are decisions rather
than omissions. It accompanies the `Dockerfile` and the three compose files
(`compose.yaml`, `compose.mysql.yaml`, `compose.proxy.yaml`), added by #35 to
close **D3** (image wraps the same uvicorn app) and **D4** (secure default
topology + checklist).

The gate references below point at the obligations register
(`docs/design/productization-obligations.md`) so a failure has an owner.

---

## 0. Pick a topology before anything else

| File | Topology | Reachability | Auth |
|---|---|---|---|
| `compose.yaml` | SQLite on a named volume | `127.0.0.1` only | `demo` (one shared owner, none) |
| `+ compose.mysql.yaml` | MariaDB | `127.0.0.1` only | `demo` |
| `compose.oidc.yaml` | SQLite + Caddy + **Kairos as the OIDC client** | `0.0.0.0:80/443` | `oidc` + subject allowlist |
| `compose.proxy.yaml` | SQLite + Caddy + oauth2-proxy | `0.0.0.0:80/443` | `header` + allowlist |

`demo` mode has **no identity check at all**. Every user is the same owner and
can create, edit and delete every poll. That is fine on loopback and is a
disaster on any interface you do not exclusively control. If in doubt, use
`compose.oidc.yaml`.

```sh
cp .env.example .env      # then fill it in; compose refuses to start on missing secrets
podman compose -f compose.yaml up -d           # local trial
podman compose -f compose.oidc.yaml up -d      # anything real; Kairos terminates OIDC
podman compose -f compose.proxy.yaml up -d     # real; oauth2-proxy terminates OIDC
```

Both real topologies publish **only Caddy**, so §1 and §2 apply to each; the
difference is solely *where* OIDC terminates. See [oidc-login.md](oidc-login.md)
§0 for which to pick, §4 for per-provider client registration, and §6 for what is
and is not proven about the OIDC path. **Both files are standalone, not
overlays** — see the note at the top of `compose.proxy.yaml`: an overlay
resurrects `compose.yaml`'s published app port and defeats the allowlist.

`.env` is gitignored **and** excluded from the Docker build context, so a
session secret lives in one place and never reaches a layer or a commit (S4).

---

## 1. S5 — TLS everywhere, no plaintext transport

- [ ] **`compose.proxy.yaml` publishes only Caddy** (80/443). Verify, do not
      assume: `podman compose -f compose.proxy.yaml ps` must show no port
      mapping on the `kairos` service. It has `expose: 8003`, never `ports`.
- [ ] `KAIROS_PUBLIC_URL` is set to the public origin. Share links, invite links
      and `.ics` deep links are built from it; unset, Kairos derives one from
      request headers, which is wrong behind a proxy.
- [ ] The ACME contact address (`ACME_EMAIL`) is monitored. Caddy warns before
      a certificate expires; nobody reads container logs on a Sunday.
- [ ] Back up the `caddy-data` volume. Losing it means re-acquiring
      certificates, against rate limits you cannot see.
- [ ] If you front Kairos with something *other than* these two compose files, the
      TLS obligation is now yours (CHECKLIST enforcement mode) — nothing in
      Kairos can enforce it.

## 2. S1 — owner identity comes only from a trusted boundary

In `KAIROS_AUTH=header`, whoever can reach the app port can assert any identity,
including ownership of any poll. Two controls, both required:

- [ ] **The app port is not published** (see §1). This is the one that actually
      holds. Measured on this repo with rootless podman: a request arriving
      through a *published* port is presented to the app as coming from the
      forwarder's address inside the container's own network namespace, which on
      a pinned compose subnet is **inside** `KAIROS_TRUSTED_PROXY_CIDRS`. There
      is no allowlist value that fixes this, because the address depends on the
      engine's port-forwarding implementation. Unpublish the port.
- [ ] **`KAIROS_TRUSTED_PROXY_CIDRS` is set** and matches the pinned subnet in
      `compose.proxy.yaml` **or `compose.oidc.yaml`** (both pin
      `172.30.30.0/24`; change one, change the other). Fail-closed: a stale value
      presents as 403 on every page, which looks like a broken app rather than a
      security control. Check the app log for `rejected untrusted peer …` when it
      happens.
- [ ] Do not add `127.0.0.1` to the allowlist. Anything able to reach the app
      over loopback would then be trusted — including the host's own processes.
- [ ] **Keep `proxy_headers=False`.** The image's `CMD` runs the `kairos`
      console script, which sets it. If you replace the command with `uvicorn`
      directly, you must pass `--no-proxy-headers` yourself, or uvicorn rewrites
      the client address from `X-Forwarded-For` *before* Kairos sees it and the
      allowlist is checked against attacker input.

      Measured in-image, from inside the container (uvicorn only rewrites the peer
      for local peers, so a request over a published port cannot show the
      difference at all). `tests/probe_s1_bypass.py` runs this; CI runs both
      arms, so the check cannot pass vacuously:

      | command | `GET /new` + `X-Forwarded-For: 192.0.2.7` + `X-User: attacker` |
      |---|---|
      | `uvicorn … kairos.main:app` (uvicorn's default) | **200** — page renders as `attacker`; `POST /new` with the CSRF token from that page then **creates a poll owned by `attacker`** |
      | `uvicorn --no-proxy-headers …` | 403 |
      | the image's `CMD` (`kairos --host 0.0.0.0 …`) | 403 |

      It is `POST /new` and not `POST /api/polls`: the API surface is Bearer-key
      gated and its creator is the literal `"api"`, so it never reads an identity
      header and says nothing about header trust.
- [ ] Set `KAIROS_ALLOW` as a second, independent owner gate if your IdP is
      broader than your user list. Empty means any identity the IdP vouches for
      may own polls. (In `KAIROS_AUTH=oidc` the equivalent gate is
      `KAIROS_OIDC_ALLOWED_SUBJECTS`; `KAIROS_ALLOW` is inert there because no
      identity header is read, and Kairos warns if it is set.)

## 2a. S1 in `oidc` mode — the boundary moved, and which one is load-bearing

With Kairos terminating OIDC, **two** controls exist and they are not the same
control. Read the boot line to see which is doing what:

```
owner auth: oidc (issuer=…, allowlist=3 subject(s) + trusted-proxy CIDRs
  (edge only, not the identity boundary); …)
```

- [ ] **`KAIROS_OIDC_ALLOWED_SUBJECTS` (or `_ALLOWED_EMAIL_DOMAINS`) is set.** It
      is the control that decides who may own polls, it **denies by default**, and
      Kairos **refuses to boot** without one — so a running container is already
      proof it is set. See [oidc-login.md](oidc-login.md) §2.
- [ ] **`KAIROS_TRUSTED_PROXY_CIDRS` is still set** and still matches the pinned
      subnet. It no longer decides identity; it holds the edge, so only your TLS
      terminator can reach the app at all. Same fail-closed 403-on-every-page
      behaviour when it goes stale.
- [ ] `KAIROS_PUBLIC_URL` is set. It decides the redirect URI sent to the IdP and
      the `Secure` flag on the session cookie; unset, both fall back to request
      headers and the app warns at boot.
- [ ] **Run one real sign-in, and one rejected one.** The verifier is hand-rolled
      (see §6 of the OIDC guide for exactly what that does and does not cover),
      and a deny path nobody has ever exercised is not a deny path.
- [ ] Set `KAIROS_RATE_LIMIT=on` for anything reachable by people you do not
      know: `/oidc/start` and `/oidc/callback` are unauthenticated and each makes
      an outbound call per request.

## 3. S2 — `SESSION_SECRET`

- [ ] Set, and generated, and **not** in git. In `header` mode Kairos refuses to
      serve authenticated requests without it (observed as a 500 on every page,
      logged as `SESSION_SECRET is not configured`).
- [ ] Treat it as durable. Rotating it invalidates every session, every signed
      response-edit token and every invite signature in flight — respondents get
      signed out mid-poll and links 403. There is no re-issue path.
- [ ] `OAUTH2_PROXY_COOKIE_SECRET` likewise, and likewise backup-worthy.

## 4. Persistence (D5 — SQLite on a volume, #36)

- [ ] The DB is on a volume. `kairos.db` is written to the working directory,
      which the image sets to `/data`; the compose file mounts a named volume
      there. Check: `podman volume inspect kairos_kairos-data` and
      `podman exec <c> ls -l /data/kairos.db` should show uid 10001.
- [ ] **A fresh named volume inherits `/data`'s ownership (10001:10001) from the
      image**, so no chown step is needed. A **bind** mount is different: chown
      the host directory to 10001:10001, or run with
      `--user $(id -u):$(id -g)`, and on SELinux hosts add `:Z`.
- [ ] **That inheritance only happens for a volume that does not exist yet.** An
      *existing* volume with the wrong ownership is **not** re-chowned, and there
      is no entrypoint running as root to fix it, so the container crash-loops
      with `sqlite3.OperationalError: unable to open database file` in the log
      and `podman compose ps` shows `restarting`. Reproduced, and it is the
      first thing to check for any "the container will not stay up" report:

      ```sh
      podman run --rm -v <volume>:/data alpine ls -ldn /data   # expect 10001:10001
      # fix, if the contents are disposable:
      podman volume rm <volume>            # recreated with correct ownership
      # fix, if they are not:
      podman run --rm -u 0 -v <volume>:/data alpine chown -R 10001:10001 /data
      ```

      A volume created by an older run of a different uid, or by `docker` on the
      same host, is the usual way to land here.
- [ ] Back up by copying the volume, not by copying a live file:
      `podman run --rm -v kairos_kairos-data:/data -v "$PWD":/backup alpine \
       tar czf /backup/kairos.tgz -C /data .`
- [ ] `podman compose down` keeps the volume. `down -v` deletes every poll.
- [ ] **SQLite runs in rollback-journal mode; there is no WAL tuning in
      `dbconn.py` today.** That is fine for one always-on instance. It is the
      wrong shape for more than one writer or for scale-to-zero. PLAN.md tracks
      this; do not put two app containers on one volume.
- [ ] On a 1 GB disk, prune. There is no retention job yet (P3 is #32), so a
      long-lived instance grows until it does not.

## 5. M1/M5 — outbound mail (if you enable it)

- [ ] If you turn on `KAIROS_IMIP` or SMTP sending, send from a domain you
      control with SPF + DKIM + DMARC set. Never a personal mailbox (M1).
- [ ] Use a non-Gmail ORGANIZER address if you want native iMIP RSVP in Gmail —
      Gmail does not render accept buttons for a Gmail-organized event (M5); the
      deep-link fallback still works.
- [ ] `KAIROS_IMIP_ORGANIZER` must equal `KAIROS_IMAP_MAILBOX`. Mismatch = the
      reply mailbox is not the one being polled.

## 6. Abuse surface

- [ ] If this is reachable by anyone you do not know, the register's hard gate is
      **A1–A3** (Turnstile, verified creator, rate limits — issues #31, #37) plus
      **S6** (#29) and **M1** (§5). None of those are in this image; an exposed
      instance is an open mail relay until they are.
- [ ] Set `KAIROS_API_KEY` or leave it empty. Empty disables the Bearer-key API
      surface; it does not disable the public poll pages.

## 7. Cookies and consent (P1/P4)

- [ ] Kairos sets only strictly-necessary cookies and needs no consent banner.
      **That stops being true the moment you add a third-party embed** — most
      likely Cloudflare Turnstile once #31 lands. If you add one, either put it
      behind a click-to-load facade or add the banner and update `/privacy`.

## 8. Supply chain

- [ ] The image installs the exact closure in `uv.lock` (`uv sync --locked`), so
      the CI `audit` job (`pip-audit` over that lock) covers what ships. If you
      re-resolve at build time, that coverage no longer applies.
- [ ] `.env` is in `.dockerignore`; confirm it never reached a layer:
      `podman history --no-trunc <image>` and look for it.
- [ ] Pin or vendor the base image if your policy requires digest pinning. The
      image does **not** pin a digest — see §9.

## 9. Decisions this image deliberately did not make

Flagged, not chosen. All four are reversible without touching the app.

| Decision | Default taken here | Alternatives |
|---|---|---|
| **Base image family** | `python:3.12-slim-bookworm` — glibc CPython, has a shell for `podman run --rm -it <img> sh`, same family as `uvx kairos` | Alpine (musl; ~60 MB total, but a different libc and a rebuild to trust); `gcr.io/distroless/python3-debian12` (55 MB base, no shell at all, so no interactive debugging and no `/etc/passwd`-style tooling) |
| **Registry / publication** | none — `compose.yaml` builds locally and tags `localhost/kairos:local` | push to GHCR/quay; needs a release workflow, credentials and an `org.opencontainers.image.version` label kept in step with the release-please version |
| **Retention** | none — polls live until you delete them | a prune job (P3 / #32); the hosted target needs a window anyway (PLAN.md: 7–10 days fits D1's 500 MB) |
| **TLS termination** | Caddy in `compose.proxy.yaml` | nginx/traefik/ingress-controller; the only hard requirement is that identity headers reach the app and the app port is unpublished |

Two smaller ones, same category:

- **No digest pinning** on the base or on `ghcr.io/astral-sh/uv`. Both move.
- **`apt` remains in the runtime layer.** There is no compiler, no `make`, no
  `pip` anywhere, and no `curl`/`wget`/`git` — but the Debian base ships a package
  manager, which is how you would patch an OS CVE in a derived image. A distroless
  swap removes it and also removes the ability to patch in place.
- **Base-image OS CVEs are not audited by this repo.** The `audit` CI job is
  `pip-audit` over `uv.lock` — the Python dependency tree and nothing else. It
  says nothing about Debian's own packages. If that matters to you, scan the
  image (Trivy/Grype) in your own pipeline, or take the distroless option.

## 10. Verification you can repeat

```sh
podman build -t kairos:test .
podman run --rm -p 127.0.0.1:8003:8003 -v kairos-verify:/data kairos:test
curl -sf http://127.0.0.1:8003/health          # {"status":"ok","app":"kairos"}

# non-root?
podman exec <c> id                             # uid=10001(kairos) gid=10001(kairos)

# persistence? create a poll, `podman rm -f`, run again with the same volume.
```

CI runs the first two on every PR (obligation D3, "CI (image boots + probes)").
