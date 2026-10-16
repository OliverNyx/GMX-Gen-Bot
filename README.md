# GMX registration bot (HTTP/2, Go only)

Pure **Go** client that replays the **GMX.com signup** API flow captured in `gmx.com.har`. No Chromium, Playwright, or Selenium.

## HAR flow (reviewed)

| Step | Method | URL | Notes |
|------|--------|-----|--------|
| 1 | GET | `https://signup.gmx.com/` | SPA shell; embeds CaptchaFox site key `sk_…` |
| 2 | GET | `https://signup.gmx.com/account/configuration` | Returns `{"captcha":"CAPTCHA_FOX"}` |
| 3 | POST | `https://register-suggest.gmx.com/rest/email-alias/availability` | Check `@gmx.com` alias |
| 4 | POST | `https://mam-api.captchafox.com/captcha/.../challenge` + `/captcha/verify` | **Encrypted binary** bodies from browser WASM/JS |
| 5 | POST | `https://signup.gmx.com/account/email-registration` | Header `cf-captcha-response: MAM_…` |
| 6 | POST | `https://login.gmx.com/login` | Form login after 204 registration |

All signup API calls in the HAR use **HTTP/2.0**.

### CaptchaFox + Capzy (default)

GMX uses the **MAM** CaptchaFox build; tokens must be **`MAM_…`**. Set **`CAPZY_API_KEY`** — the bot calls [Capzy](https://capzy.ai/docs) `CaptchaFoxTask` with the **same proxy** as signup (`apiServer` = MAM package path from the signup page).

Optional: local **[CapSkip](https://capskip.com/api-docs/)** with `-no-capskip=false`, or `-captcha-token` / `CAPTCHA_TOKEN` for a manual token.

## Features

- Forced **HTTP/2** TLS transport (`golang.org/x/net/http2`)
- HTTP proxy via **`proxy.txt`** (one `host:port:user:pass` per line), `PROXY=…`, or `PROXY_*` env vars. With a file, the bot tries random lines until GMX signup+configuration succeed (`-proxy-max-tries`, default 40).
- Per-run **browser fingerprint** (`User-Agent`, `sec-ch-ua*`, template `A`/`B`)
- Random **US identity**: name, birth date, state, **E.164 US mobile**
- New **`x-ccguid`** per account (matches HAR `iid` on login)
- **New IP per account** (default): each run generates a fresh iProyal `_session-<id>` in the proxy password (`-rotate-proxy-session=true`)

## Setup

```bash
cd "C:\Projects\GMX gen bot"
go mod tidy
go build -o gmxgen.exe ./cmd/gmxgen
```

Copy `.env.example` to `.env` and set proxy credentials (do not commit `.env`).

## Usage

Dry run (identity + fingerprint only):

```bash
.\gmxgen.exe -dry-run
```

Register:

```bash
set CAPZY_API_KEY=capzy_...
set PROXY_USER=...
set PROXY_PASS=...
.\gmxgen.exe
```

Flags: `-capzy-key`, `-capskip-url`, `-captcha-token`, `-no-capskip`, proxy flags, `-skip-login`, `-seed`.

## Output

JSON to stdout with email, password, mobile, HTTP status codes, and last protocol (`HTTP/2.0`).

## Legal

Automating account creation may violate GMX terms of service. Use only where you have permission.
