# ct-hunter

Real-time detection of phishing infrastructure via Certificate
Transparency log monitoring, built to catch typosquatting domains
**before** they get weaponized, not after they show up in a public feed.

## Why this exists

Most phishing "detection" is actually aggregation: consuming a feed
(OpenPhish, PhishTank, VirusTotal) that already did the work of finding
and confirming a domain. That is useful, but it is not detection, and it
is not something worth putting in a portfolio as original work.

Every certificate issued for a public TLS domain gets logged to
Certificate Transparency within minutes, most attackers request one
immediately since browsers flag plaintext HTTP. That log is public and
streamable. Watching it directly means seeing a suspicious domain the
moment its certificate is issued, often before there is any content on
it at all, instead of waiting for someone else to notice the attack in
progress.

This project is the result of building that pipeline end to end: a
self-hosted Certificate Transparency firehose, a typosquatting engine
layered from cheap heuristics to fuzzy matching, external corroboration
before anything gets called "confirmed," and a Streamlit UI built for
actually triaging what comes out the other end, not just displaying it.
It has been run against live traffic since day one, which is also where
most of the interesting engineering problems came from: false positives
that only show up against real domains, a firehose that needs to run
for days without supervision, and a database written to from two
processes at once.

`docs/architecture.md` is a running decision log covering every design
choice and every bug found this way, written so each one can be
explained and defended on its own, not just "it works."

## What it demonstrates

- **A layered detection engine, not a single regex.** A precomputed
  variant index (O(1) lookup, generated at startup for every brand:
  omissions, repetitions, transpositions, homoglyphs, hyphenation, TLD
  swaps, brand+keyword combos) handles the common cases at firehose
  speed; a length-normalized Levenshtein ratio catches whatever the
  index does not anticipate; a separate DNS-label-boundary-aware check
  catches subdomain impersonation (`brand.com.attacker.net`), which a
  naive substring match gets wrong.
- **An explicit boundary between heuristics and verdicts.** The
  system's own scoring can prioritize and auto-triage, it can never
  auto-confirm a domain as malicious on its own. Only independent
  external corroboration (a public threat feed, VirusTotal above a
  vote threshold, URLscan's own verdict) or a human reviewing the
  evidence can do that. A cheap heuristic score is not proof, and the
  design does not pretend otherwise.
- **False positives found and fixed against real traffic, not test
  fixtures.** Every one of them, a CASB reverse proxy pattern
  (`*.office.com.mcas.ms`), a nested legitimate domain
  (`apple.com.cn`), short-domain edit distance false matches (`dhl.com`
  matching almost anything at distance 2), only surfaced once the
  detector ran against live Certificate Transparency traffic instead of
  hand-picked examples. Each is documented with what broke, how it was
  found, and the fix.
- **Reliability and performance treated as real engineering, not an
  afterthought.** systemd process supervision instead of bare
  background processes, WAL-mode SQLite tuned for two processes reading
  and writing concurrently, graceful degradation when an on-demand task
  times out instead of crashing the whole UI, and a parallelized
  enrichment pipeline validated with real before/after timing
  measurements against production data, all documented with the
  reasoning, not just the diff.
- **A triage UI built for investigation, not just display.** The
  dashboard reads like a SIEM alert queue: select a domain, see its DNS
  resolution, WHOIS, visual comparison against the real brand's site
  (perceptual hash on a live screenshot), external reputation, and
  which other tracked domains share its infrastructure (IP, ASN,
  registrar, nameservers), all before deciding a verdict.

## Quickstart

```bash
# 1. Start the CT log firehose (self-hosted, see docs/architecture.md)
docker run -d --name certstream --restart unless-stopped -p 8080:8080 \
  -v certstream-state:/data -e CERTSTREAM_CT_LOG_STATE_FILE=/data/state.json \
  ghcr.io/reloading01/certstream-server-rust:latest

# 2. Install dependencies
uv sync
uv run playwright install chromium   # for visual comparison (screenshot + phash)

# 3. Install the systemd user services (auto-restart on crash, start on boot)
mkdir -p ~/.config/systemd/user
cp systemd/ct-hunter-hunt.service systemd/ct-hunter-dashboard.service ~/.config/systemd/user/
loginctl enable-linger "$USER"   # start at boot even without logging in
systemctl --user daemon-reload
systemctl --user enable --now ct-hunter-hunt.service ct-hunter-dashboard.service
```

The dashboard is now at http://localhost:8501. From its **System** tab
you can start/stop `ct-hunter-hunt` with a button; that shells out to
`systemctl --user`, it does not spawn a separate process (see
`docs/architecture.md` section 13 for why that distinction matters).

Without the systemd services, both can still be run by hand for a quick
test, they just will not survive a crash or a reboot:

```bash
uv run streamlit run src/ct_hunter/dashboard/app.py
uv run ct-hunter-hunt         # watches the live firehose, leave this running
uv run ct-hunter-enrich       # separately, resolves DNS and scores what's detected
uv run ct-hunter-reputation   # ASN + own infrastructure reuse + AbuseIPDB
uv run ct-hunter-crosscheck   # OpenPhish + URLscan (+ VirusTotal if an API key is set)
uv run ct-hunter-whois        # registrar + nameservers, feeds the infrastructure graph
uv run ct-hunter-triage       # moves 'New' to 'Monitoring' for exact-match techniques (backlog only, new detections get this automatically)
```

`ct-hunter-crosscheck` and `ct-hunter-reputation` use free external
sources. See [`.env.example`](.env.example) for the optional API keys
(VirusTotal, AbuseIPDB); none are required, copy it to `.env` and fill in
whichever you have.

The **Test a domain** tab runs any domain through the detector instantly,
without waiting for the firehose, useful for exploring the typosquatting
logic or running a demo.

Target brands (10, spanning tech, finance, logistics, and retail) are
configured in [`config/brands.yaml`](config/brands.yaml).

From a domain's panel you can also request a **visual comparison**
(screenshot from a real browser + perceptual hash against the brand's
legitimate site) and generate a **report draft** for a confirmed case.
See `docs/architecture.md` for the details and known limitations of each.

The **Infrastructure graph** tab correlates domains that share an IP,
ASN, registrar, or nameserver, an interactive network view plus a list of
the resulting clusters. Known generic hosting/parking providers (Sedo,
AWS, etc.) are excluded from correlation; see `docs/architecture.md`
section 10 for why and how that was found.

## Case reports

[`reports/`](reports/) documents individual domains that reached a
confirmed verdict, with the certificate-seen timestamp and the
confirmation timestamp side by side, both verifiable against
`data/ct_hunter.db`. The point of that directory is the gap between the
two dates: evidence that watching Certificate Transparency catches
infrastructure before it is used, not a summary of something already
public elsewhere. See [`reports/README.md`](reports/README.md) for how
a case gets built and what belongs in one.

## Stack

Python 3.12, SQLite (no ORM, explicit SQL), Streamlit, dnspython,
rapidfuzz, tldextract, networkx + pyvis, Playwright + imagehash,
systemd user services. Dependency management via `uv`.

## Project status

v1: ingestion, detection, storage, scoring, visual comparison, and
external reputation (own ASN correlation, URLscan, optional
VirusTotal/AbuseIPDB) all working end to end.

v2, in progress: infrastructure correlation graph (IP/ASN/registrar/
nameserver, not just a flat ASN match) shipped. Also shipped: a
reliability audit that found and fixed four real production bugs
(no process supervision across reboots/crashes, no error handling in
the ingestion path, a dashboard crash on stale filter state, an
on-demand task timeout crashing the whole session), SQLite WAL mode,
log rotation for `data/hunt.log`, and a performance pass (cached
dashboard status calls, vectorized table styling, a composite index
plus two more, `synchronous=NORMAL`, parallelized DNS/reputation
enrichment, Playwright browser reuse for visual comparison, a
precomputed brand whitelist on the ingestion hot path), see
`docs/architecture.md` sections 13 through 17. Still pending: log
rotation for the dashboard's own log, pagination at larger table sizes,
automated alerts, more CT sources in parallel.
