# ct-hunter

Phishing infrastructure detection (typosquatting) via real-time
[Certificate Transparency](https://certificate.transparency.dev/) log
monitoring, before a domain gets used in a campaign.

See [`docs/architecture.md`](docs/architecture.md) for the design
decisions behind how this is built.

## Quickstart

```bash
# 1. Start the CT log firehose (self-hosted, see docs/architecture.md)
docker run -d --name certstream --restart unless-stopped -p 8080:8080 \
  -v certstream-state:/data -e CERTSTREAM_CT_LOG_STATE_FILE=/data/state.json \
  ghcr.io/reloading01/certstream-server-rust:latest

# 2. Install dependencies
uv sync
uv run playwright install chromium   # for visual comparison (screenshot + phash)

# 3. Launch the web interface
uv run streamlit run src/ct_hunter/dashboard/app.py
```

From the web interface (**System** tab) you can start/stop
`ct-hunter-hunt` with a button, no terminal needed. It can also be run by
hand if you prefer:

```bash
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

Target brands are configured in [`config/brands.yaml`](config/brands.yaml).

From a domain's panel you can also request a **visual comparison**
(screenshot from a real browser + perceptual hash against the brand's
legitimate site) and generate a **report draft** for a confirmed case.
See `docs/architecture.md` for the details and known limitations of each.

The **Infrastructure graph** tab correlates domains that share an IP,
ASN, registrar, or nameserver, an interactive network view plus a list of
the resulting clusters. Known generic hosting/parking providers (Sedo,
AWS, etc.) are excluded from correlation; see `docs/architecture.md`
section 10 for why and how that was found.

## Project status

v1: ingestion, detection, storage, scoring, visual comparison, and
external reputation (own ASN correlation, URLscan, optional
VirusTotal/AbuseIPDB) all working end to end.

v2, in progress: infrastructure correlation graph (IP/ASN/registrar/
nameserver, not just a flat ASN match) shipped. Still pending: automated
alerts, more CT sources in parallel.
