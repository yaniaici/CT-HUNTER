# Cases

Each file in this directory documents a domain detected by ct-hunter and
marked `confirmado_malicioso` in the dashboard, with a detection date
(when the certificate was seen in CT logs) and a confirmation date (when
it was verified as real phishing/malicious infrastructure), both
verifiable against `data/ct_hunter.db`.

The value of this directory is not the code, it is the time window between
those two dates: proof that watching Certificate Transparency detects
attack infrastructure before it gets used, not after.

## How a case gets generated

1. Triage in the dashboard (Detections tab): select the domain, investigate
   with WHOIS / HTTP check / external links.
2. Set the verdict to `confirmado_malicioso` once there is real evidence
   (active phishing content, listed in a public feed like OpenPhish, etc.),
   never automatic.
3. "Generate report draft" button in the domain's own panel, or:
   ```
   uv run ct-hunter-report <domain>
   ```
   This writes `YYYY-MM-DD-domain.md` with the timeline, technical signals,
   and investigation notes already on record.
4. **By hand**: add the "Interpretation" section, why this case matters,
   what makes it stand out, what it shows. That part is not auto-generated;
   it is what demonstrates the actual analysis work.

## What this directory is not

Not a collection of generic IOCs, and not a summary of threats already
published elsewhere; that is what the original sources (OpenPhish, etc.)
are for. Every entry here should be able to answer "what did I see, when,
and how did I verify it?"
