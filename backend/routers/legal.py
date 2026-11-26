from __future__ import annotations
import os
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["legal"])
OPERATOR = os.getenv("MCAS_OPERATOR_NAME", "Mosley Client Acquisition System (MCAS)")
EMAIL = os.getenv("MCAS_LEGAL_EMAIL", "moslinahkimanzi@gmail.com")

def _page(title: str, subtitle: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title} — MCAS</title><style>body{{margin:0;font-family:system-ui,sans-serif;background:#0b1220;color:#e6edf7;line-height:1.6}}
.wrap{{max-width:860px;margin:32px auto;padding:0 20px}}.card{{background:#111a2e;border:1px solid #1e2d4a;border-radius:12px;padding:30px}}
nav{{display:flex;gap:16px;margin-bottom:20px;font-size:14px}}a{{color:#38bdf8;text-decoration:none}}h2{{border-bottom:1px solid #1e2d4a;padding-bottom:6px;margin-top:24px}}
footer{{margin-top:24px;padding-top:14px;border-top:1px solid #1e2d4a;font-size:13px;color:#9fb0cc;display:flex;justify-content:space-between;flex-wrap:wrap}}</style></head>
<body><div class="wrap"><nav><a href="/">&larr; Back to MCAS</a><a href="/privacy">Privacy Policy</a><a href="/terms">Terms of Service</a><a href="/data-processing">Data Processing (DPA)</a></nav>
<div class="card"><h1>{title}</h1><p style="color:#9fb0cc">{subtitle} &bull; Effective Date: November 26, 2026</p>{body}
<footer><span>&copy; 2026 {OPERATOR}</span><span>Contact: <a href="mailto:{EMAIL}">{EMAIL}</a></span></footer></div></div></body></html>"""

@router.get("/privacy", response_class=HTMLResponse)
def privacy_policy():
    return _page("Privacy Policy", "Kenya Data Protection Act (2019) & GDPR Compliant", f"""
<p><strong>{OPERATOR}</strong> ("MCAS") complies with the <strong>Kenya Data Protection Act, 2019</strong> (Office of the Data Protection Commissioner — ODPC) and international privacy standards including the EU/UK GDPR.</p>
<h2>1. Data We Collect</h2><ul><li><strong>Account Data:</strong> Name, email address, password hash, Google OAuth identifier, and session tokens.</li>
<li><strong>Billing Metadata:</strong> Plan tier, credit ledger entries, currency (USD/KES), payment method, and Flutterwave references. Raw card numbers and M-Pesa PINs are never stored on MCAS servers.</li>
<li><strong>Workspace Records:</strong> Business leads, public contact links, website audit reports, and drafts scoped strictly to your tenant <code>user_id</code>.</li></ul>
<h2>2. Security &amp; Your Rights</h2><p>All data is encrypted in transit (HTTPS/TLS), isolated per tenant, and backed up daily. We never sell user or prospect data. To access, export, or delete your account and workspace records, email <a href="mailto:{EMAIL}">{EMAIL}</a>.</p>""")

@router.get("/terms", response_class=HTMLResponse)
def terms_of_service():
    return _page("Terms of Service", "Subscriptions, Credit Ledger & Acceptable Use", f"""
<p>These Terms govern your use of <strong>{OPERATOR}</strong> under the laws of the <strong>Republic of Kenya</strong>.</p>
<h2>1. Acceptable Use</h2><p>MCAS provides B2B prospect research, bounded static website audits, and outreach drafting. You agree to comply with applicable anti-spam and data protection laws and not use MCAS to probe private networks or misrepresent static HTML observations as penetration tests.</p>
<h2>2. Subscriptions, Credits &amp; Refunds</h2><ul><li>Plans and credit packs are priced in USD, with real-time KES conversion displayed before M-Pesa checkout via Flutterwave.</li>
<li>Monthly subscriptions last 30 days and renew only upon customer-initiated payment (no silent recurring M-Pesa debits).</li>
<li>Failed asynchronous jobs automatically refund reserved credits to your ledger. Duplicate payment charges verified with Flutterwave are refunded upon request to <a href="mailto:{EMAIL}">{EMAIL}</a>.</li></ul>""")

@router.get("/data-processing", response_class=HTMLResponse)
def data_processing_agreement():
    return _page("Data Processing Agreement (DPA)", "ODPC Section 42 & GDPR Article 28 Commitments", f"""
<p>This DPA applies where Customer acts as Data Controller for business contact records processed in <strong>{OPERATOR}</strong> under Section 42 of the <strong>Kenya Data Protection Act, 2019</strong> and Article 28 of the <strong>GDPR</strong>.</p>
<h2>1. Technical &amp; Organizational Safeguards</h2><ul><li>Strict <code>user_id</code> multi-tenant query isolation and SSRF network protections.</li>
<li>TLS encryption in transit, hashed credentials, and automated rolling backups.</li>
<li>Breach notification within 48 hours of confirmation and full data erasure within 14 days of account deletion request to <a href="mailto:{EMAIL}">{EMAIL}</a>.</li></ul>""")
