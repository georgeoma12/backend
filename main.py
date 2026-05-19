from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import os
from dotenv import load_dotenv
import anthropic

load_dotenv()

app = FastAPI(title="OSINT Intelligence Suite")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_methods=["*"],
    allow_headers=["*"],
)

VT_KEY       = os.getenv("VIRUSTOTAL_API_KEY")
ABUSE_KEY    = os.getenv("ABUSEIPDB_API_KEY")
HIBP_KEY     = os.getenv("HIBP_API_KEY")
ST_KEY       = os.getenv("SECURITYTRAILS_API_KEY")
ANTHROPIC_KEY = os.getenv("ANTHROPIC_API_KEY")


# ── Models ────────────────────────────────────────────────────────────────────

class DomainRequest(BaseModel):
    domain: str

class IPRequest(BaseModel):
    ip: str

class EmailRequest(BaseModel):
    email: str

class UsernameRequest(BaseModel):
    username: str

class AdFraudRequest(BaseModel):
    platform: str = ""
    brand: str = ""
    product: str = ""
    url: str = ""


# ── Domain ────────────────────────────────────────────────────────────────────

@app.post("/api/domain")
async def investigate_domain(req: DomainRequest):
    domain = req.domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
    results = {}

    async with httpx.AsyncClient(timeout=15) as client:

        # VirusTotal domain report
        if VT_KEY:
            vt = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_KEY}
            )
            if vt.status_code == 200:
                vt_data = vt.json().get("data", {}).get("attributes", {})
                stats = vt_data.get("last_analysis_stats", {})
                results["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "reputation": vt_data.get("reputation", 0),
                    "registrar": vt_data.get("registrar", "Unknown"),
                    "creation_date": vt_data.get("creation_date"),
                    "categories": vt_data.get("categories", {}),
                }

        # SecurityTrails WHOIS + DNS
        if ST_KEY:
            st_whois = await client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}",
                headers={"APIKEY": ST_KEY}
            )
            if st_whois.status_code == 200:
                st_data = st_whois.json()
                results["securitytrails"] = {
                    "hostname": st_data.get("hostname"),
                    "alexa_rank": st_data.get("alexa_rank"),
                    "apex_domain": st_data.get("apex_domain"),
                    "whois": st_data.get("whois", {}),
                    "current_dns": st_data.get("current_dns", {}),
                }

            # Subdomains
            st_sub = await client.get(
                f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                headers={"APIKEY": ST_KEY}
            )
            if st_sub.status_code == 200:
                results["subdomains"] = st_sub.json().get("subdomains", [])[:10]

        # crt.sh certificate transparency
        crt = await client.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            headers={"Accept": "application/json"}
        )
        if crt.status_code == 200:
            certs = crt.json()
            unique_names = list({c.get("name_value", "").replace("*.", "") for c in certs})[:15]
            results["certificates"] = {
                "total_certs": len(certs),
                "related_domains": unique_names,
            }

    return results


# ── IP ────────────────────────────────────────────────────────────────────────

@app.post("/api/ip")
async def investigate_ip(req: IPRequest):
    ip = req.ip.strip()
    results = {}

    async with httpx.AsyncClient(timeout=15) as client:

        # AbuseIPDB
        if ABUSE_KEY:
            abuse = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": ABUSE_KEY, "Accept": "application/json"}
            )
            if abuse.status_code == 200:
                d = abuse.json().get("data", {})
                results["abuseipdb"] = {
                    "abuse_score": d.get("abuseConfidenceScore"),
                    "country": d.get("countryCode"),
                    "isp": d.get("isp"),
                    "domain": d.get("domain"),
                    "is_tor": d.get("isTor"),
                    "is_proxy": d.get("isPublicProxy") or d.get("isWhitelisted") == False,
                    "usage_type": d.get("usageType"),
                    "total_reports": d.get("totalReports"),
                    "last_reported": d.get("lastReportedAt"),
                }

        # VirusTotal IP
        if VT_KEY:
            vt = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_KEY}
            )
            if vt.status_code == 200:
                vt_data = vt.json().get("data", {}).get("attributes", {})
                stats = vt_data.get("last_analysis_stats", {})
                results["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "country": vt_data.get("country"),
                    "asn": vt_data.get("asn"),
                    "as_owner": vt_data.get("as_owner"),
                    "network": vt_data.get("network"),
                }

        # Free IP geolocation (no key needed)
        geo = await client.get(f"https://ipapi.co/{ip}/json/")
        if geo.status_code == 200:
            g = geo.json()
            results["geolocation"] = {
                "city": g.get("city"),
                "region": g.get("region"),
                "country_name": g.get("country_name"),
                "latitude": g.get("latitude"),
                "longitude": g.get("longitude"),
                "org": g.get("org"),
                "timezone": g.get("timezone"),
            }

    return results


# ── Email ─────────────────────────────────────────────────────────────────────

@app.post("/api/email")
async def investigate_email(req: EmailRequest):
    email = req.email.strip().lower()
    results = {}

    async with httpx.AsyncClient(timeout=15) as client:

        # HaveIBeenPwned
        if HIBP_KEY:
            hibp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": False},
                headers={
                    "hibp-api-key": HIBP_KEY,
                    "User-Agent": "OSINT-Suite-App"
                }
            )
            if hibp.status_code == 200:
                breaches = hibp.json()
                results["breaches"] = [{
                    "name": b.get("Name"),
                    "domain": b.get("Domain"),
                    "breach_date": b.get("BreachDate"),
                    "description": b.get("Description", "")[:150],
                    "data_classes": b.get("DataClasses", []),
                    "is_verified": b.get("IsVerified"),
                } for b in breaches]
            elif hibp.status_code == 404:
                results["breaches"] = []

            # Pastes
            pastes = await client.get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
                headers={"hibp-api-key": HIBP_KEY, "User-Agent": "OSINT-Suite-App"}
            )
            if pastes.status_code == 200:
                results["pastes"] = pastes.json()
            elif pastes.status_code == 404:
                results["pastes"] = []

        # Basic email validation via free API
        domain_part = email.split("@")[-1] if "@" in email else ""
        if domain_part:
            mx = await client.get(f"https://dns.google/resolve?name={domain_part}&type=MX")
            if mx.status_code == 200:
                mx_data = mx.json()
                results["mx_records"] = {
                    "has_mx": bool(mx_data.get("Answer")),
                    "records": [r.get("data") for r in mx_data.get("Answer", [])][:5]
                }

    return results


# ── Username ──────────────────────────────────────────────────────────────────

PLATFORMS = [
    {"name": "GitHub",    "url": "https://github.com/{}"},
    {"name": "Reddit",    "url": "https://www.reddit.com/user/{}"},
    {"name": "Twitter/X", "url": "https://twitter.com/{}"},
    {"name": "Instagram", "url": "https://www.instagram.com/{}"},
    {"name": "TikTok",    "url": "https://www.tiktok.com/@{}"},
    {"name": "LinkedIn",  "url": "https://www.linkedin.com/in/{}"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{}"},
    {"name": "Twitch",    "url": "https://www.twitch.tv/{}"},
    {"name": "YouTube",   "url": "https://www.youtube.com/@{}"},
    {"name": "Steam",     "url": "https://steamcommunity.com/id/{}"},
    {"name": "Telegram",  "url": "https://t.me/{}"},
    {"name": "Medium",    "url": "https://medium.com/@{}"},
    {"name": "Quora",     "url": "https://www.quora.com/profile/{}"},
    {"name": "Flickr",    "url": "https://www.flickr.com/people/{}"},
    {"name": "VK",        "url": "https://vk.com/{}"},
]

@app.post("/api/username")
async def investigate_username(req: UsernameRequest):
    username = req.username.strip()
    results = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for platform in PLATFORMS:
            url = platform["url"].format(username)
            try:
                resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
                # Basic heuristic: 200 = found, 404 = not found
                found = resp.status_code == 200
                results.append({
                    "platform": platform["name"],
                    "url": url,
                    "found": found,
                    "status_code": resp.status_code,
                })
            except Exception:
                results.append({
                    "platform": platform["name"],
                    "url": url,
                    "found": False,
                    "status_code": None,
                })

    return {"username": username, "results": results}


# ── Ad Fraud AI Report ────────────────────────────────────────────────────────

@app.post("/api/adfraud")
async def adfraud_report(req: AdFraudRequest):
    if not ANTHROPIC_KEY:
        raise HTTPException(status_code=500, detail="Anthropic API key not configured")

    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    prompt = f"""You are a cybersecurity OSINT analyst specialising in ad fraud and scam campaigns.
A user has spotted a suspicious advertisement with these details:
- Platform / app where seen: {req.platform or 'unknown'}
- Brand being impersonated: {req.brand or 'unknown'}
- Product or game being promoted: {req.product or 'unknown'}
- URL / domain / app name visible in ad: {req.url or 'none provided'}

Write a professional intelligence report covering:
1. Scam classification (what type of fraud this is)
2. Likely threat actor profile and motivation
3. Technical mechanism (how the ad ecosystem is being abused)
4. Recommended immediate actions (report to whom, how)
5. OSINT next steps to investigate further

Be concise (max 250 words), direct, and professional. No markdown headers."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1000,
        messages=[{"role": "user", "content": prompt}]
    )

    return {"report": message.content[0].text}


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "status": "OSINT Suite running",
        "endpoints": ["/api/domain", "/api/ip", "/api/email", "/api/username", "/api/adfraud"]
    }
