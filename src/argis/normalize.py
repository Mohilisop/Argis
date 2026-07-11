from __future__ import annotations

from typing import Optional

from argis.models import EvidenceItem, ProfileEvidence


# Corporate/service email domains to exclude from identity extraction
CORPORATE_EMAIL_DOMAINS = {
    "waze.com", "google.com", "facebook.com", "meta.com", "apple.com",
    "microsoft.com", "amazon.com", "twitter.com", "x.com", "github.com",
    "gitlab.com", "cloudflare.com", "fastly.com", "akamai.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "gstatic.com", "googleapis.com", "youtube.com", "spotify.com",
    "discord.com", "twitch.tv", "reddit.com", "imgur.com", "tumblr.com",
    "wordpress.com", "automattic.com", "squarespace.com", "wix.com",
    "shopify.com", "stripe.com", "paypal.com", "coinbase.com",
    "binance.com", "kraken.com", "adobe.com", "canva.com", "figma.com",
    "notion.so", "slack.com", "zoom.us", "atlassian.com", "jira.com",
    "trello.com", "asana.com", "clickup.com", "linear.app",
    "sentry.io", "datadog.com", "newrelic.com", "pagerduty.com",
    "intercom.io", "zendesk.com", "hubspot.com", "salesforce.com",
    "mailchimp.com", "sendgrid.net", "twilio.com", "intuit.com",
    "noreply.github.com",
}


def normalize_scan_result(
    platform_name: str,
    category: str,
    raw_result: dict,
    username: str,
) -> ProfileEvidence:
    """Convert a single raw scanner result into the canonical ProfileEvidence model."""
    status = raw_result.get("status", "UNKNOWN")
    url = raw_result.get("url", "")
    confidence = raw_result.get("confidence", 0)

    evidence_list: list[EvidenceItem] = []

    # Title → display name candidate
    title = raw_result.get("title") or None

    # Description → bio candidate
    description = raw_result.get("description") or None

    # Emails list
    raw_emails = raw_result.get("emails", [])
    if isinstance(raw_emails, str):
        import re
        raw_emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", raw_emails)
    personal_emails = [e for e in raw_emails if _is_user_email(e, username)]

    for e in personal_emails:
        evidence_list.append(EvidenceItem(
            field="email", value=e, source="scan.page_source",
            confidence=confidence,
        ))

    return ProfileEvidence(
        platform=platform_name,
        category=category,
        username=username,
        url=url,
        status=status,
        confidence=confidence,
        title=title,
        display_name=None,
        bio=description,
        emails=personal_emails,
        evidence=evidence_list,
    )


def normalize_scan_results(
    results: dict[str, dict],
    site_categories: dict[str, str],
    username: str,
) -> list[ProfileEvidence]:
    """Normalize all FOUND scan results into ProfileEvidence objects."""
    profiles: list[ProfileEvidence] = []
    for platform_name, raw in results.items():
        if raw.get("status") != "FOUND":
            continue
        if not raw.get("url"):
            continue
        cat = site_categories.get(platform_name, "uncategorized")
        profiles.append(
            normalize_scan_result(platform_name, cat, raw, username)
        )
    return profiles


def profile_evidence_to_dict(pe: ProfileEvidence) -> dict:
    """Convert ProfileEvidence → abbreviated dict for the JS dossier template.

    The dossier HTML template and its embedded JavaScript expect these keys:
      p, cat, url, name, mail, bio, img, avatar_hash, links, status,
      confidence, verification, warnings
    """
    return {
        "p": pe.platform,
        "cat": pe.category,
        "url": pe.url,
        "name": pe.display_name or "",
        "mail": "; ".join(pe.emails) if pe.emails else "",
        "bio": pe.bio or "",
        "img": pe.avatar_url or "",
        "avatar_hash": pe.avatar_hash or "",
        "links": pe.external_links,
        "status": pe.status,
        "confidence": pe.confidence,
        "verification": pe.verification,
        "warnings": pe.warnings,
    }


def profiles_to_dossier_dicts(profiles: list[ProfileEvidence]) -> list[dict]:
    """Convert a list of ProfileEvidence → list of abbreviated dicts."""
    return [profile_evidence_to_dict(p) for p in profiles]


def adapt_v05_record(record: dict, username: str) -> ProfileEvidence:
    """Adapt a v0.5-style record (keys: p, cat, name, bio, mail, img) to ProfileEvidence."""
    raw_mail = record.get("mail", "") or ""
    import re
    emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", raw_mail)
    personal_emails = [e for e in emails if _is_user_email(e, username)]

    evidence = []
    if record.get("name"):
        evidence.append(EvidenceItem(
            field="display_name", value=record["name"],
            source="v05.compat", confidence=50,
        ))
    for e in personal_emails:
        evidence.append(EvidenceItem(
            field="email", value=e, source="v05.compat", confidence=50,
        ))

    return ProfileEvidence(
        platform=record.get("p", ""),
        category=record.get("cat", "uncategorized"),
        username=username,
        url=record.get("url", ""),
        status="FOUND",
        confidence=record.get("confidence", 50),
        display_name=record.get("name") or None,
        bio=record.get("bio") or None,
        emails=personal_emails,
        avatar_url=record.get("img") or None,
        evidence=evidence,
    )


def adapt_v07_record(record: dict, platform_name: str, category: str, username: str) -> ProfileEvidence:
    """Adapt a v0.7-style raw scan record (status, url, title, description, emails) to ProfileEvidence."""
    return normalize_scan_result(platform_name, category, record, username)


_IMAGE_EXT_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico",
                    "bmp", "tiff", "tif"}


def _is_user_email(email: str, username: str) -> bool:
    """Basic filter: reject known corporate/system emails and asset filenames."""
    if not email or "@" not in email:
        return False
    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    if domain in CORPORATE_EMAIL_DOMAINS:
        return False
    # Reject image/file extensions used as TLDs (e.g. Error_Lock_SP@2x.avif)
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _IMAGE_EXT_TLDS:
        return False
    local_lower = local.lower()
    system_prefixes = ["noreply", "no-reply", "support", "admin", "help",
                       "billing", "sales", "marketing", "team", "contact",
                       "feedback", "abuse", "postmaster", "webmaster",
                       "security", "privacy", "legal", "compliance",
                       "careers", "jobs", "press", "info"]
    if any(local_lower.startswith(p) or local_lower == p for p in system_prefixes):
        return False
    return True
