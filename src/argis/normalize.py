from __future__ import annotations

from argis.models import EvidenceItem, ProfileEvidence

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


def _raw_avatar(raw_result: dict, platform_name: str, username: str) -> str | None:
    """Preserve avatar fields emitted by APIs/extractors and provide safe fallbacks."""
    for key in (
        "avatar_url", "avatar", "profile_image", "profile_image_url",
        "image", "img", "picture", "photo_url",
    ):
        value = raw_result.get(key)
        if isinstance(value, dict):
            value = value.get("url") or value.get("contentUrl")
        if isinstance(value, str) and value.startswith(("http://", "https://", "//")):
            return "https:" + value if value.startswith("//") else value

    # GitHub exposes a stable public avatar redirect for every real account.
    if platform_name.lower() in {"github", "gist", "github sponsors"}:
        return f"https://github.com/{username}.png?size=460"
    return None


def normalize_scan_result(
    platform_name: str,
    category: str,
    raw_result: dict,
    username: str,
) -> ProfileEvidence:
    """Convert one scanner result into the canonical dossier model."""
    status = raw_result.get("status", "UNKNOWN")
    url = raw_result.get("url", "")
    confidence = int(raw_result.get("confidence", 0) or 0)
    evidence_list: list[EvidenceItem] = []

    title = raw_result.get("title") or None
    description = raw_result.get("description") or raw_result.get("bio") or None

    raw_emails = raw_result.get("emails", [])
    if isinstance(raw_emails, str):
        import re
        raw_emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", raw_emails)
    personal_emails = [e for e in raw_emails if _is_user_email(str(e), username)]

    for email in personal_emails:
        evidence_list.append(EvidenceItem(
            field="email", value=email, source="scan.page_source",
            confidence=confidence,
        ))

    avatar_url = _raw_avatar(raw_result, platform_name, username)
    if avatar_url:
        evidence_list.append(EvidenceItem(
            field="avatar", value=avatar_url,
            source="scan.avatar_field" if any(raw_result.get(k) for k in ("avatar_url", "avatar", "profile_image", "image", "img", "picture")) else "platform.public_avatar_endpoint",
            confidence=90 if platform_name.lower() == "github" else max(60, confidence),
        ))

    external_links = raw_result.get("external_links") or raw_result.get("links") or []
    if isinstance(external_links, str):
        external_links = [external_links]

    return ProfileEvidence(
        platform=platform_name,
        category=category,
        username=username,
        url=url,
        status=status,
        confidence=confidence,
        title=title,
        display_name=raw_result.get("display_name") or None,
        bio=description,
        emails=personal_emails,
        external_links=[str(link) for link in external_links],
        avatar_url=avatar_url,
        avatar_hash=raw_result.get("avatar_hash") or None,
        evidence=evidence_list,
    )


def normalize_scan_results(
    results: dict[str, dict],
    site_categories: dict[str, str],
    username: str,
) -> list[ProfileEvidence]:
    profiles: list[ProfileEvidence] = []
    for platform_name, raw in results.items():
        if raw.get("status") != "FOUND" or not raw.get("url"):
            continue
        profiles.append(normalize_scan_result(
            platform_name,
            site_categories.get(platform_name, "uncategorized"),
            raw,
            username,
        ))
    return profiles


def profile_evidence_to_dict(pe: ProfileEvidence) -> dict:
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
    return [profile_evidence_to_dict(profile) for profile in profiles]


def adapt_v05_record(record: dict, username: str) -> ProfileEvidence:
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
    for email in personal_emails:
        evidence.append(EvidenceItem(
            field="email", value=email, source="v05.compat", confidence=50,
        ))
    if record.get("img"):
        evidence.append(EvidenceItem(
            field="avatar", value=record["img"], source="v05.compat", confidence=50,
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
        avatar_hash=record.get("avatar_hash") or None,
        external_links=record.get("links") or [],
        evidence=evidence,
    )


def adapt_v07_record(record: dict, platform_name: str, category: str, username: str) -> ProfileEvidence:
    return normalize_scan_result(platform_name, category, record, username)


_IMAGE_EXT_TLDS = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico",
    "bmp", "tiff", "tif",
}


def _is_user_email(email: str, username: str) -> bool:
    if not email or "@" not in email:
        return False
    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    if domain in CORPORATE_EMAIL_DOMAINS:
        return False
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _IMAGE_EXT_TLDS:
        return False
    local_lower = local.lower()
    system_prefixes = [
        "noreply", "no-reply", "support", "admin", "help", "billing",
        "sales", "marketing", "team", "contact", "feedback", "abuse",
        "postmaster", "webmaster", "security", "privacy", "legal",
        "compliance", "careers", "jobs", "press", "info",
    ]
    return not any(
        local_lower.startswith(prefix) or local_lower == prefix
        for prefix in system_prefixes
    )
