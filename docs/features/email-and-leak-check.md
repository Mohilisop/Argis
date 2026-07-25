# Email Pattern Generator & Password Leak Check

Two complementary features that extend Argis's investigation capabilities beyond platform scanning into proactive credential exposure analysis.

---

## Email Pattern Generator

### Problem

When investigating a target, discovering their real email address is often the most valuable outcome. Most platforms don't expose emails directly, but many follow predictable email patterns based on the target's name, username, or known aliases.

### Solution

An automatic email pattern generator that produces all plausible email address variations for a target, then checks each candidate against discovered platforms and breach databases.

### How It Works

1. **Collect inputs** — username, known aliases, discovered names, known domains
2. **Generate patterns** — applies 30+ common email format templates
3. **Filter candidates** — removes patterns that don't match the target's language/locale hints
4. **Validate** — cross-references candidates against breach data and discovered emails
5. **Rank** — orders candidates by likelihood based on name similarity, domain popularity, and pattern prevalence

### Email Patterns Generated

| Pattern | Example |
|---------|---------|
| `firstname@domain` | `john@example.com` |
| `firstname.lastname@domain` | `john.doe@example.com` |
| `f.lastname@domain` | `j.doe@example.com` |
| `firstname_lastname@domain` | `john_doe@example.com` |
| `firstname-lastname@domain` | `john-doe@example.com` |
| `firstname+alias@domain` | `john+work@example.com` |
| `first_initial.lastname@domain` | `j.doe@example.com` |
| `lastname+keyword@domain` | `doe+admin@example.com` |
| `firstname@domain-tld` | `john@domain.com` |
| `username@domain` | `johndoe_42@domain.com` |
| `alias+domain` | `mohil.dev@domain.com` |
| `firstname.year@domain` | `john.1990@domain.com` |
| `firstname_initials@domain` | `jds@example.com` |
| `username+number@domain` | `johndoe42@domain.com` |
| `role_username@domain` | `admin.johndoe@domain.com` |

### Integration Points

- **During investigation** — runs silently alongside squads, feeds candidates into breach check
- **After investigation** — available via `argis emails <username>` command for on-demand generation
- **Confidence scoring** — patterns matching the target's native language and common domains rank higher

### Usage

```bash
# Auto-generate and check emails during investigation
argis investigate johnsmith --generate-emails

# On-demand email generation
argis emails johnsmith

# With known aliases for wider pattern coverage
argis emails johnsmith -a "john_smith,jsmith,j.doe"

# Output to file
argis emails johnsmith -o emails.json
```

### Output Format

```json
{
  "target": "johnsmith",
  "generated_at": "2026-07-25T...",
  "candidates": [
    {
      "email": "john.smith@gmail.com",
      "pattern": "firstname.lastname@domain",
      "confidence": 0.85,
      "in_breach": true,
      "breach_count": 3,
      "found_on_platforms": ["github", "twitter"],
      "rationale": "Matches known alias + common Gmail pattern"
    }
  ],
  "stats": {
    "total_candidates": 247,
    "already_discovered": 12,
    "in_breach": 89,
    "found_on_platforms": 34
  }
}
```

---

## Password Leak Check

### Problem

Discovering that a target's credentials have been exposed in breaches is critical for both offensive OSINT (finding access points) and defensive auditing (understanding exposure). Currently Argis checks emails against breach databases, but not password patterns associated with the target's accounts.

### Solution

A password leak check that cross-references discovered emails, known aliases, and username patterns against breach databases to identify:
- Known compromised password patterns
- Password reuse across platforms
- Credential stuffing vulnerability indicators
- Weak password patterns based on the target's personal data

### How It Works

1. **Collect email candidates** — from the email pattern generator or discovered during scan
2. **Check against breach databases** — queries HaveIBeenPwned and other breach aggregation services
3. **Analyze password patterns** — identifies if the target uses passwords derived from:
   - Username variants
   - Known aliases
   - Birth years or dates discovered
   - Platform names or handles
   - Common password patterns (e.g., `Username123!`, `Firstname+year`)
4. **Cross-reference platforms** — checks if the same password pattern appears across multiple breached accounts
5. **Generate risk report** — summarizes exposure with actionable recommendations

### Analysis Layers

#### Layer 1: Known Breach Match
```
Email: john.smith@gmail.com
Breaches: 3 (LinkedIn 2012, Adobe 2013, Dropbox 2016)
Data classes: passwords, emails, personal info
```

#### Layer 2: Password Pattern Analysis
```
Target: johnsmith | Aliases: john_smith
Generated passwords tested:
  - johndoe123     → FOUND in 2 breaches (LinkedIn, Adobe)
  - johnsmith2020  → FOUND in 1 breach (Dropbox)
  - j.smith!pass   → NOT FOUND (strong pattern)
  - Smith@2020     → NOT FOUND (moderate)
```

#### Layer 3: Cross-Platform Reuse
```
Email A (john@gmail.com): password = "Smith2020"  → breached on LinkedIn
Email B (john.smith@outlook.com): password = "Smith2020!". → NOT breached directly, 
                                but pattern "Smith+year" matches breach A
  ⚠ WARNING: Credential reuse detected — if one account is compromised, 
    other accounts using similar patterns are at risk
```

### Integration Points

- **During investigation** — runs automatically after email discovery, feeds into risk scoring
- **Standalone check** — `argis check-passwords <username>` for on-demand analysis
- **Risk scoring** — contributes to the overall exposure score in the investigation report
- **Active Risk Radar** — breach findings affect the radar's signal level (ELEVATED when passwords are leaked)

### Usage

```bash
# Auto-check during investigation
argis investigate johnsmith --check-passwords

# On-demand password pattern check
argis check-passwords johnsmith

# Check specific emails
argis check-passwords --emails john@gmail.com,j.doe@outlook.com

# With alias expansion for wider pattern testing
argis check-passwords johnsmith -a "john_smith,jsmith,j.doe"

# Full output with all breach details
argis check-passwords johnsmith --verbose --output report.json
```

### Output Format

```json
{
  "target": "johnsmith",
  "checked_at": "2026-07-25T...",
  "emails_checked": [
    "john.smith@gmail.com",
    "j.smith@outlook.com",
    "john_smith@yahoo.com"
  ],
  "breach_summary": {
    "total_breaches": 3,
    "emails_compromised": 2,
    "unique_password_patterns_found": 4
  },
  "password_patterns": [
    {
      "pattern": "Firstname+Year",
      "example": "Smith2020",
      "found_in_breaches": true,
      "breach_count": 1,
      "breach_sources": ["LinkedIn 2021"],
      "reuse_risk": "HIGH"
    },
    {
      "pattern": "Username+Number",
      "example": "johnsmith42",
      "found_in_breaches": false,
      "breach_count": 0,
      "reuse_risk": "MEDIUM"
    }
  ],
  "risk_assessment": {
    "overall_score": 78,
    "grade": "HIGH EXPOSURE",
    "recommendations": [
      "Change all passwords on compromised email addresses immediately",
      "Enable 2FA on all accounts using username-derived passwords",
      "Do not reuse password patterns across platforms",
      "Consider using a password manager with generated passwords"
    ]
  }
}
```

### Recommendations Generated

The check produces actionable recommendations based on findings:

| Severity | Recommendation |
|----------|---------------|
| 🔴 HIGH | Change password on breached accounts immediately |
| 🔴 HIGH | Enable 2FA on all accounts using reused patterns |
| 🟡 MEDIUM | Avoid username-derived passwords across platforms |
| 🟡 MEDIUM | Use unique passwords per service |
| 🟢 LOW | Consider a password manager for generated passwords |

### Integration with Other Features

The email pattern generator and password leak check work together with existing Argis features:

- **Active Risk Radar** — breach findings increase the risk signal level
- **Cross-Username Correlation** — discovered emails feed into pattern generation
- **Dork Findings** — surface exposure URLs provide additional data points
- **Investigation Report** — all findings integrate into a unified exposure score
- **Epsilon Squad** — specialist agents can use findings for deeper analysis
