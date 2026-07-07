# Contributing to Argis

Thanks for considering contributing! Argis is a young project and there's a
lot of low-friction, high-value work available — you don't need deep Python
experience to make a real difference.

## The easiest way to help: verify a site rule

`src/argis/sites.json` defines how Argis detects whether a username exists on
a given platform. Many entries were written from general knowledge of common
patterns (HTTP 404, specific error text, etc.) rather than live-verified
against the real site, so some are likely stale or wrong. Verifying one is a
perfect first contribution:

1. Pick a platform from `sites.json` you're not sure is correct.
2. Visit a URL for a **real, known-existing** username and a **clearly
   fake** one (e.g. `xk29fjq0ptzz`).
3. Compare what actually comes back (status code, page text, redirect) to
   what the `error_type` / `error_criteria` in `sites.json` currently says.
4. If it's wrong, fix it and open a PR. If it's right, comment on the
   relevant issue or PR saying "confirmed" — that's useful too.

Detection rule types:

| `error_type`   | `error_criteria` means...                                         |
|----------------|---------------------------------------------------------------------|
| `status_code`  | The site returns this HTTP status when the user doesn't exist       |
| `message`      | This text appears in the HTML when the user doesn't exist           |
| `response_url` | The final (post-redirect) URL when the user doesn't exist           |

## Adding a brand-new platform

Add an entry to `sites.json` with a `url` template (`{}` is replaced with the
username) and a detection rule as above, then add a test case to
`tests/test_core.py` if the rule type is new or unusual.

## Local setup

```bash
git clone <your-fork-url>
cd argis
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest -v
```

## Code contributions

Some ideas beyond `sites.json`, if you want to write actual code:

- Reduce false positives further (e.g. detect more WAF/challenge page types)
- Add an interactive mode / TUI
- Add rate-limit backoff instead of just marking a site `BLOCKED`
- Support reading a batch of usernames from a file
- Add a `--category` filter (e.g. `argis scan foo --category gaming`)

## Submitting a PR

1. Fork the repo, create a branch (`git checkout -b fix/discord-rule`)
2. Make your change, run `pytest -v` to confirm nothing's broken
3. Open a PR with a short description of what you verified or changed

## Code of conduct

Be kind. Assume good faith. This is a small project run by volunteers.
