# Webhooks & Notifications

## Desktop Notifications

```bash
argis scan johndoe --notify
```

Works on Windows (toast), Linux (notify-send), and macOS (terminal-notifier). Falls back to console print if no desktop notifier is available.

## Webhooks

Send results to Slack or Discord:

```bash
# Slack
argis scan johndoe --webhook https://hooks.slack.com/services/T00/B00/xxxxx

# Discord
argis scan johndoe --webhook https://discord.com/api/webhooks/000000/xxxxx

# With monitor
argis monitor johndoe --webhook https://hooks.slack.com/services/T00/B00/xxxxx
```

The webhook payload includes found platforms, counts per status, and scan timestamp.