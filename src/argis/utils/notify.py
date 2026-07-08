from __future__ import annotations

_NOTIFICATION_ENABLED = True


def enable_notifications() -> None:
    global _NOTIFICATION_ENABLED
    _NOTIFICATION_ENABLED = True


def disable_notifications() -> None:
    global _NOTIFICATION_ENABLED
    _NOTIFICATION_ENABLED = False


def send_notification(title: str, message: str) -> bool:
    if not _NOTIFICATION_ENABLED:
        return False
    try:
        from plyer import notification

        notification.notify(title=title, message=message, app_name="Argis", timeout=5)
        return True
    except ImportError:
        pass
    except Exception:
        pass
    return _notify_fallback(title, message)


def _notify_fallback(title: str, message: str) -> bool:
    try:
        import platform
        import subprocess

        system = platform.system().lower()
        if system == "darwin":
            subprocess.run(
                ["osascript", "-e", f'display notification "{message}" with title "{title}"'],
                timeout=3,
                capture_output=True,
            )
            return True
        elif system == "linux":
            subprocess.run(
                ["notify-send", title, message], timeout=3, capture_output=True
            )
            return True
    except Exception:
        pass
    return False
