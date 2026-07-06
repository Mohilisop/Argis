from argis import diff as diffmod


def test_compute_diff_added_and_removed():
    previous = {
        "GitHub": {"status": "FOUND", "url": "https://github.com/foo"},
        "Reddit": {"status": "NOT_FOUND", "url": "https://reddit.com/foo"},
    }
    current = {
        "GitHub": {"status": "NOT_FOUND", "url": "https://github.com/foo"},
        "Reddit": {"status": "FOUND", "url": "https://reddit.com/foo"},
    }
    result = diffmod.compute_diff(previous, current)
    assert result["removed"] == [("GitHub", "https://github.com/foo")]
    assert result["added"] == [("Reddit", "https://reddit.com/foo")]
    assert result["unchanged_count"] == 0


def test_compute_diff_no_changes():
    snapshot = {"GitHub": {"status": "FOUND", "url": "https://github.com/foo"}}
    result = diffmod.compute_diff(snapshot, snapshot)
    assert result["added"] == []
    assert result["removed"] == []
    assert result["unchanged_count"] == 1


def test_save_and_load_history(tmp_path, monkeypatch):
    monkeypatch.setattr(diffmod.Path, "home", classmethod(lambda cls: tmp_path))

    username = "test_user"
    assert diffmod.load_history(username) == []

    results_1 = {"GitHub": {"status": "FOUND", "url": "https://github.com/test_user"}}
    diffmod.save_scan(username, results_1)

    history = diffmod.load_history(username)
    assert len(history) == 1
    assert history[0]["results"] == results_1

    results_2 = {"GitHub": {"status": "NOT_FOUND", "url": "https://github.com/test_user"}}
    diffmod.save_scan(username, results_2)

    history = diffmod.load_history(username)
    assert len(history) == 2

    last = diffmod.get_last_scan(username)
    assert last["results"] == results_2

    removed = diffmod.clear_history(username)
    assert removed is True
    assert diffmod.load_history(username) == []


def test_save_scan_respects_max_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(diffmod.Path, "home", classmethod(lambda cls: tmp_path))
    username = "bounded_user"

    for i in range(5):
        diffmod.save_scan(username, {"Site": {"status": "FOUND", "url": "x"}}, max_entries=3)

    history = diffmod.load_history(username)
    assert len(history) == 3
