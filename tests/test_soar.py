from aegissoc.soar import run_action


def test_destructive_requires_approval():
    r = run_action("block_ip", "203.0.113.9")
    assert not r.executed and r.message == "approval required"


def test_protected_asset_blocked():
    r = run_action("disable_user", "Administrator", approved=True)
    assert r.message == "blocked: protected asset"


def test_dry_run_by_default(monkeypatch):
    monkeypatch.delenv("AEGIS_DRY_RUN", raising=False)
    r = run_action("isolate_host", "linux-victim", approved=True)
    assert not r.executed and r.message.startswith("dry-run")


def test_unknown_action():
    assert run_action("format_disk", "host").message == "unknown action"