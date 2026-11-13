import logging
import os
from dataclasses import dataclass

log = logging.getLogger(__name__)

DESTRUCTIVE = {"block_ip", "disable_user", "isolate_host"}
PROTECTED_TARGETS = {"root", "administrator", "domain-controller", "wazuh-server"}


@dataclass
class ActionResult:
    action: str
    target: str
    executed: bool
    message: str


def _dry_run() -> bool:
    return os.getenv("AEGIS_DRY_RUN", "true").lower() != "false"


def run_action(action: str, target: str, approved: bool = False) -> ActionResult:
    if action not in DESTRUCTIVE | {"notify"}:
        return ActionResult(action, target, False, "unknown action")
    if target.lower() in PROTECTED_TARGETS:
        return ActionResult(action, target, False, "blocked: protected asset")
    if action in DESTRUCTIVE and not approved:
        return ActionResult(action, target, False, "approval required")
    if _dry_run():
        log.info("[dry-run] %s -> %s", action, target)
        return ActionResult(action, target, False, "dry-run: no change made")
    # Real integrations (firewall, identity provider, EDR) come in later milestones.
    return ActionResult(action, target, False, "not implemented")