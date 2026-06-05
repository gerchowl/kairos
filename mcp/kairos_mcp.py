# /// script
# requires-python = ">=3.12"
# dependencies = ["mcp>=1.2", "httpx>=0.27"]
# ///
"""Kairos MCP server — the scheduling-poll API as native agent tools.

Runs locally (stdio) and talks to the Kairos REST API over HTTPS:

    KAIROS_API_KEY=... uv run mcp/kairos_mcp.py

Env:
    KAIROS_URL      base URL of your Kairos instance (default http://127.0.0.1:8003)
    KAIROS_API_KEY  bearer key of the instance

Registered in .claude/mcp.json so Claude Code sessions in this repo get
kairos_* tools automatically.
"""

import os

import httpx
from mcp.server.fastmcp import FastMCP

BASE = os.environ.get("KAIROS_URL", "http://127.0.0.1:8003").rstrip("/")
KEY = os.environ.get("KAIROS_API_KEY", "")

mcp = FastMCP("kairos")


def _req(method: str, path: str, **kwargs):
    r = httpx.request(method, f"{BASE}/scheduler/api{path}",
                      headers={"Authorization": f"Bearer {KEY}"},
                      timeout=30, **kwargs)
    if r.status_code >= 400:
        return {"error": r.status_code, "detail": r.text[:500]}
    if r.headers.get("content-type", "").startswith("text/calendar"):
        return r.text
    return r.json()


@mcp.tool()
def list_polls() -> list:
    """List all scheduling polls (id, title, status, share_url)."""
    return _req("GET", "/polls")


@mcp.tool()
def get_poll(poll_id: str) -> dict:
    """Full poll state: slots, responses, invites, convergence
    (collecting|ready|partial|blocked — ready means a date works for everyone)."""
    return _req("GET", f"/polls/{poll_id}")


@mcp.tool()
def create_poll(title: str, mode: str, slots: list[dict], description: str = "",
                timezone: str = "Europe/Zurich", creator: str | None = None) -> dict:
    """Create a poll. mode: 'full_day' (slots: [{date}]) or 'time_slot'
    (slots: [{date, start_time, end_time}], HH:MM). Pass creator (account uid)
    so the poll appears on that user's dashboard. Returns share_url."""
    return _req("POST", "/polls", json={
        "title": title, "mode": mode, "slots": slots,
        "description": description or None, "timezone": timezone, "creator": creator})


@mcp.tool()
def update_poll(poll_id: str, title: str | None = None, description: str | None = None,
                timezone: str | None = None, status: str | None = None) -> dict:
    """Edit title/description/timezone, or status 'closed' / 'open' (reopen
    clears a previous decision)."""
    fields = {"title": title, "description": description,
              "timezone": timezone, "status": status}
    return _req("PATCH", f"/polls/{poll_id}", json={k: v for k, v in fields.items() if v is not None})


@mcp.tool()
def add_dates(poll_id: str, dates: list[str], notify: bool = False) -> dict:
    """Add dates (YYYY-MM-DD) to a poll additively — existing responses are
    kept; time_slot polls expand over the poll's time grid. notify=True runs
    the idempotent reminder engine so participants hear about the new dates."""
    return _req("POST", f"/polls/{poll_id}/slots", json={"dates": dates, "notify": notify})


@mcp.tool()
def respond(poll_id: str, name: str, availabilities: dict[str, str],
            email: str | None = None) -> dict:
    """Submit availability ({slot_id: yes|maybe|no}). With an email it upserts:
    re-submitting edits the same response."""
    return _req("POST", f"/polls/{poll_id}/respond",
                json={"name": name, "email": email, "availabilities": availabilities})


@mcp.tool()
def invite(poll_id: str, emails: list[str], required: bool = True) -> dict:
    """Email personal invite links. required=False marks optional invitees —
    only required ones gate the convergence light."""
    return _req("POST", f"/polls/{poll_id}/invite",
                json={"emails": emails, "required": required})


@mcp.tool()
def nudge(poll_id: str, emails: list[str] | None = None, force: bool = False) -> dict:
    """Smart reminders, idempotent and safe to repeat: pending invitees (max
    once/day) and people who haven't seen newly added dates. Restrict with
    emails=[...]; force=True mails exactly those now (bypasses gating)."""
    return _req("POST", f"/polls/{poll_id}/nudge",
                json={"emails": emails, "force": force})


@mcp.tool()
def decide(poll_id: str, slot_id: str) -> dict:
    """Fix the final date/slot. Use get_poll first; convergence 'ready' means
    a slot works for everyone."""
    return _req("POST", f"/polls/{poll_id}/decide", json={"slot_id": slot_id})


@mcp.tool()
def email_decision(poll_id: str, note: str = "") -> dict:
    """Mail the decided date to every respondent + invitee with the .ics
    calendar file attached. Optional note goes into the email body."""
    return _req("POST", f"/polls/{poll_id}/email-decision", json={"note": note})


@mcp.tool()
def get_ics(poll_id: str) -> str:
    """The decided slot as an iCalendar (.ics) document (404 until decided)."""
    return _req("GET", f"/polls/{poll_id}/event.ics")


@mcp.tool()
def get_contacts(poll_id: str) -> list:
    """Outbound-mail audit trail for a poll (who was contacted, what kind,
    when), newest first."""
    return _req("GET", f"/polls/{poll_id}/contacts")


@mcp.tool()
def delete_poll(poll_id: str) -> dict:
    """Permanently delete a poll and all its responses/invites."""
    return _req("DELETE", f"/polls/{poll_id}")


if __name__ == "__main__":
    mcp.run()
