"""Obligation M1 (#48): outbound mail must be authenticated from our domain.

SPF/DKIM/DMARC are DNS records, so Kairos can publish none of them and read none of
them — it cannot verify the authentication exists. What it can do is refuse the
failure it *can* see: sending as an address whose domain nobody could publish
authenticated DNS for us. `KAIROS_HOSTED` is what separates that from a self-hoster's
deployment, which authenticates its own mail and must be left alone.

The tests are grouped as: the primitives, the invariant that self-host and ETH do
not change, the refusals, the admissions, and the wiring from environment to boot.
"""

import os
import subprocess
import sys
from datetime import date, time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kairos import email_service, main, settings

# A poll in the shape the decision-mail route expects (mirrors tests/test_routes.py).
POLL = {
    "id": "p1", "creator_id": "u", "title": "Retro", "description": "d",
    "mode": "time_slot", "timezone": "UTC", "status": "decided",
    "decided_slot_id": "t1", "public_token": "tok123",
    "slots": [{"id": "t1", "date": date(2026, 6, 8),
               "start_time": time(9, 0), "end_time": time(9, 30)}],
}

# Our house brand (ADR-0011), and the dedicated sending subdomain recommended for it.
HOUSE = "nerdmachines.com"
SENDING = "mail.nerdmachines.com"


# -- fixtures ----------------------------------------------------------------


class _FakeRelay:
    """Stands in for _smtp_session(): records what would have been handed to SMTP."""

    def __init__(self):
        self.sent: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def send_message(self, msg):
        self.sent.append(msg)


@pytest.fixture
def relay(monkeypatch):
    """A fake relay, installed, with mail switched on.

    SMTP_HOST is set here rather than per-test so that "was this refused because of
    M1?" is never confused with "was mail simply off?" — is_configured() answers
    False for both, and only one of them is this feature.
    """
    fake = _FakeRelay()
    monkeypatch.setattr(email_service, "SMTP_HOST", "smtp.example.net")
    monkeypatch.setattr(email_service, "_smtp_session", lambda: fake)
    # Once-per-process refusal logging; reset so each test observes its own state.
    monkeypatch.setattr(email_service, "_last_refusal_logged", None)
    return fake


@pytest.fixture
def hosted(monkeypatch):
    """A hosted deployment whose sender is correctly configured, as the baseline."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{SENDING}")
    monkeypatch.setattr(settings, "IMIP_ENABLED", False)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "")


def _refusal() -> str:
    """The refusal message, or "" when outbound is permitted.

    Most assertions go through the stable `code` instead; these are the few where the
    operator-facing wording is itself the thing under test (does it name the knob?).
    """
    refusal = email_service.sender_refusal()
    return refusal.message if refusal else ""


def _code() -> str:
    """The stable refusal code, or "" when outbound is permitted."""
    refusal = email_service.sender_refusal()
    return refusal.code if refusal else ""


def _invite(**kwargs):
    args = {
        "to_email": "someone@elsewhere.example",
        "poll_title": "Retro",
        "invite_url": "https://kairos.example/p/i/tok",
        "sender_name": "Ada",
    }
    args.update(kwargs)
    return email_service.send_invite_email(**args)


# -- primitives --------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("kairos@mail.nerdmachines.com", "mail.nerdmachines.com"),
        ("  Kairos@MAIL.NerdMachines.COM  ", "mail.nerdmachines.com"),  # case + space
        ("<kairos@mail.nerdmachines.com>", "mail.nerdmachines.com"),  # From header form
        ("mail.nerdmachines.com.", "mail.nerdmachines.com"),  # trailing root dot
        ("mail.nerdmachines.com", "mail.nerdmachines.com"),  # bare domain
        ("reply+abc123@mail.nerdmachines.com", "mail.nerdmachines.com"),  # sub-address
        ("kairos+ext@mail.nerdmachines.com", "mail.nerdmachines.com"),  # + extension
        ("", ""),
        ("not-an-address", ""),
        ("a@b@c", ""),
        ("localhost", ""),  # no dot, so not a domain name
        # An IP literal is never a domain name: DKIM's d= and DMARC alignment are both
        # defined over domains, so this can never be authenticated however it is set up.
        ("1.2.3.4", ""),
        ("kairos@1.2.3.4", ""),
        ("2001:db8::1", ""),
        ("kairos@[1.2.3.4]", ""),
    ],
)
def test_domain_of_normalises(raw, expected):
    """Comparison has to survive case, whitespace, angle brackets and trailing dots.

    An operator will type all of these; a strict parser would refuse a correctly
    configured domain over a stray space. The rejects are the other half: anything that
    is not exactly one addr-spec on a domain name returns "" rather than a best guess.
    """
    assert email_service.domain_of(raw) == expected


@pytest.mark.parametrize(
    "value",
    [
        "evil@attacker.test, kairos@mail.nerdmachines.com",  # address list
        "kairos@evil.test; kairos@nerdmachines.com",  # separator variant
        "<evil.test>@nerdmachines.com",  # nested angle brackets
        'evil.test <kairos@nerdmachines.com>',  # real display name (formataddr's own form)
        '"Ada" <kairos@nerdmachines.com>',  # quoted display name
        "Kairos <kairos@nerdmachines.com>, other@attacker.test",
        "kairos@nerdmachines.com other@attacker.test",  # bare whitespace-separated list
    ],
)
def test_domain_of_refuses_anything_that_is_not_one_addr_spec(value):
    """The must-fix: a value that merely *contains* our domain must not be "aligned".

    formataddr() does not escape what it is given, so "evil@attacker.test,
    kairos@our.domain" produces a single From header whose first address is the
    attacker's -- and smtplib derives the envelope sender from exactly that first
    address. A "does it end in our domain" check waves all of these through.
    """
    assert email_service.domain_of(value) == ""


@pytest.mark.parametrize(
    "value",
    ["kairos@mail.nerdmachines.com", "<kairos@mail.nerdmachines.com>",
     "reply+abc123@mail.nerdmachines.com", "kairos@nerdmachines.com"],
)
def test_a_single_wrapped_addr_spec_is_still_accepted(value):
    """Strict must not mean fussy: the forms an operator actually types still work."""
    assert email_service.domain_of(value) != ""


@pytest.mark.parametrize(
    "address",
    [
        "kairos@gmail.com",
        "kairos@googlemail.com",
        "a@hotmail.co.uk",
        "a@outlook.de",
        "a@yahoo.co.jp",
        "a@icloud.com",
        "a@aol.com",
        "a@gmx.de",
        "a@proton.me",
        "a@mail.ru",
        "a@qq.com",
        "a@163.com",
        "a@sbcglobal.net",
        "a@t-online.de",
    ],
)
def test_consumer_providers_are_recognised(address):
    """Country variants are covered too — an exact-match list always misses them."""
    assert email_service.is_consumer_provider(address) is True


@pytest.mark.parametrize(
    "address",
    [
        f"kairos@{HOUSE}",
        f"kairos@{SENDING}",
        "kairos@sub.deep.nerdmachines.com",
        f"mail@{HOUSE}",
        f"weird-name@{HOUSE}",
    ],
)
def test_our_own_domains_are_not_consumer_providers(address):
    """A false positive here would refuse a correct hosted deployment."""
    assert email_service.is_consumer_provider(address) is False


@pytest.mark.parametrize(
    ("domain", "declared", "aligned"),
    [
        (HOUSE, HOUSE, True),  # exact
        (SENDING, HOUSE, True),  # the dedicated sending subdomain
        ("deep.sub.nerdmachines.com", HOUSE, True),
        (HOUSE, SENDING, False),  # not the reverse: apex is not under the subdomain
        ("evil-nerdmachines.com", HOUSE, False),  # suffix without a label boundary
        ("nerdmachines.com.attacker.test", HOUSE, False),  # prefix attack
        ("", HOUSE, False),
        (HOUSE, "", False),
    ],
)
def test_alignment_respects_label_boundaries(domain, declared, aligned):
    """A naive endswith() would wave "evil-nerdmachines.com" through."""
    assert email_service.aligned_with(domain, declared) is aligned


# -- the invariant: self-host and ETH are untouched (ADR-0001/0002) -----------


def test_test_env_does_not_enable_the_gate():
    """So the invariance assertions below are actually testing something."""
    assert settings.HOSTED is False


@pytest.mark.parametrize(
    ("sender", "from_domain"),
    [
        ("noreply@example.org", ""),  # the untouched default
        ("kairos@gmail.com", ""),  # a personal mailbox, exactly what M1 forbids hosted
        ("kairos@gmail.com", HOUSE),  # ...but this deployment is self-hosted
        ("kairos@ethz.ch", "ethz.ch"),
        ("", ""),
        ("garbage", "not a domain"),
    ],
)
def test_self_host_never_refuses(monkeypatch, sender, from_domain):
    """The invariant, stated as a table: with KAIROS_HOSTED unset, no combination
    of sender and domain produces a refusal.

    This is what keeps ADR-0001/0002 true. A self-hoster has configured a relay that
    authenticates *their* mail with *their* DNS, and Kairos refusing to send for
    that reason would break the deployment that has least to do with our brand.
    """
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "FROM_DOMAIN", from_domain)
    monkeypatch.setattr(email_service, "SMTP_FROM", sender)
    monkeypatch.setattr(settings, "IMIP_ENABLED", True)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "lars@gmail.com")

    assert email_service.sender_refusal() is None


def test_self_host_still_sends(relay, monkeypatch):
    """Byte-for-byte the old behaviour: mail goes out, From is the configured sender."""
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "FROM_DOMAIN", "")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    assert email_service.is_configured() is True
    assert _invite(recipient_name="Grace") is True
    assert len(relay.sent) == 1
    assert relay.sent[0]["From"] == "Ada via Kairos <kairos@gmail.com>"
    assert relay.sent[0]["Reply-To"] is None


def test_self_host_logs_nothing_about_m1(relay, monkeypatch, caplog):
    """No gate, no ERROR: a self-hoster must not see an obligation they do not have."""
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")
    with caplog.at_level("WARNING", logger="kairos.mail"):
        _invite()
    assert "M1" not in caplog.text
    assert caplog.text == ""


def test_mail_off_is_not_an_m1_refusal(relay, monkeypatch):
    """With SMTP_HOST unset there is nothing to refuse — the identity is not the
    problem, so reporting a refusal would send an operator to the wrong knob."""
    monkeypatch.setattr(email_service, "SMTP_HOST", "")
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{SENDING}")
    monkeypatch.setattr(email_service, "_last_refusal_logged", None)

    assert email_service.is_configured() is False
    assert email_service.sender_refusal() is None


# -- hosted: the refusals ----------------------------------------------------
#
# These assert the stable `code`, not the prose: the wording is for a human in a log and
# will be edited, whereas the code is what the API contract and the UI branch on. The few
# message assertions below check only that the message *names the knob*, which is
# irreducible to it.


def test_hosted_without_from_domain_refuses(relay, monkeypatch):
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", "")
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{HOUSE}")

    assert email_service.is_configured() is False
    assert _code() == "m1_from_domain_unset"
    assert "KAIROS_FROM_DOMAIN" in _refusal()


@pytest.mark.parametrize("declared", ["1.2.3.4", "2001:db8::1", "not a domain", "mail"])
def test_hosted_from_domain_that_is_not_a_domain_refuses(relay, monkeypatch, declared):
    """An IP literal, or anything that is not a domain name, can never be authenticated.

    DKIM's `d=` tag must be a domain name and DMARC alignment is defined over domain
    names, so `KAIROS_FROM_DOMAIN=1.2.3.4` with `SMTP_FROM=kairos@1.2.3.4` is a
    configuration that looks correct and passes every "does it match?" test while being
    impossible to authenticate. It gets its own code so it cannot be confused with
    "unset", which has a different fix.
    """
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", declared)
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{declared}")

    assert email_service.is_configured() is False
    assert _code() == "m1_from_domain_not_a_domain"


def test_hosted_from_domain_is_a_consumer_provider_refuses(relay, monkeypatch):
    """Declaring a personal mailbox as *the* sending domain is the case M1 names."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", "gmail.com")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    assert email_service.is_configured() is False
    assert _code() == "m1_from_domain_consumer"


def test_hosted_sender_on_a_personal_provider_refuses(relay, monkeypatch):
    """The literal M1 case, with everything else correct: our domain is declared and
    aligned, yet the message would leave as a personal Gmail — damaging a reputation
    that is not ours to spend."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    assert email_service.is_configured() is False
    assert _code() == "m1_address_consumer"
    assert "SMTP_FROM" in _refusal()


@pytest.mark.parametrize(
    "sender",
    [
        "kairos@attacker.test",
        "kairos@evil-nerdmachines.com",
        "kairos@nerdmachines.com.attacker.test",
    ],
)
def test_hosted_misaligned_sender_refuses(relay, monkeypatch, sender):
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", sender)

    assert email_service.is_configured() is False
    assert _code() == "m1_address_misaligned"


@pytest.mark.parametrize(
    "sender",
    [
        # The must-fix: each of these *contains* our domain, and every one of them
        # produced a From header whose first address -- which is what smtplib turns into
        # the envelope sender -- was not ours.
        "evil@attacker.test, kairos@mail.nerdmachines.com",
        "kairos@evil.test; kairos@nerdmachines.com",
        "<evil.test>@nerdmachines.com",
        "kairos@nerdmachines.com, evil@attacker.test",
        'Kairos <kairos@nerdmachines.com>, other@attacker.test',
        # And the plain cases the fix must not start rejecting.
        "kairos@1.2.3.4",
    ],
)
def test_hosted_sender_that_is_not_one_addr_spec_refuses(relay, monkeypatch, sender):
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", sender)

    assert email_service.is_configured() is False
    assert _code() in ("m1_address_unreadable", "m1_address_misaligned")
    assert _invite() is False
    assert relay.sent == []


def test_a_bare_display_name_sender_is_refused_rather_than_silently_mangled(relay, hosted, monkeypatch):
    """formataddr() would happily double-wrap it into 'Ada via Kairos <"Ada" <a@b>>'.

    Kairos supplies its own display name, so a configured one is a configuration error
    rather than something to support.
    """
    monkeypatch.setattr(email_service, "SMTP_FROM", f"Ada <kairos@{SENDING}>")

    assert email_service.is_configured() is False
    assert _code() == "m1_address_unreadable"


@pytest.mark.parametrize("sender", ["noreply@example.org", "kairos@example.com", "kairos@example.net"])
def test_hosted_reserved_placeholder_sender_refuses(relay, monkeypatch, sender):
    """A reserved name is refused as a placeholder, not as a puzzling misalignment.

    Both are refusals but they are different fixes, and SMTP_FROM *defaults* to a
    reserved name — so "you forgot to set it" is the likeliest misconfiguration here
    and should not be reported as a domain mismatch.
    """
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", sender)

    assert email_service.is_configured() is False
    assert _code() == "m1_address_placeholder"


@pytest.mark.parametrize("sender", ["", "kairos", "kairos@", "not-an-address", "a@b@c", "localhost"])
def test_hosted_unreadable_sender_refuses(relay, monkeypatch, sender):
    """No domain means no visible From domain, which cannot be authenticated."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", sender)

    assert email_service.is_configured() is False
    assert _code() == "m1_address_unreadable"


def test_consumer_subdomains_are_recognised(relay, hosted, monkeypatch):
    """mail.gmail.com and the other sub-addressed shapes were unpinned.

    The label list catches them, and the alignment check would refuse them anyway — but
    "refused with a better message" is not the same as "recognised", and the difference
    is exactly what the docs claim about this list.
    """
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@mail.gmail.com")
    monkeypatch.setattr(settings, "IMIP_ENABLED", True)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "kairos@mail.gmail.com")
    assert email_service.is_consumer_provider("kairos@mail.gmail.com") is True
    assert _code() in ("m1_address_consumer", "m1_address_misaligned")


def test_an_aligned_domain_is_never_treated_as_a_consumer_provider(relay, hosted, monkeypatch):
    """The label list over-matches, and an operator's own domain may contain a brand.

    `gmx.nerdmachines.com` looks like GMX by label but is ours, so alignment must win:
    the consumer list is only consulted for domains alignment has already rejected.
    Without this an operator with such a domain has no way out.
    """
    monkeypatch.setattr(settings, "FROM_DOMAIN", "gmx.nerdmachines.com")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@mail.gmx.nerdmachines.com")

    assert email_service.is_consumer_provider("mail.gmx.nerdmachines.com") is True, "label list still matches"
    assert email_service.sender_refusal() is None, "but alignment wins"
    assert _code() == ""


# -- hosted: the admissions --------------------------------------------------


def test_hosted_dedicated_sending_subdomain_is_admitted(relay, hosted):
    """The recommended shape: a dedicated subdomain sends, the apex keeps its own
    reputation. Alignment must not punish it."""
    assert email_service.sender_refusal() is None
    assert email_service.is_configured() is True
    assert _invite() is True
    assert len(relay.sent) == 1


def test_hosted_exact_domain_is_admitted(relay, hosted, monkeypatch):
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{HOUSE}")
    assert email_service.sender_refusal() is None


def test_hosted_is_case_and_format_tolerant(relay, hosted, monkeypatch):
    """An operator typing "Kairos@Mail.NerdMachines.com" is not misconfigured."""
    monkeypatch.setattr(email_service, "SMTP_FROM", " Kairos@Mail.NerdMachines.com ")
    assert email_service.sender_refusal() is None
    assert _invite() is True


def test_sub_addressed_sender_is_admitted(relay, hosted, monkeypatch):
    """reply+<token>@ routing (#34) puts the token in the local part; the From domain
    is what gets authenticated, so sub-addressing must not fail the gate."""
    monkeypatch.setattr(email_service, "SMTP_FROM", f"reply+abc123@{SENDING}")
    assert email_service.sender_refusal() is None
    assert _invite() is True


# -- every send path is behind the gate, not just is_configured() -------------


def test_no_mail_leaves_the_process_when_refused(relay, monkeypatch):
    """The decisive test for the gate's placement.

    Asserting is_configured() is False would still pass if some send path stopped
    consulting it. This drives all four senders and asserts nothing reached the
    relay — an invite, an iMIP REQUEST, an update and the decision mail.
    """
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    assert _invite() is False
    assert (
        email_service.send_imip(
            "someone@elsewhere.example",
            "Invitation",
            "body",
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            "REQUEST",
            "kairos@gmail.com",
            "Kairos",
        )
        is False
    )
    assert (
        email_service.send_update_emails(
            [("a@elsewhere.example", "https://kairos.example/p/i/t")], "Retro", "Ada"
        )
        == 0
    )
    assert (
        email_service.send_decision_email(
            ["a@elsewhere.example", "b@elsewhere.example"],
            "Retro",
            "Mon 2 Jun",
            "https://kairos.example/p/i/t",
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            "Ada",
        )
        == []
    )

    assert relay.sent == [], "a refused identity must not reach the relay"


def test_a_refusal_is_logged_once_with_the_knob_named(relay, monkeypatch, caplog):
    """One ERROR per process, naming the variable to fix.

    Log-once is load-bearing, not tidiness: the API invite path calls
    send_invite_email per recipient, so a 200-person poll would otherwise bury the
    actual cause under 200 identical lines.
    """
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    with caplog.at_level("ERROR", logger="kairos.mail"):
        for _ in range(5):
            _invite()

    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1
    assert "obligation M1" in errors[0].getMessage()
    assert "SMTP_FROM" in errors[0].getMessage()
    assert "gmail.com" in errors[0].getMessage()


def test_the_relay_is_never_even_opened_when_refused(relay, monkeypatch):
    """Cheaper and quieter than connecting and dropping: check before the session."""
    opened = []
    monkeypatch.setattr(email_service, "_smtp_session", lambda: opened.append(1) or relay)
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    _invite()
    assert opened == []


# -- iMIP: the organizer is a From and an ORGANIZER, so it is gated too ------


def test_imip_organizer_off_domain_refuses(relay, hosted, monkeypatch):
    """build_imip_message sends From = the organizer, and the ICS carries
    ORGANIZER:mailto:<same address>. An organizer mailbox off our domain therefore
    fails DMARC for the invitation itself — and strands the reply path."""
    monkeypatch.setattr(settings, "IMIP_ENABLED", True)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "lars@gmail.com")

    assert email_service.is_configured() is False
    assert "KAIROS_IMIP_ORGANIZER" in _refusal()
    assert _invite() is False


def test_imip_organizer_outside_the_sending_subdomain_refuses(relay, hosted, monkeypatch):
    """A dedicated FROM_DOMAIN means the organizer mailbox must live there too.

    A relay that only signs mail.<host> cannot send an invitation whose visible From
    is organizer@<apex> and have it authenticate. That is a real constraint of the
    dedicated-subdomain setup, so it is enforced here rather than discovered in a
    spam folder — and it is why docs/design/mail-auth.md puts the organizer mailbox
    on the sending subdomain.
    """
    monkeypatch.setattr(settings, "FROM_DOMAIN", SENDING)
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{SENDING}")
    monkeypatch.setattr(settings, "IMIP_ENABLED", True)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "organizer@nerdmachines.com")

    assert email_service.sender_refusal() is not None
    assert "KAIROS_IMIP_ORGANIZER" in _refusal()


def test_imip_organizer_on_the_sending_subdomain_is_admitted(relay, hosted, monkeypatch):
    monkeypatch.setattr(settings, "IMIP_ENABLED", True)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", f"organizer@{SENDING}")

    assert email_service.sender_refusal() is None
    assert (
        email_service.send_imip(
            "someone@elsewhere.example",
            "Invitation",
            "body",
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            "REQUEST",
            f"organizer@{SENDING}",
            "Kairos",
        )
        is True
    )
    sent = relay.sent[0]
    assert sent["From"] == f"Kairos <organizer@{SENDING}>"
    assert sent["Reply-To"] is None, "no Reply-To override: replies must reach the organizer"


def test_imip_organizer_is_not_gated_when_imip_is_off(relay, hosted, monkeypatch):
    """IMIP_ORGANIZER is inert unless iMIP actually sends, so a leftover value must
    not silence ordinary invite mail."""
    monkeypatch.setattr(settings, "IMIP_ENABLED", False)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "lars@gmail.com")

    assert email_service.sender_refusal() is None
    assert _invite() is True


# -- the startup report: the "did it rot" artifact ---------------------------


def test_startup_report_states_the_self_host_case(relay, monkeypatch):
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")
    report = email_service.mail_identity_report()
    assert "kairos@gmail.com" in report
    assert "M1 gate is off" in report
    assert "REFUSING" not in report


def test_startup_report_names_the_authenticated_domain_when_configured(relay, hosted):
    report = email_service.mail_identity_report()
    assert f"the M1 gate is ON for {HOUSE}" in report
    assert f"SMTP_FROM=kairos@{SENDING}" in report
    assert "cannot read DNS" in report
    assert "docs/design/mail-auth.md" in report
    assert "REFUSING" not in report


def test_startup_report_leads_with_the_refusal(relay, monkeypatch):
    """A refusal must be the first thing the line says, not a clause at the end."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    report = email_service.mail_identity_report()
    assert report.startswith("outbound mail: REFUSING TO SEND")
    assert "SMTP_FROM" in report


def test_startup_report_reports_mail_off_without_claiming_success(relay, monkeypatch):
    monkeypatch.setattr(email_service, "SMTP_HOST", "")
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)

    report = email_service.mail_identity_report()
    assert "mail is off" in report
    assert "SPF/DKIM" in report  # the records still have to exist for when it comes on
    assert "REFUSING" not in report


def test_app_logs_the_mail_identity_at_startup(monkeypatch, caplog):
    """create_app is where the ETH adapter and every ASGI server land, so the report
    is emitted there rather than only by the `kairos` console script.

    Calls create_app() directly and does not reload kairos.main: reloading would
    rebind kairos.main.app out from under every other test module that imported it.
    """
    import kairos.main as main_mod

    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{SENDING}")
    monkeypatch.setattr(email_service, "SMTP_HOST", "smtp.example.net")

    with caplog.at_level("INFO", logger="kairos.mail"):
        main_mod.create_app()

    assert f"the M1 gate is ON for {HOUSE}" in caplog.text
    assert f"kairos@{SENDING}" in caplog.text


# -- environment -> settings wiring ------------------------------------------


def _import_settings(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src');"
            " from kairos import settings;"
         " print(settings.HOSTED, settings.HOSTED_UNKNOWN, repr(settings.FROM_DOMAIN))",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, **env},
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", "True"),
        ("on", "True"),
        ("true", "True"),
        ("yes", "True"),
        ("TRUE", "True"),
        ("0", "False"),
        ("off", "False"),
        ("", "False"),
    ],
)
def test_hosted_env_is_read_and_normalised(value, expected):
    """Every other test monkeypatches settings, so pin the real env path once."""
    result = _import_settings({"KAIROS_HOSTED": value})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"{expected} False ''"


def test_from_domain_env_is_read_and_normalised():
    result = _import_settings({"KAIROS_FROM_DOMAIN": "  Mail.NerdMachines.com. "})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False False 'mail.nerdmachines.com'"


def test_both_knobs_wire_together():
    """The combination an operator actually sets, read end to end."""
    result = _import_settings({"KAIROS_HOSTED": "1", "KAIROS_FROM_DOMAIN": SENDING})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"True False '{SENDING}'"


def test_a_typo_in_from_domain_fails_loudly_at_send_not_silently():
    """A malformed domain must not raise at import — that would also break
    self-host, where the variable is unused — but it must refuse rather than align
    with everything."""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src');"
            " from kairos import settings, email_service;"
            " settings.HOSTED = True; settings.FROM_DOMAIN = 'not a domain';"
            " print(repr(email_service.sender_refusal()))",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "SMTP_FROM": f"kairos@{HOUSE}"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "KAIROS_FROM_DOMAIN" in result.stdout


# -- the refusal must reach the person who pressed Send (review, must-fix 7) ---


def test_web_ui_says_blocked_rather_than_pointing_at_the_wrong_knob(relay, hosted, monkeypatch):
    """The pre-fix behaviour: a refused send reported "SMTP is not configured".

    That is actively misdirecting -- the operator has configured SMTP correctly and would
    go looking for a setting that is already right. Asserts the redirect key, then the
    text that key renders to, rather than following the redirect into the dashboard.
    """
    from kairos import web

    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")  # refused
    assert web._mail_failure_msg() == "mailblocked"

    rendered = web._msg_text({"msg": web._mail_failure_msg()})
    assert "mail-identity policy" in rendered
    assert "SMTP is not configured" not in rendered
    # The reader of this page is a poll owner, not the operator: no internal addresses.
    assert "gmail.com" not in rendered
    assert "SMTP_FROM" not in rendered


def test_web_ui_still_reports_the_plain_failure_when_nothing_is_blocked(relay, monkeypatch):
    """mailfail must keep its meaning when the gate is not the cause."""
    from kairos import web

    monkeypatch.setattr(settings, "HOSTED", False)  # gate off: self-host behaviour
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")
    assert web._mail_failure_msg() == "mailfail"
    assert "SMTP is not configured" in web._msg_text({"msg": "mailfail"})


def test_a_refused_decision_mail_redirects_with_the_blocked_key(relay, hosted, monkeypatch):
    """End to end through the real route, so the call site is covered rather than the
    helper alone."""
    from kairos import web

    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")
    monkeypatch.setattr(web, "get_user", lambda request: {"uid": "u", "name": "U", "email": "u@x.test"})
    monkeypatch.setattr(web, "get_poll", lambda pid: POLL)
    monkeypatch.setattr(web, "recipient_emails", lambda pid: ["a@x.ch"])
    monkeypatch.setattr(web, "require_csrf", lambda user, form: None)
    monkeypatch.setattr(web, "log_contact", lambda *a, **k: None)

    client = TestClient(main.app, base_url="https://testserver")
    r = client.post("/scheduler/polls/p1/email-decision", data={}, follow_redirects=False)
    assert r.status_code == 302
    assert "msg=mailblocked" in r.headers["location"]


def test_api_tells_the_operator_why_a_send_was_blocked(relay, hosted, monkeypatch):
    """The API caller holds KAIROS_API_KEY, so it gets the actual reason.

    An unattended agent should not retry a send that can never succeed; `email_sent:
    false` alone cannot distinguish "SMTP unset" from "this sender is refused".
    """
    from kairos import api

    monkeypatch.setattr(api, "_get_or_404", lambda pid: POLL)
    monkeypatch.setattr(api, "create_invite", lambda pid, email, required=False, name=None: {
        "id": "i1", "token": "tok", "email": email, "required": required, "name": name})
    monkeypatch.setattr(api, "log_contact", lambda *a, **k: None)
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")  # refused

    client = TestClient(main.app, base_url="https://testserver")
    client.headers["Authorization"] = "Bearer k"
    r = client.post("/scheduler/api/polls/p1/invite", json={"emails": ["a@x.ch"]})

    assert r.status_code == 200, r.text
    entry = r.json()["invites"][0]
    assert entry["email_sent"] is False
    assert entry["email_blocked"] == "m1_address_consumer"
    assert "SMTP_FROM" in entry["blocked_reason"]


def test_api_omits_the_block_fields_when_mail_simply_failed(relay, hosted, monkeypatch):
    """Not blocked, just not sent: the extra keys must not appear, so a caller can branch
    on their presence rather than on a falsy reason."""
    from kairos import api

    monkeypatch.setattr(api, "_get_or_404", lambda pid: POLL)
    monkeypatch.setattr(api, "create_invite", lambda pid, email, required=False, name=None: {
        "id": "i1", "token": "tok", "email": email, "required": required, "name": name})
    monkeypatch.setattr(api, "log_contact", lambda *a, **k: None)
    monkeypatch.setenv("KAIROS_API_KEY", "k")
    monkeypatch.setattr(email_service, "SMTP_HOST", "")  # mail off entirely

    client = TestClient(main.app, base_url="https://testserver")
    client.headers["Authorization"] = "Bearer k"
    r = client.post("/scheduler/api/polls/p1/invite", json={"emails": ["a@x.ch"]})

    entry = r.json()["invites"][0]
    assert entry["email_sent"] is False
    assert "email_blocked" not in entry
    assert "blocked_reason" not in entry


# -- review should-fixes -----------------------------------------------------


def test_a_second_distinct_reason_is_still_logged(relay, hosted, monkeypatch, caplog):
    """The dedup key is the reason, not a bool.

    A bool would silence a *different* misconfiguration for the life of the process. Not
    reachable today (env changes need a restart), but the fix costs nothing.
    """
    monkeypatch.setattr(settings, "FROM_DOMAIN", "")
    def errors():
        # Count records, not the phrase: the refusal message itself ends with
        # "(obligation M1)", so counting occurrences would count two per line.
        return [r for r in caplog.records if r.levelname == "ERROR"]

    with caplog.at_level("ERROR", logger="kairos.mail"):
        _invite()
    assert len(errors()) == 1

    caplog.clear()
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")
    with caplog.at_level("ERROR", logger="kairos.mail"):
        _invite()
    assert len(errors()) == 1, "a different reason must not be swallowed by the log-once guard"


def test_repeating_the_same_reason_is_logged_once(relay, hosted, monkeypatch, caplog):
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")
    with caplog.at_level("ERROR", logger="kairos.mail"):
        for _ in range(4):
            _invite()
    assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 1


@pytest.mark.parametrize("value", ["y", "t", "enabled", "ok", "2", "truthy"])
def test_an_unrecognised_hosted_value_is_reported_as_unknown(relay, monkeypatch, value):
    """A typo must not silently disarm the gate.

    HOSTED stays False, which is the safe direction for self-host, but the boot line says
    so in words rather than reporting a normal self-host configuration.
    """
    monkeypatch.setattr(settings, "HOSTED", False)
    monkeypatch.setattr(settings, "HOSTED_UNKNOWN", True)
    monkeypatch.setattr(settings, "HOSTED_RAW", value)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{HOUSE}")

    report = email_service.mail_identity_report()
    assert f"KAIROS_HOSTED={value!r}" in report
    assert "not a value Kairos recognises" in report
    assert "M1 gate is OFF" in report


def test_the_report_shows_the_normalised_domain_not_the_raw_setting(relay, hosted, monkeypatch):
    """The report is what operators paste into tickets, so it must not print a value the
    gate normalised differently."""
    monkeypatch.setattr(settings, "FROM_DOMAIN", f"  {SENDING}.  ")
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{SENDING}")

    report = email_service.mail_identity_report()
    assert f"the M1 gate is ON for {SENDING}" in report
    assert "  " not in report.split("gate is ON for")[1].split(",")[0]


def test_hosted_env_typo_is_wired_through_a_subprocess():
    """HOSTED_UNKNOWN is derived in settings.py, so pin it in a real process."""
    result = _import_settings({"KAIROS_HOSTED": "y"})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False True ''"

    result = _import_settings({"KAIROS_HOSTED": "1"})
    assert result.stdout.strip() == "True False ''"
