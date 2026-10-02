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
from pathlib import Path

import pytest

from kairos import email_service, settings

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
    monkeypatch.setattr(email_service, "_refusal_logged", False)
    return fake


@pytest.fixture
def hosted(monkeypatch):
    """A hosted deployment whose sender is correctly configured, as the baseline."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{SENDING}")
    monkeypatch.setattr(settings, "IMIP_ENABLED", False)
    monkeypatch.setattr(settings, "IMIP_ORGANIZER", "")


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
        ("", ""),
        ("not-an-address", ""),
        ("a@b@c", ""),
    ],
)
def test_domain_of_normalises(raw, expected):
    """Comparison has to survive case, whitespace, angle brackets and trailing dots.

    An operator will type all of these; a strict parser would refuse a correctly
    configured domain over a stray space.
    """
    assert email_service.domain_of(raw) == expected


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
    assert email_service._aligned_with(domain, declared) is aligned


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
    monkeypatch.setattr(email_service, "_refusal_logged", False)

    assert email_service.is_configured() is False
    assert email_service.sender_refusal() is None


# -- hosted: the refusals ----------------------------------------------------


def test_hosted_without_from_domain_refuses(relay, monkeypatch):
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", "")
    monkeypatch.setattr(email_service, "SMTP_FROM", f"kairos@{HOUSE}")

    assert email_service.is_configured() is False
    assert "KAIROS_FROM_DOMAIN" in email_service.sender_refusal()


def test_hosted_from_domain_is_a_consumer_provider_refuses(relay, monkeypatch):
    """Declaring a personal mailbox as *the* sending domain is the case M1 names."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", "gmail.com")
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    assert email_service.is_configured() is False
    assert "consumer" in email_service.sender_refusal()


def test_hosted_sender_on_a_personal_provider_refuses(relay, monkeypatch):
    """The literal M1 case, with everything else correct: our domain is declared and
    aligned, yet the message would leave as a personal Gmail — damaging a reputation
    that is not ours to spend."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", "kairos@gmail.com")

    assert email_service.is_configured() is False
    assert "SMTP_FROM" in email_service.sender_refusal()
    assert "consumer" in email_service.sender_refusal()


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
    assert "not on KAIROS_FROM_DOMAIN" in email_service.sender_refusal()


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
    assert "placeholder" in email_service.sender_refusal()


@pytest.mark.parametrize("sender", ["", "kairos", "kairos@", "not-an-address", "a@b@c", "localhost"])
def test_hosted_unreadable_sender_refuses(relay, monkeypatch, sender):
    """No domain means no visible From domain, which cannot be authenticated."""
    monkeypatch.setattr(settings, "HOSTED", True)
    monkeypatch.setattr(settings, "FROM_DOMAIN", HOUSE)
    monkeypatch.setattr(email_service, "SMTP_FROM", sender)

    assert email_service.is_configured() is False
    assert "not an email address" in email_service.sender_refusal()


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
    assert "KAIROS_IMIP_ORGANIZER" in email_service.sender_refusal()
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
    assert "KAIROS_IMIP_ORGANIZER" in email_service.sender_refusal()


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
    assert f"authenticated as {HOUSE!r}" in report
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

    assert f"authenticated as {HOUSE!r}" in caplog.text
    assert f"kairos@{SENDING}" in caplog.text


# -- environment -> settings wiring ------------------------------------------


def _import_settings(env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'src');"
            " from kairos import settings; print(settings.HOSTED, repr(settings.FROM_DOMAIN))",
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
    assert result.stdout.strip() == f"{expected} ''"


def test_from_domain_env_is_read_and_normalised():
    result = _import_settings({"KAIROS_FROM_DOMAIN": "  Mail.NerdMachines.com. "})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False 'mail.nerdmachines.com'"


def test_both_knobs_wire_together():
    """The combination an operator actually sets, read end to end."""
    result = _import_settings({"KAIROS_HOSTED": "1", "KAIROS_FROM_DOMAIN": SENDING})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"True '{SENDING}'"


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
