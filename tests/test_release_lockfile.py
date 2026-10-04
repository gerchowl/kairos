"""#59: a release must move `uv.lock` with `pyproject.toml`.

`uv.lock` is not only a dependency closure. It also records the *project's* own
version, under `[[package]] name = "kairos-scheduler"`. release-please bumps
`pyproject.toml` and nothing else, so after any release the two disagree by one
version string and the Dockerfile's `uv sync --locked` refuses to build the
image. That is not hypothetical: the 0.10.0 release PR (#52) failed its `image`
job on exactly that line.

The fix is a `release-please-config.json` with an `extra-files` entry that
updates that one field. Two properties of that mechanism are asserted here,
because both fail silently:

  * **The right occurrence.** `uv.lock` has one `version = ` line per package
    (30-odd of them). A replacer that finds "a version line" edits whichever one
    it reaches first, which for a naive first-match is `annotated-doc`, not
    kairos. So the configured jsonpath is resolved against the real file and
    required to designate exactly the `kairos-scheduler` version line and no
    other line — with a positive/negative control, because an assertion that
    cannot fail proves nothing.
  * **The config file is actually read.** release-please-action takes a
    different code path whenever its `release-type` *input* is set
    (`Manifest.fromConfig`), and that path never opens
    release-please-config.json. Leaving `release-type: python` in the workflow
    would make this entire mechanism inert, with no error anywhere.

Two of these assertions can also be had the cheap way, and both are:
`_uv_lock_and_pyproject_agree` is the invariant, and the `lockfile` CI job runs
`uv lock --check` for the part no text comparison can reach (a dependency added
to pyproject without re-locking). This file exists because the CI job and the
tests cannot see each other: `uv run pytest` re-locks first, so by the time any
test reads `uv.lock` the file is already repaired — while the pre-commit hook
uses `--frozen` and does not have that problem, so keeping the check here means
it also runs at commit time.

Like `test_container_deployment.py`, this parses files as text. A real TOML
parser would be a new dependency for a 481-line generated lockfile with a
completely regular shape, and the assertions are about *which line* gets
edited, so a parser would hide the thing being tested.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = (ROOT / "pyproject.toml").read_text()
UV_LOCK = (ROOT / "uv.lock").read_text()
RELEASE_CONFIG = json.loads((ROOT / "release-please-config.json").read_text())
RELEASE_MANIFEST = json.loads((ROOT / ".release-please-manifest.json").read_text())
RELEASE_WORKFLOW = (ROOT / ".github" / "workflows" / "release-please.yml").read_text()

PROJECT_NAME = "kairos-scheduler"
# Synthetic on purpose: this test only ever compares the file against itself, so
# the value is a marker, not a prediction about the next release.
NEXT_VERSION = "9.9.9"

# The jsonpath form this file is able to resolve. Deliberately narrow: anything
# outside it raises, so changing the jsonpath to something this test cannot
# verify fails the suite instead of quietly passing. The narrowing is also what
# makes the negative controls meaningful — see `test_the_resolver_rejects_a_form`.
_JSONPATH = re.compile(
    r"^\$\.package"
    r"\[\?\(@\.(?P<filter>\w+)(?P<unwrap>\.value)?\s*==\s*'(?P<pkg>[^']+)'\)\]"
    r"\.(?P<field>\w+)$"
)


class UnsupportedJsonpath(Exception):
    """The configured jsonpath is outside the subset this test can resolve."""


def _packages(lock: str = UV_LOCK) -> list[dict]:
    """Every `[[package]]` block: its name, its version, and where each sits.

    Anchored at column 0, because the `name = ` lines nested inside a
    `dependencies = [...]` list are indented and are not the package's own name.
    Line numbers are 1-based because they are what the diff assertions report.
    """
    starts = [match.start() for match in re.finditer(r"(?m)^\[\[package\]\]$", lock)]
    entries = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(lock)
        block = lock[start:end]
        entry: dict = {}
        for field in ("name", "version"):
            match = re.search(rf'^{field} = "([^"]+)"', block, re.M)
            if match:
                entry[field] = match.group(1)
                entry[f"{field}_line"] = lock.count("\n", 0, start + match.start()) + 1
        entries.append(entry)
    return entries


def _lock_entry(name: str, lock: str = UV_LOCK) -> dict:
    matches = [entry for entry in _packages(lock) if entry.get("name") == name]
    assert len(matches) == 1, f"expected exactly one {name!r} package in uv.lock, got {len(matches)}"
    return matches[0]


def _pyproject_version(pyproject: str = PYPROJECT) -> str:
    match = re.search(r"^\[project\]$(.*?)^\[", pyproject, re.M | re.S)
    assert match, "pyproject.toml must have a [project] table"
    version = re.search(r'^version = "([^"]+)"', match.group(1), re.M)
    assert version, "pyproject.toml [project] must pin an explicit version"
    return version.group(1)


def _extra_file(path: str) -> dict:
    """The `extra-files` entry release-please will apply to `path`."""
    root = RELEASE_CONFIG["packages"]["."]
    entries = [e for e in root.get("extra-files", []) if e.get("path") == path]
    assert len(entries) == 1, f"exactly one extra-files entry for {path!r}, got {entries}"
    return entries[0]


def _live_workflow(text: str) -> str:
    """The workflow with comments stripped — the header explains `release-type`."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _jsonpath_lines(jsonpath: str, lock: str = UV_LOCK) -> list[int]:
    """1-based line numbers a `$.package[?...].<field>` jsonpath designates.

    This mirrors what release-please's `GenericToml` updater does: resolve the
    jsonpath against the parsed TOML, then splice the new version into each
    matched value, in place. The name lookup is exact and the returned list is
    allowed to be empty, because "matched nothing" is the failure mode that must
    be visible rather than swallowed.
    """
    match = _JSONPATH.match(jsonpath)
    if not match:
        raise UnsupportedJsonpath(jsonpath)
    if match["field"] not in ("name", "version") or match["filter"] != "name":
        raise UnsupportedJsonpath(jsonpath)
    if not match["unwrap"]:
        # A filter written as `@.name` is *not* a different spelling of the one
        # we want — it selects nothing, ever. release-please's parser hands the
        # filter an offset-tagged wrapper object, and an object never equals a
        # string, so every comparison is false. Modelled here as the empty
        # result it really is, so dropping `.value` fails here rather than on
        # the next release.
        return []
    entry = next((e for e in _packages(lock) if e.get(match["filter"]) == match["pkg"]), None)
    if entry is None:
        return []
    line = entry.get(f"{match['field']}_line")
    return [line] if line else []


def _apply_jsonpath(lock: str, jsonpath: str, version: str) -> str:
    """What release-please's release PR would leave in `uv.lock`."""
    field = _JSONPATH.match(jsonpath)["field"]  # _jsonpath_lines already validated it
    lines = lock.splitlines(keepends=True)
    for number in _jsonpath_lines(jsonpath, lock):
        assert lines[number - 1].startswith(f"{field} = "), lines[number - 1]
        lines[number - 1] = f'{field} = "{version}"\n'
    return "".join(lines)


# -- the invariant ----------------------------------------------------------


def test_uv_lock_and_pyproject_agree():
    """The one property everything else exists to protect.

    `uv sync --locked` in the Dockerfile compares these two, so a mismatch is a
    failed image build — found on the release PR, where it is most expensive,
    unless it is caught here.
    """
    assert _lock_entry(PROJECT_NAME)["version"] == _pyproject_version()


def test_the_lockfile_really_does_have_more_than_one_version_line():
    """The hazard is specific: "a version line" is not "the project version".

    Without this, a future refactor that made the lockfile hold exactly one
    version would quietly satisfy the test above for the wrong reason.
    """
    assert len(re.findall(r"(?m)^version = ", UV_LOCK)) > 1


# -- the right occurrence ---------------------------------------------------


def test_release_please_is_pointed_at_the_kairos_lock_entry_by_jsonpath():
    """`type: toml` + jsonpath, not the `generic` updater.

    The generic updater is a marker replacer: it only rewrites a line carrying an
    `x-release-please-version` (or `-start-version`/`-end`) comment, and a
    generated lockfile has none. So `{"type": "generic", "path": "uv.lock"}` —
    the obvious reading of the issue — is a silent no-op: the release ships, the
    skew survives, and the image build fails exactly as before. `type: toml`
    takes the documented targeted path instead.

    (The `.value` in the jsonpath is not a typo. release-please parses the file
    with a TOML parser that wraps every scalar so it can be located by offset,
    so `@.name` compares an object to a string. Without `.value` the filter
    matches nothing — again silently. That is why the resolution is asserted
    against the real file below rather than trusted.)
    """
    entry = _extra_file("uv.lock")
    assert entry["type"] == "toml", f"uv.lock needs the targeted toml updater, got {entry}"
    assert _JSONPATH.match(entry["jsonpath"]), (
        f"jsonpath {entry['jsonpath']!r} is outside the form this test can verify; "
        "widen _JSONPATH before using anything else here"
    )


def test_the_configured_jsonpath_designs_exactly_the_project_version_line():
    """One line, and it is the kairos one."""
    lines = _jsonpath_lines(_extra_file("uv.lock")["jsonpath"])
    assert lines == [_lock_entry(PROJECT_NAME)["version_line"]]


def test_applying_the_jsonpath_changes_that_line_and_nothing_else():
    """The end-to-end shape of the release PR's diff to uv.lock."""
    updated = _apply_jsonpath(UV_LOCK, _extra_file("uv.lock")["jsonpath"], NEXT_VERSION)
    before, after = UV_LOCK.splitlines(), updated.splitlines()
    assert len(before) == len(after), "the lockfile must not gain or lose lines"
    differing = [i for i, (a, b) in enumerate(zip(before, after, strict=True), start=1) if a != b]
    assert differing == [_lock_entry(PROJECT_NAME)["version_line"]]
    # ...and the result is a lockfile that agrees with itself.
    assert _lock_entry(PROJECT_NAME, updated)["version"] == NEXT_VERSION
    assert _lock_entry(PROJECT_NAME, updated)["name"] == PROJECT_NAME


# -- ...which is only meaningful if the lookup discriminates -----------------


def test_a_jsonpath_naming_another_package_selects_a_different_line():
    """Negative control. If this failed to differ, the test above would be vacuous."""
    other = next(e for e in _packages() if e.get("name") not in (PROJECT_NAME, None))
    lines = _jsonpath_lines(f"$.package[?(@.name.value=='{other['name']}')].version")
    assert lines == [other["version_line"]]
    assert lines != [_lock_entry(PROJECT_NAME)["version_line"]]


def test_a_jsonpath_naming_no_package_selects_nothing():
    """The near-miss typo. release-please logs `No entries modified` and moves
    on, so the skew reaches `main` unless something else notices."""
    assert _jsonpath_lines("$.package[?(@.name.value=='kairos')].version") == []


def test_the_resolver_rejects_a_form():
    """A jsonpath this file cannot check must fail the suite, not pass it."""
    for unsupported in (
        "$.package[0].version",
        "$.package[?(@.source.value=='x')].version",
        "$.package[?(@.name.value=='kairos-scheduler')].dependencies",
        "version",
    ):
        with pytest.raises(UnsupportedJsonpath):
            _jsonpath_lines(unsupported)


# -- the config file is not inert -------------------------------------------


def test_the_workflow_does_not_pass_release_type_to_the_action():
    """Why this is the trap rather than the fix.

    release-please-action builds its manifest with `Manifest.fromConfig` when the
    `release-type` input is present, and from the config file otherwise. Those
    are different code paths and only the second one reads
    `release-please-config.json`. With `release-type: python` left in place, the
    `extra-files` entry above would be ignored on every release, and the
    workaround would look like it was working right up until the image build.
    """
    live = _live_workflow(RELEASE_WORKFLOW)
    assert "release-type" not in live, (
        "release-type passed as an action input makes release-please ignore "
        "release-please-config.json entirely; the config belongs in the config file"
    )
    assert "config-file: release-please-config.json" in live
    assert "manifest-file: .release-please-manifest.json" in live


def test_the_manifest_records_the_version_that_was_actually_released():
    """`{".": "0.10.0"}` is what tells release-please where the last release was.

    Switching the action from its inputs to a config file also switches how the
    current version is found: from scanning GitHub Releases, to reading the
    manifest. An absent or stale manifest does not fail loudly — it backfills
    from tags, or bootstraps and re-releases a version that already shipped.
    """
    assert RELEASE_MANIFEST == {".": _pyproject_version()}


def test_the_tag_scheme_stays_version_only():
    """The duplet consumer pins `v0.10.0`-shaped tags by hand.

    Naming a component here would change the tag to
    `kairos-scheduler-v0.11.0`, and nothing in CI would notice until that consumer
    stopped resolving.
    """
    root = RELEASE_CONFIG["packages"]["."]
    assert "component" not in root
    assert root["include-component-in-tag"] is False


def test_the_image_build_still_refuses_a_stale_lockfile():
    """Pin `--locked`.

    `uv sync --locked` is a deliberate security property, not an incidental
    flag: it pins the installed dependency set to `uv.lock` instead of
    re-resolving at build time, so a stale lock fails the build rather than
    silently installing something else. Nothing else in the suite asserts it, so
    a later PR could quietly relax it to `--frozen` -- which tolerates exactly
    the drift this repository just shipped a release for (issue #59).

    Change either arm of this assertion and the security property is gone.
    """
    dockerfile = (ROOT / "Dockerfile").read_text()
    sync_lines = [ln.strip() for ln in dockerfile.splitlines()
                  if "uv sync" in ln and not ln.strip().startswith("#")]
    assert sync_lines, "no `uv sync` found in the Dockerfile -- has the build changed?"
    for line in sync_lines:
        assert "--locked" in line, f"image build no longer pins to uv.lock: {line!r}"
        assert "--frozen" not in line, (
            "--frozen tolerates a stale lockfile; --locked is the guarantee"
        )


def test_the_release_type_stays_python():
    """A missing `release-type` is not caught by any other assertion here.

    release-please reads it to choose its release strategy. Drop it and the real
    library picks `node`, then fails with "Missing required file: package.json"
    on a repository whose root has no package.json -- a baffling message for a
    one-word config omission, and the same class of failure this file exists to
    catch: correct in every assertion, wrong in the config that actually ships.
    """
    root = RELEASE_CONFIG["packages"]["."]
    assert root.get("release-type") == "python", (
        "kairos is a Python project; a missing or wrong release-type makes "
        f"release-please pick the wrong strategy, got {root.get('release-type')!r}"
    )

