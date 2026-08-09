"""The release zips must contain every module the plugin loads at RUNTIME.

Why this file exists: cd.yml stages each package by naming files one by one
(`cp a.py b.py ... dist/stage/<pkg>/`), and a module that is imported lazily
- ed25519_verify.py, which bridge.py loads by path to check licence tokens -
can be missed there without a single test, typecheck or smoke check noticing.
The failure mode is the worst kind: bridge.py swallows the load error and
falls back to "token invalid", so a genuinely licensed customer reads as
UNLICENSED and every my_browser_* tool disappears. Caught exactly once, by hand.

So this does not compare import lists (a heuristic that drifts). It stages
the packages the way cd.yml literally does, loads bridge.py out of that
staged directory, and asserts a real signed assertion still licenses it.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import sys
from pathlib import Path

import pytest

import ed25519_sign

REPO_ROOT = Path(__file__).resolve().parents[2]
CD_WORKFLOW = REPO_ROOT / ".gitea" / "workflows" / "cd.yml"

# The two zips that ship the Python side. chrome-extension/ is not one of
# them (no Python at all).
STAGED_PACKAGES = ["hermes-plugin", "claude-code-plugin"]


def staged_files(package: str) -> list[str]:
    """The files cd.yml copies into dist/stage/<package>/ with a flat `cp`."""
    text = CD_WORKFLOW.read_text(encoding="utf-8")
    pattern = re.compile(rf"^\s*cp ((?:[^\s]+ )+)dist/stage/{re.escape(package)}/$", re.MULTILINE)
    files: list[str] = []
    for match in pattern.finditer(text):
        # Skips the legal-files loop's `cp "$legal" ...` - a shell variable,
        # not a fixed path, and nothing loads LICENSE/NOTICE at runtime.
        files.extend(f for f in match.group(1).split() if "$" not in f and '"' not in f)
    assert files, f"no `cp ... dist/stage/{package}/` line found in cd.yml"
    return files


@pytest.mark.parametrize("package", STAGED_PACKAGES)
def test_staged_package_can_verify_a_licence(package, tmp_path):
    stage = tmp_path / package
    stage.mkdir()
    for name in staged_files(package):
        source = REPO_ROOT / name
        assert source.exists(), f"cd.yml stages {name} into {package}, but it does not exist"
        if source.is_file():
            shutil.copy2(source, stage / source.name)

    # cd.yml also copies the BUILT extension into the claude-code-plugin zip
    # (a separate `cp -r` line, outside the flat file list above). It is what
    # makes that package's extension version knowable, so mirror it here.
    if package == "claude-code-plugin":
        built = REPO_ROOT / "chrome-extension" / "dist"
        if built.is_dir():
            shutil.copytree(built, stage / "chrome-extension" / "dist")

    # Load bridge.py out of the STAGED copy, so anything it reaches for at
    # runtime has to be there too (the module resolves siblings off __file__).
    module_name = f"staged_bridge_{package.replace('-', '_')}"
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, stage / "bridge.py")
    assert spec is not None and spec.loader is not None
    bridge = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = bridge
    try:
        spec.loader.exec_module(bridge)

        instance = bridge.ChromeProfileBridge()
        instance.note_license_assertion(ed25519_sign.valid_assert())
        fields = instance.license_fields()
        assert fields["licenseTokenState"] == "ok", (
            f"{package} cannot verify a licence token - a module it loads at runtime "
            f"is missing from cd.yml's staging list (got {fields['licenseTokenState']!r})"
        )
        assert instance.is_licensed() is True

        # The hermes zip ships no chrome-extension/ (it is a separate
        # download), so this install cannot know the extension's version.
        # It must SAY so rather than compare - reported as v0.0.0-dev, the
        # version check nagged every Hermes user to "reload the extension"
        # forever, on a perfectly current install.
        if package == "hermes-plugin":
            assert bridge.extension_version_is_known() is False, (
                "hermes-plugin now bundles an extension, or the unknown-version "
                "sentinel changed - revisit the version-nag guard in commands.py"
            )
        elif (REPO_ROOT / "chrome-extension" / "dist" / "manifest.json").exists():
            # Only meaningful when the checkout has actually been built; a
            # clean tree has no dist/ and the zip would get one from CI.
            assert bridge.extension_version_is_known() is True
    finally:
        sys.modules.pop(module_name, None)
