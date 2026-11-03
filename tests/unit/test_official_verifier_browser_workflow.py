from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "official-interoperability.yml"


class TestOfficialVerifierBrowserWorkflow(unittest.TestCase):
    def test_every_verifier_capture_lane_selects_the_validated_hosted_browser(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        name = "      - name: Verify runner-provided released-stack browser\n"
        assert text.count(name) == 1
        step = text.split(name, 1)[1].split("\n      - name:", 1)[0]
        condition = re.search(r"^        if: (.+)$", step, re.MULTILINE)
        assert condition is not None, "The hosted-browser step must select its capture lanes explicitly"

        # Evaluate the actual workflow guard's explicit lane alternatives.
        # Every verifier captures review images, even without the final lane's
        # separate released-browser smoke; the other three lanes do neither.
        selected: set[str] = set()
        for clause in condition.group(1).split(" || "):
            match = re.fullmatch(r"matrix\.lane == '([a-z0-9-]+)'", clause)
            assert match is not None, "Use explicit lane comparisons for browser selection"
            assert match.group(1) not in selected
            selected.add(match.group(1))

        cases = {
            "oid4vci-issuer": False,
            "oid4vp-final": True,
            "oid4vp-url-query": True,
            "oid4vp-mdoc": True,
            "haip": True,
            "w3c-v2": False,
            "eudi": False,
        }
        assert selected <= cases.keys()
        for lane, needs_browser in cases.items():
            with self.subTest(lane=lane):
                assert (lane in selected) == needs_browser
        assert text.index(name) < text.index("      - name: Run official lane\n")


if __name__ == "__main__":
    unittest.main()
