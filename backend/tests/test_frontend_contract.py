"""Static contract tests for the no-build dashboard frontend."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
HTML = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
JS = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")


def tag_with_id(source: str, element_id: str) -> str:
    match = re.search(
        rf"<[^>]+\bid=[\"']{re.escape(element_id)}[\"'][^>]*>", source, re.I
    )
    if not match:
        raise AssertionError(f"Element #{element_id} was not found")
    return match.group(0)


class FrontendContractTests(unittest.TestCase):
    def test_dropzone_is_keyboard_accessible(self):
        tag = tag_with_id(HTML, "dropzone")
        self.assertRegex(tag, r'role=["\']button["\']')
        self.assertRegex(tag, r'tabindex=["\']0["\']')
        self.assertIn('aria-describedby="upload-help file-name"', tag)
        self.assertIn('dropzone.addEventListener("keydown"', JS)

    def test_async_feedback_uses_live_regions(self):
        self.assertRegex(tag_with_id(HTML, "file-name"), r'aria-live=["\']polite["\']')
        self.assertRegex(tag_with_id(HTML, "loading"), r'role=["\']status["\']')
        self.assertRegex(tag_with_id(HTML, "error-box"), r'role=["\']alert["\']')
        self.assertRegex(tag_with_id(HTML, "dyn-loading"), r'role=["\']status["\']')

    def test_shared_control_classes_cover_all_action_types(self):
        self.assertIn(".btn-primary", HTML)
        self.assertIn(".btn-secondary", HTML)
        self.assertIn(".btn-warning", HTML)
        self.assertIn(".btn-busy", HTML)
        self.assertIn("prefers-reduced-motion: reduce", HTML)
        self.assertIn("focus-visible", HTML)

        self.assertIn("btn-primary", tag_with_id(HTML, "analyze-btn"))
        self.assertIn("btn-primary", tag_with_id(HTML, "agent-run-btn"))
        self.assertIn("btn-warning", tag_with_id(HTML, "dyn-run-btn"))
        for element_id in ("pdf-btn", "ioc-csv-btn", "ioc-json-btn"):
            self.assertIn("btn-secondary", tag_with_id(HTML, element_id))

    def test_busy_helper_preserves_labels_and_exposes_state(self):
        self.assertIn("function setButtonBusy(", JS)
        self.assertIn('button.setAttribute("aria-busy", String(busy))', JS)
        self.assertIn('button.classList.toggle("btn-busy", busy)', JS)
        self.assertGreaterEqual(JS.count("setButtonBusy("), 7)


if __name__ == "__main__":
    unittest.main()
