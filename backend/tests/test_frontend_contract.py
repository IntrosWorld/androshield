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
    def test_dashboard_uses_local_tabler_icon_system(self):
        stylesheet_path = ROOT / "frontend" / "vendor" / "tabler" / "tabler-icons.min.css"
        font_path = ROOT / "frontend" / "vendor" / "tabler" / "fonts" / "tabler-icons.woff2"
        notice_path = ROOT / "frontend" / "vendor" / "tabler" / "LICENSE.txt"

        self.assertNotIn("<path", HTML, "hand-authored icon paths should not live in page markup")
        self.assertNotIn("stroke-linecap", HTML)
        self.assertGreaterEqual(HTML.count('class="ti ti-'), 13)
        self.assertIn('href="vendor/tabler/tabler-icons.min.css"', HTML)
        self.assertTrue(stylesheet_path.exists(), "the local Tabler stylesheet is missing")
        self.assertTrue(font_path.exists(), "the local Tabler icon font is missing")
        self.assertTrue(notice_path.exists(), "the Tabler source and license notice is missing")

    def test_dashboard_self_hosts_its_interface_fonts(self):
        for filename in (
            "google-sans-flex-latin.woff2",
            "LICENSE-GOOGLE-SANS-FLEX.txt",
        ):
            self.assertTrue((ROOT / "frontend" / "vendor" / "fonts" / filename).exists())
        self.assertIn('font-family: "Google Sans Flex"', HTML)
        self.assertIn('font-family: var(--font-ui) !important', HTML)
        self.assertNotIn("IBM Plex", HTML)

    def test_evidence_chips_use_theme_aware_semantic_colors(self):
        for tone in ("chip-info", "chip-warning", "chip-danger", "chip-success"):
            self.assertIn(f".{tone}", HTML)
            self.assertIn(tone, JS)
        self.assertNotRegex(JS, r'class="chip[^\"]*" style="background')

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

    def test_light_and_dark_theme_switch_is_accessible_and_persistent(self):
        toggle = tag_with_id(HTML, "theme-toggle")
        self.assertRegex(toggle, r'type=["\']button["\']')
        self.assertRegex(toggle, r'aria-pressed=["\']false["\']')
        self.assertIn('data-theme="dark"', HTML)
        self.assertIn('html[data-theme="light"]', HTML)
        self.assertIn('localStorage.getItem("apk-analyzer-theme")', HTML)
        self.assertIn('const THEME_STORAGE_KEY = "apk-analyzer-theme"', JS)
        self.assertIn('localStorage.setItem(THEME_STORAGE_KEY, next)', JS)
        self.assertIn('$("theme-toggle")?.addEventListener("click"', JS)
        self.assertIn('--gauge-track', HTML + JS)

    def test_busy_helper_preserves_labels_and_exposes_state(self):
        self.assertIn("function setButtonBusy(", JS)
        self.assertIn('button.setAttribute("aria-busy", String(busy))', JS)
        self.assertIn('button.classList.toggle("btn-busy", busy)', JS)
        self.assertGreaterEqual(JS.count("setButtonBusy("), 7)

    def test_populated_results_use_the_analyst_workspace(self):
        for element_id in (
            "overview",
            "severity-scale",
            "narrative",
            "static-evidence",
            "threat-intel",
            "sandbox",
            "action-plan",
        ):
            tag_with_id(HTML, element_id)

        self.assertIn('class="evidence-nav"', HTML)
        self.assertIn('class="result-shell workspace-section"', HTML)
        self.assertIn('class="panel-body finding-list"', HTML)
        self.assertIn('class="panel-body recommendation-grid text-sm"', HTML)
        self.assertIn('$("severity-scale").dataset.active', JS)
        self.assertNotIn("—", HTML + JS)
        self.assertNotIn("–", HTML + JS)


if __name__ == "__main__":
    unittest.main()
