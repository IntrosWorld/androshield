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
        self.assertIn("btn-secondary", tag_with_id(HTML, "workflow-start-btn"))
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

    def test_application_settings_are_accessible_and_secret_safe(self):
        opener = tag_with_id(HTML, "settings-open")
        dialog = tag_with_id(HTML, "settings-dialog")
        self.assertIn('ti ti-settings', HTML)
        self.assertRegex(opener, r'aria-label=["\']Open application settings["\']')
        self.assertRegex(dialog, r'aria-labelledby=["\']settings-title["\']')
        self.assertIn('role="status"', tag_with_id(HTML, "settings-status"))
        for element_id in (
            "setting-external-enabled", "setting-agent-enabled",
            "setting-agent-workflow-enabled", "setting-provider",
            "setting-ollama-url", "setting-ollama-model", "setting-gemini-key",
            "setting-openrouter-model", "setting-openrouter-zdr",
            "setting-openrouter-key", "setting-ui-provider", "setting-ui-model",
            "setting-vt-key", "setting-gguf-path", "settings-import-model",
        ):
            tag_with_id(HTML, element_id)
        self.assertIn('fetch(`${API}/api/settings`', JS)
        self.assertIn('method: "PUT"', JS)
        self.assertIn('type="password"', HTML)
        self.assertIn('<option value="openrouter">OpenRouter API</option>', HTML)
        self.assertIn('if (openrouterKey) data.openrouter_api_key = openrouterKey', JS)

    def test_guided_workflow_is_separate_and_explicitly_approved(self):
        tag_with_id(HTML, "workflow-card")
        tag_with_id(HTML, "workflow-body")
        self.assertIn('role="status"', tag_with_id(HTML, "workflow-status"))
        self.assertIn("Agentic Investigation", HTML)
        self.assertIn("data-workflow-approve", JS)
        self.assertIn("Approval was not sent: re-select the original APK", JS)
        self.assertIn('/api/agent/workflow/${encodeURIComponent(currentId)}', JS)
        self.assertIn("Live investigation activity", JS)
        self.assertIn("not private chain-of-thought", JS)
        tag_with_id(HTML, "workflow-vision")

    def test_ai_review_progress_identifies_actual_provider(self):
        self.assertIn('provider === "ollama" ? "locally through Ollama"', JS)
        self.assertIn("through hosted ${provider}", JS)
        self.assertNotIn("CPU-only local inference", JS)

    def test_results_prioritize_guided_workflow_over_manual_tools(self):
        manual_sandbox = tag_with_id(HTML, "manual-sandbox")
        self.assertTrue(manual_sandbox.lower().startswith("<details"))
        self.assertNotRegex(manual_sandbox, r"\sopen(?:\s|=|>)")
        self.assertIn("Manual Sandbox", HTML)
        self.assertIn("For normal investigations, use Agentic Investigation above", HTML)
        self.assertLess(HTML.index('id="workflow-card"'), HTML.index('id="manual-sandbox"'))
        self.assertLess(HTML.index('id="action-plan"'), HTML.index('id="sandbox"'))

    def test_ai_review_and_history_use_progressive_disclosure(self):
        self.assertIn("hypothesisCards.slice(0, 3)", JS)
        self.assertIn("View full AI Review", JS)
        self.assertIn("s.upload_time", JS)
        self.assertIn("toLocaleString", JS)

    def test_settings_distinguish_read_only_review_from_sandbox_execution(self):
        self.assertIn("AI Review is read-only", HTML)
        self.assertIn("Run AI Review automatically", HTML)
        self.assertIn("this never runs the APK", HTML)

    def test_dynamic_ui_agent_exposes_tree_and_vision_modes(self):
        mode = tag_with_id(HTML, "dyn-ui-agent-mode")
        self.assertIn('value="tree"', HTML)
        self.assertIn('value="vision"', HTML)
        self.assertIn("disabled", mode)
        self.assertIn('fd.append("ui_agent_mode", uiAgentMode)', JS)
        self.assertIn('if (geminiKey) data.gemini_api_key = geminiKey', JS)

    def test_dynamic_run_links_static_case_and_renders_final_score(self):
        self.assertIn('fd.append("sample_id", currentId)', JS)
        self.assertIn("Final score after dynamic analysis", JS)
        self.assertIn("final_score_breakdown", JS)
        self.assertIn("Static ${Number(d.static_score)", JS)

    def test_optional_components_are_explicit_and_source_attributed(self):
        tag_with_id(HTML, "component-list")
        self.assertIn("Optional feature downloads", HTML)
        self.assertIn("official upstream source", HTML)
        self.assertIn("Malware research datasets are never included", HTML)
        self.assertIn('fetch(`${API}/api/components`', JS)
        self.assertIn("data-component-install", JS)
        self.assertIn("pollComponentJob", JS)

    def test_busy_helper_preserves_labels_and_exposes_state(self):
        self.assertIn("function setButtonBusy(", JS)
        self.assertIn('button.setAttribute("aria-busy", String(busy))', JS)
        self.assertIn('button.classList.toggle("btn-busy", busy)', JS)
        self.assertGreaterEqual(JS.count("setButtonBusy("), 7)

    def test_static_analysis_uses_persisted_background_jobs(self):
        self.assertIn('fetch(`${API}/api/analysis-jobs`', JS)
        self.assertIn("async function waitForAnalysisJob", JS)
        self.assertIn("ANALYSIS_PHASE_LABELS", JS)
        self.assertIn("completed.sample_id", JS)

    def test_folder_batch_uses_directory_picker_and_persistent_jobs(self):
        folder_input = tag_with_id(HTML, "folder-input")
        self.assertIn("webkitdirectory", folder_input)
        self.assertIn("multiple", folder_input)
        tag_with_id(HTML, "folder-select-btn")
        tag_with_id(HTML, "batch-card")
        tag_with_id(HTML, "batch-summary")
        tag_with_id(HTML, "batch-list")
        export_button = tag_with_id(HTML, "batch-export-btn")
        self.assertIn("disabled", export_button)
        tag_with_id(HTML, "folder-history-card")
        tag_with_id(HTML, "folder-history-list")
        self.assertIn('/api/analysis-jobs/batch', JS)
        self.assertIn('/api/analysis-batches', JS)
        self.assertIn("async function loadFolderHistory", JS)
        self.assertIn("async function openFolderBatch", JS)
        self.assertIn("/api/samples?exclude_batch=true", JS)
        self.assertIn('form.append("folder_name"', JS)
        self.assertIn("async function waitForBatchJobs", JS)
        self.assertIn("data-batch-open", JS)
        self.assertIn("function exportBatchCsv", JS)
        self.assertIn('"classification", "analysis_status"', JS)
        self.assertIn("Likely malicious", JS)
        self.assertIn("Prevent spreadsheet applications", JS)
        self.assertIn("static analysis only", HTML.lower())

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
