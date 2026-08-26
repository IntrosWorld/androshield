import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from app.agent.providers import AgentProvider
from app import main
from app.dynamic import ui_agent


XML = '''<?xml version="1.0" encoding="UTF-8"?>
<hierarchy>
  <node package="org.test.app" class="android.widget.EditText" text="" content-desc="Email"
        resource-id="org.test.app:id/email" clickable="true" focusable="true" password="false"
        bounds="[10,20][210,80]" />
  <node package="org.test.app" class="android.widget.Button" text="Continue" content-desc=""
        resource-id="org.test.app:id/continue" clickable="true" focusable="true" password="false"
        bounds="[10,100][210,160]" />
  <node package="com.android.systemui" class="android.widget.Button" text="Settings"
        clickable="true" bounds="[0,0][10,10]" />
</hierarchy>'''


class SequenceProvider(AgentProvider):
    name = "fake"
    model = "ui-test"

    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.tool_sets = []
        self.message_sets = []

    def health(self):
        return {"available": True}

    def next_step(self, messages, tools):
        self.tool_sets.append(tools)
        self.message_sets.append(messages)
        return self.decisions.pop(0)


class UiPolicyTests(unittest.TestCase):
    @patch("app.dynamic.ui_agent.adb.shell")
    def test_foreground_package_falls_back_to_android_15_activity_state(self, shell):
        shell.side_effect = [
            (0, "window output without focus fields", ""),
            (0, "topResumedActivity=ActivityRecord{abc u0 org.test.app/.MainActivity t1}", ""),
        ]
        self.assertEqual("org.test.app", ui_agent._foreground_package("emulator-5554"))

    def test_tree_exposes_only_target_package_and_hides_coordinates(self):
        public, private = ui_agent.parse_ui(XML, "org.test.app")
        self.assertEqual(2, len(public))
        self.assertNotIn("bounds", public[0])
        self.assertNotIn("com.android.systemui", str(public))
        self.assertEqual(110, private["n1"]["x"])

    def test_typing_accepts_only_synthetic_profile_keys(self):
        _public, private = ui_agent.parse_ui(XML, "org.test.app")
        with self.assertRaises(ui_agent.UiAgentError):
            ui_agent._validate({
                "type": "tool", "tool": "type",
                "arguments": {"node_id": "n1", "value_key": "credit_card"},
                "reason": "fill",
            }, private)

    def test_native_tool_reason_argument_is_audited_not_executed(self):
        _public, private = ui_agent.parse_ui(XML, "org.test.app")
        action, args, reason = ui_agent._validate({
            "type": "tool", "tool": "type",
            "arguments": {"node_id": "n1", "value_key": "email", "reason": "fill form"},
            "reason": "provider default",
        }, private)
        self.assertEqual("type", action)
        self.assertEqual({"node_id": "n1", "value_key": "email"}, args)
        self.assertEqual("fill form", reason)

    def test_redundant_native_action_envelope_is_safely_unwrapped(self):
        _public, private = ui_agent.parse_ui(XML, "org.test.app")
        action, args, _reason = ui_agent._validate({
            "type": "tool", "tool": "type", "reason": "provider default",
            "arguments": {"type": "tool", "tool": "type", "reason": "fill email",
                          "arguments": {"node_id": "n1", "value_key": "email"}},
        }, private)
        self.assertEqual("type", action)
        self.assertEqual({"node_id": "n1", "value_key": "email"}, args)

    def test_nested_allowlisted_tool_is_normalized_then_validated(self):
        _public, private = ui_agent.parse_ui(XML, "org.test.app")
        action, args, _reason = ui_agent._validate({
            "type": "tool", "tool": "tap", "reason": "provider default",
            "arguments": {"type": "tool", "tool": "type",
                          "arguments": {"node_id": "n1", "value_key": "email"}},
        }, private)
        self.assertEqual("type", action)
        self.assertEqual("email", args["value_key"])

    def test_high_impact_button_is_blocked(self):
        nodes = {"n1": {"clickable": True, "editable": False,
                         "label": "Transfer money now", "x": 1, "y": 1}}
        with self.assertRaises(ui_agent.UiAgentError):
            ui_agent._validate({
                "type": "tool", "tool": "tap", "arguments": {"node_id": "n1"},
                "reason": "advance",
            }, nodes)

    def test_profile_is_stable_and_uses_reserved_domain(self):
        first = ui_agent.synthetic_profile("org.test.app")
        self.assertEqual(first, ui_agent.synthetic_profile("org.test.app"))
        self.assertTrue(first["email"].endswith("@example.invalid"))

    def test_png_dimensions_reads_header_only(self):
        png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + (1080).to_bytes(4, "big") + (1920).to_bytes(4, "big")
        self.assertEqual((1080, 1920), ui_agent._png_dimensions(png))
        self.assertIsNone(ui_agent._png_dimensions(b"not a png"))

    def test_model_image_downscales_without_changing_coordinate_source(self):
        from io import BytesIO
        from PIL import Image
        source = BytesIO()
        Image.new("RGB", (1080, 1920), "white").save(source, "PNG")
        prepared = ui_agent._model_image(source.getvalue())
        with Image.open(BytesIO(prepared)) as image:
            self.assertLessEqual(max(image.size), 640)
            self.assertEqual("JPEG", image.format)

    def test_visual_action_is_bounded_and_labeled(self):
        action, args, _reason = ui_agent._validate({
            "type": "tool", "tool": "tap_visual",
            "arguments": {"x_percent": 50, "y_percent": 40, "label": "Digit 7"},
            "reason": "calculator button is not in accessibility tree",
        }, {}, (1080, 1920))
        self.assertEqual("tap_visual", action)
        self.assertEqual(50.0, args["x_percent"])
        for arguments in (
            {"x_percent": 1, "y_percent": 40, "label": "Digit 7"},
            {"x_percent": 50, "y_percent": 40, "label": "Pay now"},
            {"x_percent": 50, "y_percent": 40, "label": ""},
        ):
            with self.assertRaises(ui_agent.UiAgentError):
                ui_agent._validate({"type": "tool", "tool": "tap_visual",
                                    "arguments": arguments, "reason": "test"}, {}, (1080, 1920))

    def test_qwen_compact_visual_action_and_1000_grid_are_normalized(self):
        action, args, _reason = ui_agent._validate({
            "type": "tap_visual",
            "arguments": {"x_percent": "500", "y_percent": "380", "label": "7"},
            "reason": "visible keypad button",
        }, {}, (1080, 1920))
        self.assertEqual("tap_visual", action)
        self.assertEqual(50.0, args["x_percent"])
        self.assertEqual(38.0, args["y_percent"])

    def test_visual_type_accepts_only_synthetic_profile_key(self):
        with self.assertRaises(ui_agent.UiAgentError):
            ui_agent._validate({
                "type": "tool", "tool": "type_visual",
                "arguments": {"x_percent": 50, "y_percent": 40,
                              "label": "Account", "value_key": "bank_account"},
                "reason": "fill",
            }, {}, (1080, 1920))

    @patch("app.dynamic.ui_agent.adb.shell", return_value=(0, "", ""))
    def test_visual_tap_converts_percentage_to_device_coordinate(self, shell):
        result = ui_agent._execute("tap_visual", {
            "x_percent": 25.0, "y_percent": 50.0, "label": "Digit 7",
        }, {}, {}, "emulator-5554", (1080, 1920))
        self.assertEqual(0, result[0])
        shell.assert_called_once_with(["input", "tap", "270", "960"],
                                      serial="emulator-5554", timeout=10)

    def test_tap_on_labeled_editable_field_becomes_synthetic_type(self):
        _public, private = ui_agent.parse_ui(XML, "org.test.app")
        action, args, reason = ui_agent._validate({
            "type": "tool", "tool": "tap", "arguments": {"node_id": "n1"},
            "reason": "select email",
        }, private)
        self.assertEqual("type", action)
        self.assertEqual("email", args["value_key"])
        self.assertIn("synthetic email", reason)

    @patch("app.dynamic.ui_agent._foreground_package", return_value="org.test.app")
    @patch("app.dynamic.ui_agent._execute", return_value=(0, "", ""))
    @patch("app.dynamic.ui_agent._dump_ui", return_value=XML)
    def test_exploration_executes_validated_sequence(self, _dump, execute, _foreground):
        provider = SequenceProvider([
            {"type": "tool", "tool": "type",
             "arguments": {"node_id": "n1", "value_key": "email"}, "reason": "fill"},
            {"type": "final", "reason": "done"},
        ])
        result = ui_agent.explore("org.test.app", "emulator-5554", provider, max_steps=3)
        self.assertEqual("completed", result["status"])
        self.assertEqual("••••••", result["synthetic_profile"]["password"])
        self.assertEqual("email", result["audit"][0]["value_key"])
        self.assertTrue(provider.tool_sets[0])
        execute.assert_called_once()

    @patch("app.dynamic.ui_agent.adb.shell", return_value=(0, "", ""))
    @patch("app.dynamic.ui_agent._foreground_package", return_value="com.android.chrome")
    @patch("app.dynamic.ui_agent._execute", return_value=(0, "", ""))
    @patch("app.dynamic.ui_agent._dump_ui", return_value=XML)
    def test_external_surface_is_closed(self, _dump, _execute, _foreground, shell):
        provider = SequenceProvider([
            {"type": "tool", "tool": "tap", "arguments": {"node_id": "n2"},
             "reason": "continue"},
            {"type": "final", "reason": "done"},
        ])
        result = ui_agent.explore("org.test.app", "emulator-5554", provider, max_steps=3)
        self.assertEqual("contained", result["audit"][0]["status"])
        shell.assert_called_with(["input", "keyevent", "KEYCODE_BACK"],
                                 serial="emulator-5554", timeout=10)

    @patch.dict("os.environ", {"UI_AGENT_VISION_ENABLED": "true"})
    @patch("app.dynamic.ui_agent._foreground_package", return_value="org.test.app")
    @patch("app.dynamic.ui_agent._execute", return_value=(0, "", ""))
    @patch("app.dynamic.ui_agent.adb.screenshot_png")
    @patch("app.dynamic.ui_agent._dump_ui", return_value="<hierarchy />")
    def test_vision_fallback_sends_image_and_audits_coordinates(
            self, _dump, screenshot, _execute, _foreground):
        png = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
               + (1000).to_bytes(4, "big") + (2000).to_bytes(4, "big"))
        screenshot.return_value = (png, "")
        provider = SequenceProvider([{
            "type": "tool", "tool": "tap_visual",
            "arguments": {"x_percent": 50, "y_percent": 40, "label": "Digit 7"},
            "reason": "visible calculator key",
        }, {"type": "final", "reason": "done"}])
        provider.name = "ollama"
        result = ui_agent.explore(
            "org.test.app", "emulator-5554", provider, max_steps=2, mode="vision")
        self.assertEqual("vision", result["mode"])
        self.assertEqual(1, result["vision_actions"])
        self.assertEqual(2, result["screenshots_seen"])
        self.assertTrue(provider.message_sets[0][-1].get("images"))
        self.assertEqual([], provider.tool_sets[0])
        self.assertEqual({"x": 50.0, "y": 40.0},
                         result["audit"][0]["coordinates_percent"])

    @patch.dict("os.environ", {"UI_AGENT_VISION_ENABLED": "true"})
    @patch("app.dynamic.ui_agent.adb.screenshot_png")
    @patch("app.dynamic.ui_agent._dump_ui", return_value=XML)
    def test_tree_mode_does_not_send_screenshots(self, _dump, screenshot):
        provider = SequenceProvider([{"type": "final", "reason": "done"}])
        provider.name = "ollama"
        result = ui_agent.explore(
            "org.test.app", "emulator-5554", provider, max_steps=1, mode="tree")
        self.assertEqual("tree", result["mode"])
        self.assertFalse(result["vision_enabled"])
        self.assertNotIn("images", provider.message_sets[0][-1])
        screenshot.assert_not_called()


class UiAgentApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_endpoint_refuses_ui_agent_when_disabled(self):
        upload = MagicMock(filename="sample.apk")
        with patch.object(main.dyn_sandbox, "status", return_value={"available": True}), \
             patch.object(main.ui_agent, "health", return_value={"enabled": False}):
            with self.assertRaises(HTTPException) as context:
                await main.dynamic_analyze(upload, 5, False, True, "emulator-5554")
        self.assertEqual(409, context.exception.status_code)

    async def test_endpoint_refuses_non_sandbox_target(self):
        upload = MagicMock(filename="sample.apk")
        state = {"available": True, "serial": None, "devices": [{
            "serial": "emulator-5556", "avd_name": "PersonalPhone",
        }]}
        with patch.object(main.dyn_sandbox, "status", return_value=state), \
             patch.object(main.ui_agent, "health", return_value={"enabled": True}):
            with self.assertRaises(HTTPException) as context:
                await main.dynamic_analyze(upload, 5, False, True, "emulator-5556")
        self.assertEqual(400, context.exception.status_code)
        self.assertIn("dedicated AVD", context.exception.detail)

    async def test_endpoint_refuses_vision_mode_when_unavailable(self):
        upload = MagicMock(filename="sample.apk")
        state = {"available": True, "serial": "emulator-5554", "devices": [{
            "serial": "emulator-5554", "avd_name": "FraudSandbox",
        }]}
        with patch.object(main.dyn_sandbox, "status", return_value=state), \
             patch.object(main.ui_agent, "health", return_value={
                 "enabled": True, "vision_enabled": False,
             }):
            with self.assertRaises(HTTPException) as context:
                await main.dynamic_analyze(
                    upload, 5, False, True, "emulator-5554", "vision")
        self.assertEqual(409, context.exception.status_code)


if __name__ == "__main__":
    unittest.main()
