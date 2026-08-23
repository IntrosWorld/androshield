# Frontend Analyst Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade the APK analyzer dashboard into a clearer, accessible analyst console without changing backend behavior.

**Architecture:** Keep the existing no-build vanilla HTML/JavaScript architecture. Add a small CSS component layer to `index.html`, wire reusable interaction-state helpers in `app.js`, and protect the markup/behavior contract with Python static tests.

**Tech Stack:** HTML5, Tailwind CDN utilities, native CSS, vanilla JavaScript, Python `unittest`/pytest.

---

### Task 1: Lock the frontend accessibility and state contract

**Files:**
- Create: `backend/tests/test_frontend_contract.py`

- [x] **Step 1: Write failing contract tests**

Create tests that load `frontend/index.html` and `frontend/app.js`, then assert the dropzone has button semantics and keyboard support, status/error live regions exist, shared button classes are used, reduced-motion CSS exists, and JavaScript exposes a `setButtonBusy` helper with `aria-busy` management.

- [x] **Step 2: Verify the tests fail for missing functionality**

Run: `python -m pytest tests/test_frontend_contract.py -q`

Expected: failures for the missing semantic attributes, component classes, and busy-state helper.

- [x] **Step 3: Keep the failing test file unchanged while implementing Tasks 2–3**

The tests are the target contract. Correct production code rather than weakening assertions.

### Task 2: Build the visual component system and page hierarchy

**Files:**
- Modify: `frontend/index.html`

- [x] **Step 1: Add design tokens and component classes**

Define page background layers, panel treatments, button variants, inputs, focus-visible rules, dropzone states, status dots, skeleton/progress animation, and reduced-motion behavior in the existing `<style>` block.

- [x] **Step 2: Improve structural and semantic markup**

Add a skip link and `<main>`, make the dropzone keyboard operable, add live-region roles, and provide accessible labels/tooltips where iconography or state is otherwise ambiguous.

- [x] **Step 3: Apply consistent action hierarchy**

Use the cyan primary button for static analysis and agent investigation, neutral secondary buttons for exports, and the amber warning button only for explicit emulator execution. Preserve all element IDs consumed by `app.js`.

- [x] **Step 4: Improve responsive grouping**

Make header health, file actions, exports, dynamic controls, and result cards wrap cleanly at narrow widths with consistent 40 px control targets.

### Task 3: Wire complete interactive states

**Files:**
- Modify: `frontend/app.js`

- [x] **Step 1: Add reusable busy-state behavior**

Implement `setButtonBusy(button, busy, busyLabel)` to preserve the original label, toggle `disabled` and `aria-busy`, and add/remove the shared busy class.

- [x] **Step 2: Add file-selection and keyboard feedback**

Support Enter/Space activation for the dropzone, toggle drag/selected classes, reject non-APK drops without stale selected state, and retain the live selected-file announcement.

- [x] **Step 3: Apply busy states to asynchronous actions**

Use the helper in static analysis, agent investigation, and dynamic analysis. Restore each action’s correct enabled/disabled state in `finally` blocks.

- [x] **Step 4: Keep dynamic safety copy explicit**

Do not blur static and dynamic behavior: keep emulator execution amber, opt-in, and labeled as isolated AVD execution.

### Task 4: Verify and commit the refresh

**Files:**
- Test: `backend/tests/test_frontend_contract.py`
- Verify: `frontend/index.html`
- Verify: `frontend/app.js`

- [x] **Step 1: Verify frontend tests pass**

Run: `python -m pytest tests/test_frontend_contract.py -q`

Expected: all frontend contract tests pass.

- [x] **Step 2: Verify JavaScript syntax**

Run: `node --check frontend/app.js`

Expected: exit code 0 and no syntax errors.

- [x] **Step 3: Run the full backend suite**

Run: `python -m pytest -q`

Expected: frontend work introduces no new failures; report the known three baseline YARA failures separately if still present.

- [x] **Step 4: Review the diff and whitespace**

Run: `git diff --check` and `git diff --stat`

Expected: no whitespace errors; changes limited to the spec/plan, frontend, and frontend contract test.

- [x] **Step 5: Commit the implementation**

Run: `git add frontend/index.html frontend/app.js backend/tests/test_frontend_contract.py docs/superpowers/plans/2026-08-23-frontend-analyst-console.md && git commit -m "feat: polish frontend analyst console"`
