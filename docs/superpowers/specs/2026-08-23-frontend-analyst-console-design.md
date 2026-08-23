# Frontend Analyst Console Design

## Goal

Refresh the existing single-page APK analysis dashboard so its main actions are easier to understand and operate, while preserving every current API contract and the safety boundary between static and dynamic analysis.

## Design direction

The page remains a dark, high-density security analyst console. Cyan stays the single product accent; amber is reserved for the emulator warning/action and severity colors remain data semantics. The interface uses a soft 14–16 px card radius, 10–12 px control radius, restrained shadows, and short state transitions. It does not add a framework, build step, font download, or JavaScript dependency.

## Information hierarchy

- A compact header communicates product identity, static-analysis safety, and service health.
- The upload area is the first task and clearly displays idle, drag-over, selected, invalid, and analyzing states.
- A small workflow rail explains the sequence: upload, static triage, evidence review.
- Result actions are grouped by intent: primary investigation, secondary exports, and explicitly amber dynamic execution.
- Evidence panels retain their current order and IDs so rendering logic and API behavior remain compatible.

## Interaction design

- Shared button classes provide consistent primary, secondary, warning, icon, hover, focus-visible, active, disabled, and busy states.
- Busy buttons keep their width, expose `aria-busy`, disable repeat submission, and show a CSS spinner without replacing semantic labels with ambiguous text.
- The dropzone is keyboard operable and announces selected-file changes through a live region.
- Errors use `role="alert"`; long-running status messages use `role="status"` and `aria-live="polite"`.
- Focus rings are visible on buttons, inputs, selects, links, the dropzone, and history rows.
- Motion is reduced under `prefers-reduced-motion`.

## Responsive behavior

- The page stays single-column on small screens.
- Header badges and action groups wrap without horizontal clipping.
- Result and evidence grids become two/three columns only at existing medium breakpoints.
- Touch targets are at least roughly 40 px tall and primary actions may expand to full width on narrow screens.

## Files and boundaries

- `frontend/index.html`: design tokens, component classes, semantic markup, and responsive styling.
- `frontend/app.js`: reusable busy-state helper, keyboard/drop feedback, and action-state wiring.
- `backend/tests/test_frontend_contract.py`: static regression checks for required semantics and shared state hooks.

The work must not modify analyzers, risk scoring, API routes, model behavior, APK execution rules, or data rendering semantics.

## Verification

- Run the frontend contract tests first through a red/green cycle.
- Run JavaScript syntax checking with `node --check frontend/app.js` when Node is available.
- Run the backend test suite and report the known three baseline YARA failures independently.
- Serve the app locally and inspect the dashboard at desktop and mobile viewport widths when the runtime is available.
