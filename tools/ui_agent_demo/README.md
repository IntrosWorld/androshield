# UI-agent safe form fixture

This is a deliberately harmless Android activity used to validate that the bounded UI
agent can identify form controls, enter its generated synthetic profile, and create an
action audit. It requests no permissions, performs no network or file I/O, and its
button only updates an on-screen `TextView`.

The launcher activity is a canvas-rendered numeric keypad with deliberately hidden
accessibility descendants. It validates the screenshot-coordinate fallback without
network access, permissions, or sensitive actions. `MainActivity` retains the ordinary
accessibility-based synthetic form fixture.

The generated APK and build artifacts are intentionally not committed.
