# AndroShield native experiment

Optional C++17/pybind11 kernels for keyword presence counting and high-entropy string
counts. The `optimization` branch keeps the normal Python backend and scoring rules.
The experiment is disabled unless `ANDROSHIELD_NATIVE=1` is present in the backend's
launch environment. Missing or incompatible native modules fall back to Python.

## Build and try

From the repository root, using the backend environment:

```powershell
backend/.venv/Scripts/python -m pip install ./backend/native
$env:ANDROSHIELD_NATIVE = '1'
cd backend
.venv/Scripts/python -m uvicorn app.main:app --port 8000
```

The build needs a C++17 compiler and Python development headers. Tested here with
Windows x64, CPython 3.13, and Visual Studio 2022's C++ compiler. pybind11 is a build
dependency of this optional package, not a mandatory application dependency.

Remove `ANDROSHIELD_NATIVE` or set it to `0` before starting the backend to use Python.
No APKs are installed or executed by the kernels or benchmarks. No model/API calls
are involved in the benchmark.

## Design constraints

- Keyword matching preserves one presence count per keyword per string, ASCII word
  boundaries, and first-seen ordering for tied counts. Non-ASCII strings retain the
  original Python Unicode/case-insensitive regex behavior.
- Entropy uses the same 24..512-character candidates and 4.5-bit threshold. Unicode
  and values within 1e-12 of the threshold return to Python for classification.
- All native inputs must be builtin Python strings. String subclasses and unsupported
  batches use Python. Native batch and keyword counts are explicitly bounded.
- Kernels read immutable extracted strings only. They do not parse DEX, decompress
  archives, dereference APK-provided offsets, or execute code from a sample.
- This prototype deliberately holds the GIL while borrowing Python Unicode storage.
  It does not claim multithreaded speedup. A future parallel version would need owned
  buffers, separate memory measurements, and additional concurrency verification.
- C++ extension crashes cannot be caught by a Python fallback. This is an opt-in
  experiment; parity/fuzz tests do not replace a native memory-safety audit.

## Reproduce measurements

### Observed results (2026-10-27)

Windows x64 / CPython 3.13.2 / MSVC 2022, three measured runs per mode after
warmup. These are local exploratory measurements under normal background load,
not a controlled performance guarantee. Raw runs and profiling summaries are in
[the aggregate report](../../docs/optimization-results.json).

| Workload | Python median | Native median | Speedup |
|---|---:|---:|---:|
| Keyword kernel, 20,030 strings | 788.820 ms | 38.234 ms | 20.63x |
| Entropy kernel, same strings | 255.020 ms | 14.577 ms | 17.49x |
| Complete IOC extraction | 1,080.491 ms | 255.655 ms | 4.23x |
| Complete obfuscation analysis, string-only fixture | 283.104 ms | 18.547 ms | 15.26x |
| Full static pipeline, string-only APK | 2,513.800 ms | 1,170.165 ms | 2.15x |
| Full static pipeline, OpenCalculator v53 APK | 6,927.941 ms | 6,545.019 ms | 1.06x |

Every successful warmup and measured run agreed on findings, after the component-list
normalization described below. The real APK improved about **5.5%** in this run;
the Python/native timing ranges overlap, so this small gain needs a larger sample and
more repetitions before a release decision. The large synthetic speedup reflects its
string-heavy, zero-code construction and should not be advertised as general app speed.
Profiling attributes most real-APK work to Androguard DEX basic blocks and cross-references.
The next useful experiment is reducing redundant parser work, with evidence parity,
before considering a much larger native parser rewrite.

Verification: 62 relevant regression/parity tests pass with the compiled extension
enabled and disabled.
The eight dedicated native/fallback tests also pass independently. Coverage includes
Unicode folding, exact threshold cases, word boundaries, seeded fuzz input, unsupported
types, explicit bounds and failure fallback. No APK was executed.

```powershell
backend/.venv/Scripts/python backend/tools/benchmark_native.py --repeats 3 --apk samples/com.darkempire78.opencalculator_53.apk --profile --output docs/optimization-results.json
```

Pass `--apk path/to/a/local.apk` to also measure a real static-analysis input. The
default fixture has a valid manifest and string-only DEX with **zero methods/classes**.
It is not representative of a code-heavy application. Real APKs and profiler files
are kept out of Git; the JSON report includes aggregate timings and parity flags only.

Measurements use warmed imports/caches, alternating Python/native order and
`perf_counter` medians. `cProfile` is used separately to attribute work, never for
Python-vs-C++ speed ratios. Only manifest component membership lists are sorted for
parity because Androguard can enumerate them in different orders across Python-only
runs. Every score and ordered evidence list must still agree.

The previous portable release is unchanged. Before shipping a native portable build,
install this extension in the build environment and verify the frozen artifact includes
the correct Python/OS/architecture module and its runtime libraries. This experiment
does not publish compiled wheels or a replacement desktop release.

Build reference: [pybind11 build systems](https://pybind11.readthedocs.io/en/stable/compiling.html).
Measurement reference: [Python 3.13 profiling guidance](https://docs.python.org/3.13/library/profile.html).
