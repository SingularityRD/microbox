# MicroBox

![MicroBox](microbox.png)

**Run unmodified code in one of the safest and fastest policy-first sandboxes.**

MicroBox is designed to be the shortest path from "I have code" to "I can run it under explicit policy" without asking you to rewrite, wrap, or adapt the project first. It keeps the workload intact, makes sandbox rules visible, and gives you a clean execution path on Linux, macOS, and Windows.

This README is the canonical project entrypoint.

What ships today:
- `microbox run <command>` CLI
- `microbox validate`
- `microbox bench` with text, JSON, and Markdown reports
- `microbox bench --peer-target auto` to compare against available sandbox peers
- fresh-sandbox adapter layer for provider-style benchmark execution
- policy compiler and preset resolution
- config file parsing
- `microbox doctor` with policy resolution and readiness reporting
- machine-readable `doctor` and `validate` output for agents and automation
- backend selection: `auto`, `compat`, `secure`
- cross-platform execution on Linux, macOS, and Windows via the compat backend
- Linux secure backend with process-group cleanup, best-effort namespaces, Landlock confinement, seccomp hardening, cgroup delegation fallback, and outbound allowlists

Why this matters:
- **No code changes needed to start**: point MicroBox at a script or repo and run it as-is.
- **Safest where it matters, fastest where it counts**: use secure Linux enforcement where it exists and compat execution everywhere else.
- **Policy stays explicit**: filesystem, network, environment, and resource limits live in config, not hidden defaults.
- **Built for release and demo**: the same binary supports day-to-day execution, validation, and benchmark reporting.

## Install

```bash
cargo install --path crates/microbox-cli --locked
```

If you want to run from source while developing:

```bash
cargo run -- <command>
```

Network note:
- secure backend enforces outbound allowlists on Linux; non-Linux hosts use the compat fallback

Supported platforms:
- Linux: secure backend with the full hardening stack
- macOS and Windows: compat backend for local execution, validation, and benchmarking
- CI runs the shared contract on all three platforms

## Run Code Directly

```bash
cargo run -- run python examples/hello.py
```

That example:
- prints a short status message
- writes a file inside `.microbox-demo/`
- gives new users a zero-setup way to see MicroBox execute real code in the sandbox

## AI Agent Ready

MicroBox is built to fit agent-driven workflows without asking you to change the codebase first.

Use these commands when you want structured output for an LLM agent, orchestrator, or CI bot:

```bash
cargo run -- doctor --format json
cargo run -- validate --format json
cargo run -- run --preset ai-agent python examples/hello.py
```

What the `ai-agent` preset gives you:
- explicit outbound access for OpenAI and Anthropic API endpoints
- environment passthrough for common agent keys like `OPENAI_API_KEY` and `ANTHROPIC_API_KEY`
- deny rules for common secret-heavy environments
- a safe default workspace policy for coding agents

If you are wiring MicroBox into an agent system, start with `doctor --format json`, then `validate --format json`, then run the actual command under `--preset ai-agent`.

## Philosophy

MicroBox is built around a simple idea: sandboxing should be the default, not an afterthought.

What we optimize for:
- **Policy-first execution**: the policy is not decorative; it is the product surface.
- **Safe-by-default behavior**: restrictive network and filesystem controls should be easy to keep enabled.
- **Fast local feedback**: `validate`, `doctor`, and `bench` are first-class workflows, not admin tools.
- **Open comparison**: benchmark output should make it easy to compare MicroBox with public sandbox providers.
- **Practical developer experience**: the sandbox should still feel like normal code execution.

What we do not optimize for:
- “Security theater” with unclear guarantees
- Hidden fallback behavior that silently changes the security model
- Hard-to-debug policy syntax
- A benchmark story that only works in private or opaque environments

In practice this means:
- Linux is the real secure target.
- macOS and Windows are supported for development, validation, and local execution.
- Peer comparisons and release benchmarks are visible, repeatable, and documented.
- The docs should tell you how to run code, how to tighten policy, and how to measure regressions.

## How It Works

MicroBox has three layers:

1. Policy resolution
   - Loads `microbox.toml` if present
   - Applies CLI overrides
   - Resolves filesystem, network, environment, CPU, RAM, disk, and timeout policy
2. Backend selection
   - `auto` picks the strongest backend available on the current platform
   - `secure` forces Linux enforcement
   - `compat` uses local execution fallback for development and non-Linux hosts
3. Command execution
   - `run` launches a sandboxed command
   - `validate` checks policy and config without executing anything
   - `doctor` prints readiness and backend inventory

## Quick start

```bash
cargo run -- run python my_agent.py
cargo run -- doctor
cargo run -- validate
cargo run -- bench --iterations 3
cargo run -- bench --format json --output bench.json
cargo run -- bench --format markdown --baseline-report bench.json
cargo run -- run --backend secure python my_agent.py
```

Backend modes:
- `--backend auto` picks the secure Linux backend when available, otherwise compatibility mode.
- `--backend secure` requires Linux.
- `--backend compat` uses local execution fallback for non-Linux development environments.
- `--backend auto` uses secure Linux enforcement when available, including outbound allowlists on Linux.

## Configuration

MicroBox reads `microbox.toml` from the current directory unless you pass `--config`.

The included example file is [`microbox.toml.example`](microbox.toml.example).

Key sections:

- `[sandbox]`
  - `level`: default isolation profile
  - `timeout`: command runtime ceiling
  - `max_cpu`, `max_ram`, `max_disk`: resource caps
- `[network]`
  - `allow`: endpoints the sandbox can reach
  - `deny_all_other`: deny by default when true
- `[filesystem]`
  - `writable`: directories the command may modify
  - `readonly`: mounted read-only paths
  - `deny`: hard-deny paths that should never be visible
- `[environment]`
  - `passthrough`: env vars that survive into the sandbox
  - `deny`: variable patterns that must be stripped

Recommended release pattern:

1. Start from [`microbox.toml.example`](/C:/Users/anıl/Desktop/sandbox/microbox.toml.example)
2. Trim `network.allow` to the minimum your workload needs
3. Keep `filesystem.deny` strict
4. Use `microbox validate` before `microbox run`

Benchmark reports:
- `--format text` prints a human-readable summary.
- `--format json` produces a machine-readable benchmark report.
- `--format markdown` renders a shareable report table.
- `--profile sequential|staggered|burst|all` controls the benchmark scheduling profile.
- `--stagger-delay-ms <n>` sets the delay between iterations for staggered runs.
- `--baseline-label` names the comparison baseline, defaulting to `E2B-style`.
- `--baseline-source report|e2b` selects a JSON baseline report or a live E2B comparison.
- `--baseline-output <path>` stores a generated E2B baseline report for later reuse.
- `--baseline-report <path>` compares the current JSON report against a previous JSON report.
- `--baseline-source e2b` requires `E2B_API_KEY` and uses the official E2B Python SDK.
- Example E2B compare run:
  - `cargo run -- bench --baseline-source e2b --baseline-output bench.e2b.json --format markdown --output microbox-vs-e2b.md`
- `bench` runs a built-in scenario suite by default:
  - `startup-noop`
  - `shell-echo`
  - `workspace-write`
- If you pass a command after the flags, `bench` measures that exact command instead.
- `bench --peer-target auto` discovers and compares local peer sandbox runtimes such as Docker, Podman, Firejail, bwrap, and E2B when they are available.
- `E2B_DOMAIN` switches the E2B adapter into self-hosted mode when your cluster is deployed from the open-source E2B infra.
- ComputeSDK-style benchmark example:
  - `cargo run --release -- bench --profile all --iterations 100 --warmups 0 --format markdown --output compute-style-bench.md echo benchmark`

## Command Reference

`microbox run`
- Runs a command under the selected policy and backend
- Best for the everyday “run code safely” path

`microbox validate`
- Resolves policy and config only
- Use this before release or before changing policy defaults
- `--format text|json` controls whether the output is human-readable or machine-readable

`microbox doctor`
- Reports backend readiness, peer availability, and policy summary
- Useful for support, docs, and release notes
- `--format text|json` controls whether the output is human-readable or machine-readable

`microbox bench`
- Measures startup overhead, shell roundtrips, and workspace writes
- Can also compare against peer sandboxes and baseline reports

## Release Workflow

Open-source release flow:

1. `cargo run -- doctor`
2. `cargo run -- validate`
3. `cargo run -- bench --profile all --iterations 100 --warmups 0 --format markdown --output microbox-benchmark.md echo benchmark`
4. `cargo build --release`
5. Tag a release as `v*` to produce OS-specific archives and SHA-256 checksums

## Benchmark Leaderboard

Public ComputeSDK leaderboard medians published on March 2, 2026:

| Rank | Provider | Median TTI |
| ---: | --- | ---: |
| 1 | Daytona | 0.20 s |
| 2 | E2B | 0.26 s |
| 3 | Hopx | 0.86 s |
| 4 | Blaxel | 1.58 s |
| 5 | Modal | 1.84 s |
| 6 | CodeSandbox | 2.23 s |
| 7 | Namespace | 2.29 s |
| 8 | Vercel | 2.60 s |
| 9 | Runloop | 3.97 s |

- Source: [ComputeSDK Sandbox Provider Leaderboard](https://www.computesdk.com/benchmarks/)

MicroBox release snapshot from this workspace:

| Profile | Average TTI | Notes |
| --- | ---: | --- |
| Sequential | 13.17 ms | local `compat-local-exec` on Windows |
| Staggered | 13.83 ms | same command path, spaced iterations |
| Burst | 18.62 ms | concurrent launch pressure |
| Compute-style custom command | 12.86 ms | `echo benchmark` under 100 iterations |

- Artifact: [compute-style-all.json](compute-style-all.json)
- These numbers are from the local `compat-local-exec` path on Windows, so they are not apples-to-apples with the hosted provider leaderboard above.
- Use the public leaderboard for market context and the MicroBox snapshot for regression tracking and DX validation.

## Release Verification

```bash
cargo build --release
cargo run --release -- doctor
cargo run --release -- validate
cargo run --release -- bench --peer-target auto --iterations 1 --warmups 0 --format text
```

- Tag pushes that match `v*` produce release archives and SHA-256 checksum files for Linux, macOS, and Windows.
- Manual `workflow_dispatch` runs build the same release artifacts without publishing a GitHub Release.

## Troubleshooting

- `production_ready = no`
  - Expected on macOS and Windows
  - Expected on Linux if the secure backend or kernel features are unavailable
- `E2B_API_KEY is required`
  - Set `E2B_API_KEY` for hosted E2B comparisons
  - Set `E2B_DOMAIN` as well when targeting a self-hosted E2B cluster
- `docker daemon is not reachable`
  - Docker CLI alone is not enough; the daemon must be running
- `peer_targets = ... no`
  - Means the peer runtime was not installed or not reachable on this host

## Example `microbox.toml`

```toml
version = 1

[sandbox]
level = "safe"
timeout = "5m"
max_cpu = 1
max_ram = "512m"
max_disk = "1g"

[network]
allow = ["api.openai.com:443"]
deny_all_other = true

[filesystem]
writable = [".", "/tmp"]
readonly = []

[environment]
passthrough = ["OPENAI_API_KEY", "NODE_ENV"]
```
