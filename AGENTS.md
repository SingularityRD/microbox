# MicroBox Agent Guide

MicroBox is an open-source sandbox for running unmodified code under explicit policy.

Use it like this:

```bash
cargo run -- doctor --format json
cargo run -- validate --format json
cargo run -- run --preset ai-agent <command>
cargo run -- workspace init --name demo --source .
cargo run -- workspace run --name demo --preset ai-agent <command>
```

Recommended agent flow:
1. Inspect readiness with `doctor --format json`.
2. Validate policy with `validate --format json`.
3. Run the target command with `run --preset ai-agent` or `workspace run`.
4. Use `workspace snapshot` to create restore points.
5. Use `bench` only for local regression checks or release snapshots.

Why this repository is agent-friendly:
- `doctor` and `validate` can emit JSON.
- The `ai-agent` preset already includes the common API and env allowances for coding agents.
- Persistent workspaces and snapshots are available without Docker or Podman.
- Policy is explicit and user-controlled.
- The default path works without modifying the code you are trying to run.

When proposing or applying changes:
- keep policies explicit
- avoid hidden fallbacks
- prefer machine-readable output where possible
- preserve the "run unmodified code" principle
