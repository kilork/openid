# AGENTS.md

OpenID Connect & Discovery client library (`openid` crate), async/await, on top of `reqwest` + `biscuit`.

## Build & test

- Toolchain is pinned via `rust-toolchain.toml` (1.85, MSRV). CI uses exactly 1.85.1.
- `cargo check --all-features` / `cargo test --all-features` — always verify with `--all-features` (enables `uma2`, `microsoft`, doc builds); docs.rs builds with `all`.
- `cargo f` (alias in `.cargo/config.toml`) is the project formatter (enables `wrap_comments`) — always use it instead of plain `cargo fmt` before committing.
- Pre-existing crate warnings (~70) are known; do not fix unrelated warnings in a change.
- No dev-dependencies. Unit tests are plain `#[cfg(test)] mod test` blocks with `#[test]` (no async runtime deps). Prefer extracting sync logic into small helpers to keep them testable that way. Doctests and a README doctest are part of `cargo test` — keep them compiling.

## Code conventions

- Modules are private; public API is re-exported from `src/lib.rs` (rustfmt-sorted `pub use` list). Adding public API = put item in its module + re-export + document.
- `missing_docs` lint is enabled: every public item needs a doc comment. Docstrings use `# Errors` sections listing concrete `Error` variants.
- `README.md` is generated: edit `templates/README.md` (handlebars), run `handlebars-magic templates .` to regenerate; the crate docstring is the README.
- Public API design: no boolean flags — prefer sibling methods (e.g. `jwks` / `jwks_insecure`) and enums over bools. Keep existing signatures stable when extending.
- Internal call chains share one choke point where practical (e.g. `discovered::jwks` is used by `Client::discover`, UMA2 discovery, and the public API) — fix/enforce at the choke point, not per caller.

## Security invariants

- JWKS is trust-critical: `Client::decode_token` verifies ID token signatures against `Client::jwks`. Never add a code path that fetches JWKS over plain http without an explicit opt-out.
- `discovered::jwks` enforces https (`Error::Insecure`); `jwks_insecure` is the explicit per-call escape hatch for dev providers (e.g. Keycloak on `http://localhost:8080`).
- Do not weaken token validation (`validate_token_issuer/aud/exp/nonce`) without an explicit issue discussion.

## Branch and PR flow

- Trunk-based on `master`; feature branches pushed to origin; squash-merged PRs (history shows `(#NN)` suffixes). Reference issues with `Fixes #N` in the PR body.
- Related changes across files touched by multiple issues → stacked PRs (base = parent PR's branch); GitHub retargets after merge. Rebase stacked branches onto `master` after the base merges.
- One PR per issue, containing only that issue's changes.

## Release

- `RELEASE_TYPE=minor|patch|current ./release.sh` on `master` only (`current` = version already bumped manually).
- The script: bumps version (`cargo set-version`), then upgrades + builds the sibling repo `../openid-examples` (its `[patch.crates-io] openid = { path = "../openid" }` makes this a compatibility test against local master — must pass before any release), commits `"openid version X.Y"` + branch `vX.Y` there, regenerates this repo's README via `handlebars-magic templates .`, commits `"Release X.Y.Z"`, tags `vX.Y.Z`, pushes.
- Tag push triggers CI → `cargo publish` to crates.io + GitHub release. No manual publish needed.
- Requires: `cargo set-version`/`cargo upgrade` (cargo-edit), `handlebars-magic`.
