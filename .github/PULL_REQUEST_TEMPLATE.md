<!--
  kora-backend pull request template.
  Fill in every section. Delete a checklist item only if it genuinely does
  not apply, and say why.
-->

## Related issue

Closes #<!-- issue number -->

## What changed

<!-- A short summary of the change and the behavior it adds or fixes. -->

## Why

<!-- The motivation / the problem this solves. Link to ASSUMPTIONS.md if this
     introduces or resolves a judgment call. -->

## Testing

<!-- Paste the relevant `cargo test` output, or describe the manual checks.
     Note any new tests you added and what they pin. -->

```
$ cargo test -p kora-2fa
```

## Checklist

- [ ] `cargo fmt --all --check` is clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo test --workspace` passes against a Postgres 16 database
- [ ] Changed a `sqlx::query!` / `sqlx::query_as!` or a migration? — `.sqlx/`
      regenerated with `cargo sqlx prepare --workspace` and the diff committed
      (`ASSUMPTIONS.md` §15)
- [ ] Changed dependencies? — `cargo deny check` is clean, or a scoped,
      commented exception was added to `deny.toml` with a rationale
      (`ASSUMPTIONS.md` §21)
- [ ] Changed a router hardening layer or one of its constants? —
      `tests/hardening.rs` still passes (`ASSUMPTIONS.md` §18)
- [ ] Changed the `Dockerfile` / `docker-compose.yml`? — `docker compose up
      --build` still serves `GET /health`
- [ ] New judgment call or new env var? — recorded as a numbered section in
      `ASSUMPTIONS.md`, and `docs/` updated if behavior or configuration changed
- [ ] Self-only authorization is preserved on every authenticated endpoint
