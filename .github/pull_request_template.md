<!--
Every change reaches main through a pull request with green CI. Nothing is
pushed to main directly — see CONTRIBUTING.md.
-->

## What this changes

<!-- One paragraph. What is now possible, or what is now prevented? -->

## Why this design

<!--
The reasoning, not the diff — the diff is already visible below.
If you weighed an alternative and rejected it, say which and why. If the
decision is architectural, add an ADR under docs/adr/ and link it here.
-->

## How to verify

```bash
make dev-up      # if not already running
make verify      # fmt + vet + lint + race tests + build + preflight
```

<!-- Then the specific commands a reviewer should run for THIS change. -->

## Checklist

- [ ] `make verify` passes locally
- [ ] New behaviour has tests; fixed bugs have a regression test
- [ ] Architectural decisions recorded in `docs/adr/`
- [ ] `README.md` / `docs/ARCHITECTURE.md` updated if the contract changed
- [ ] No secrets, credentials or `.env` files in the diff
- [ ] Agents still cannot reach infrastructure except through the harness

## Risk

<!--
What could this break, and how would you notice? For anything touching the
harness, the permission engine or the policy engine, state explicitly what
prevents an agent from escalating past it.
-->
