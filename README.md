<div align="center">

# AegisOps AI

**An autonomous AI DevOps engineer that investigates incidents — and cannot touch your infrastructure without permission.**

</div>

---

> 🚧 **Repository baseline.** This commit establishes the licence, tooling and
> CI pipeline only. All implementation arrives through reviewed pull requests —
> see [CONTRIBUTING.md](CONTRIBUTING.md).

## What this will be

A control plane that runs the on-call loop end to end:

```
observe → hypothesise → gather evidence → diagnose → plan → act → verify → document
```

Seven specialised agents collaborate on an incident. A local LLM does the
reasoning. **A harness does the acting** — and the agents cannot bypass it,
because an agent's most powerful possible output is a description of an action,
never an action.

## Ground rules

| | |
|---|---|
| **Language** | Go 1.24, standard library only — no web framework |
| **AI** | Local models via Ollama; no paid APIs, no egress |
| **Safety** | Every infrastructure action passes a five-gate harness |
| **Process** | Branch → CI → review → merge. `main` is always deployable |

## License

MIT — see [LICENSE](LICENSE).
