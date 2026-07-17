# Skill Governance Control Plane

English | [中文](README.md)

[![CI](https://github.com/PANGKAIFENG/skill-governance-control-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/PANGKAIFENG/skill-governance-control-plane/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A local **SkillOps workbench** for people using multiple AI agents. It turns Skills scattered across
Claude Code, Codex, OpenCode, Qoder, WorkBuddy, and other runtimes into one inspectable inventory.

![Skill inventory dashboard](docs/assets/skill-inventory-dashboard.png)

## The problem

Once you use more than one AI agent, Skills become folders spread across multiple runtimes. It is
hard to tell which copy is current, which agents are missing a Skill, and which edits only exist
locally.

This project starts with a deliberately simple promise: **see what you actually have before deciding
what to sync.**

- Merge same-named Skills into one asset while retaining every runtime instance.
- Surface version mismatches, missing targets, local-only Skills, and scan warnings.
- Refresh a read-only snapshot without silently overwriting or deleting Skills.
- Provide governance primitives for plans, approvals, drift detection, and rollback.

## How it relates to Skillshare

These projects complement each other:

| Tool | Main question | Main actions |
| --- | --- | --- |
| [Skillshare](https://github.com/runkids/skillshare) | How do I install, sync, and update Skills? | `install`, `sync`, `collect`, `update` |
| This project | What Skills do I have, are they healthy, and was a change reviewed? | inventory, drift, plans, approvals, rollback |

The Portal uses read-only Skillshare commands for discovery. Mutating operations remain behind
explicit CLI commands and Adapter safety boundaries.

## Quick start

Requirements: Python 3.11 or 3.12, an initialized
[Skillshare](https://github.com/runkids/skillshare) installation, and
[GitHub CLI](https://cli.github.com/).

```bash
git clone https://github.com/PANGKAIFENG/skill-governance-control-plane.git
cd skill-governance-control-plane

python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .

skillctl portal
```

Open [http://127.0.0.1:8000/](http://127.0.0.1:8000/). The Portal only binds to a loopback address
and stores local state under `~/.local/state/skillctl/` by default.

```bash
skillctl portal --port 8123 --state-dir ./local-state
```

## Safety boundaries

Opening or refreshing the Portal does not install, sync, update, delete, publish, push, or write
Skills back to any agent. Portal approvals record decisions but never invoke `apply` or `rollback`.
Unsupported or unverified Adapter capabilities fail closed.

This is an early, usable MVP focused on individual multi-agent environments. See the Chinese
[roadmap](docs/technical-debt.md), [contribution guide](CONTRIBUTING.md), and
[security policy](SECURITY.md).

## License

[MIT](LICENSE)
