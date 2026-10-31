# TUM Group โ€” Git Flow Branching & Release Strategy

This repository strictly enforces the **Git Flow** workflow adapted for TUM Group's enterprise sovereign identity, quantum resilience, cyber telemetry, and governance ecosystems.

---

## 1. Core Branch Architecture

| Branch | Lifecycle | Source | Merges Into | Purpose | Direct Commit Allowed? |
| :--- | :--- | :--- | :--- | :--- | :--- |
| main | Permanent | - | - | Production-ready, signed tags (X.Y.Z). Only merges from elease/* and hotfix/*. | โ **Strictly Prohibited** |
| develop | Permanent | main | main (via release) | Primary integration branch for active development. Nightly builds & test suites. | โ **PR / Merge Only** |
| eature/* | Ephemeral | develop | develop | New capabilities, providers, components. Format: eature/<ticket-key>-<short-description> | โ… Allowed by Feature Owner |
| elease/* | Ephemeral | develop | main & develop | Release stabilization, version bumps, release notes. Format: elease/v<version> | โ… Fixes only |
| hotfix/* | Ephemeral | main | main & develop | Critical production bug fixes. Format: hotfix/<ticket-key>-<short-description> | โ… Hotfix Owner |
| ugfix/* | Ephemeral | develop | develop | Non-critical bug fixes during development. Format: ugfix/<ticket-key>-<description> | โ… Bugfix Owner |

---

## 2. Standard Branch Naming Conventions

All branch names must include the Jira Issue Key or GitHub Issue number where applicable:

- **Features**: eature/SCRUM-123-oauth-pkce-hardening
- **Releases**: elease/v1.2.0
- **Hotfixes**: hotfix/SCRUM-124-null-pointer-token-validator
- **Bugfixes**: ugfix/SCRUM-125-fix-pcsc-reader-timeout

---

## 3. Git Flow CLI Quick Reference

This repository is pre-configured for git-flow (AVH Edition):

### Starting & Finishing a Feature
`ash
# 1. Start feature from develop
git flow feature start SCRUM-123-new-provider

# 2. Make commits following Conventional Commits (feat, fix, refactor, test)
git commit -m "feat(provider): add sovereign trust anchor connector"

# 3. Finish feature (merges into develop, deletes feature branch)
git flow feature finish SCRUM-123-new-provider
`

### Preparing a Release
`ash
# 1. Start release from develop
git flow release start v1.2.0

# 2. Bump version in .csproj / docs / package.json
# Run verification loop: dotnet test, dotnet format

# 3. Finish release (merges into main with tag, merges back to develop)
git flow release finish v1.2.0
`

### Production Emergency Hotfix
`ash
# 1. Start hotfix from main
git flow hotfix start SCRUM-124-critical-security-patch

# 2. Implement fix and verify
git commit -m "security(core): patch token audience bypass"

# 3. Finish hotfix (merges into main with tag, and back into develop)
git flow hotfix finish SCRUM-124-critical-security-patch
`

---

## 4. Orca & Multi-Project Integration

In the Orca multi-project orchestrator:
- The default base ref for all worktrees is set to develop (efs/heads/develop).
- When launching new agent sessions or creating worktrees:
  `ash
  orca worktree create --repo <repo> --name feature-scrum-123 --agent antigravity --prompt "Implement ..."
  `
- **Autonomous Jira & GitHub Sync**: Every feature branch and PR MUST reference the matching Jira Issue (SCRUM-XX) and GitHub Issue.
