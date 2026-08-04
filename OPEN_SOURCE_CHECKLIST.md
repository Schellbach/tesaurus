# Open-source checklist

Use this immediately before and after changing repository visibility.

## Before making the repository public

- [ ] Merge the containment changes only after `Security CI` passes.
- [ ] Re-run Gitleaks against both `git --all` history and the working tree.
- [ ] Confirm there are no funded addresses, real WIFs, RPC cookies, access
      tokens, private logs, or identifying wallet data in any branch or tag.
- [ ] Confirm mainnet and network co-signing fail closed from a clean build.
- [ ] Do not create release binaries or describe any version as production-ready.
- [ ] Keep the README and security limitations visible.

## Immediately after making it public

- [ ] Enable **Settings → Security → Private vulnerability reporting**.
- [ ] Enable secret scanning and push protection.
- [ ] Enable Dependabot alerts and security updates.
- [ ] Protect `main`: require pull requests and the `Security CI` checks; block
      force pushes and branch deletion.
- [ ] Verify <https://github.com/Schellbach/tesaurus/security/advisories/new>
      accepts a private report.
- [ ] Add repository topics/description that clearly say `experimental` and
      `regtest/testnet only`.

## Review intake

Require reports to name the affected commit, exploit prerequisites, violated
invariant, realistic impact, and a regtest reproducer or failing test. Treat
scanner-only output as a lead, not a confirmed vulnerability.
