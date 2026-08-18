# smtithy-naive-baseline

**This is not a real project.** It is the naive-baseline arm of a code-review security
experiment, and it deliberately contains hostile pull requests: prompt injection, forged
review context, credential-exfiltration attempts.

The review workflow here is copied from [`ferrumio/pydynox`](https://github.com/ferrumio/pydynox)
(Apache-2.0) and is the *artifact under test* — it is a competent, prompt-defended agent
review, used as the baseline that smtithy's structural defenses are measured against.
Modifications are declared in the workflow header.

Two arms: `agent-review.yml` (defended prompt, default) and `agent-review-undefended.yml`
(security rules stripped, runs only on PRs labelled `arm-b`). The delta measures what
prompt-based defense is worth on its own.

Native redacted experiment records live under `results/`. Cross-arm
comparisons remain in smtithy; see `results/README.md` for the ownership
contract.
