# ACE v0.7 verification results

Baseline: stacked on draft PR #3 at `83ec9a9`, retaining v0.5's witnessed
log, anchored witness, and v0.6's clustered conditional inference.

- v2 certificate format: strict domain-separated interpretation policy with
  externally supplied source, witness, cluster, policy and action pins.
- Independent verifier: reconstructs every signed report from the complete
  witnessed log and recomputes all cluster bits and conditional evidence.
- Exhaustive differential check: ternary streams length 0 through 5, budgets
  0, 1, 2, for IID and Markov conditional nulls.
- Conflicting signed evidence: fail-closed even after earlier compatible
  evidence crosses the authorization threshold.
- Action and cluster substitution: rejected via independent commitments.
- Legacy v1 output: rejected on the v2 verification route.
- SQLite action gate: authorized nonces consumed transactionally; denied
  checkpoints advance the trusted log chain so evidence can accrue.
- Reproducible synthetic signed test vector: `vectors/v07_fixture.json` and
  independent externally pinned values in `vectors/v07_pins.json`.

## Commands

```sh
python -m pip install -r requirements.txt
python -m unittest discover -q
python demo_clustered.py --output /tmp/ace_v07.json --pins /tmp/ace_v07_pins.json
python - <<'PY'
import json, subprocess, sys
p=json.load(open('/tmp/ace_v07_pins.json'))
argv=[sys.executable,'verify_clustered.py','/tmp/ace_v07.json']
for k,v in p.items(): argv.extend(['--'+k.replace('_','-'),str(v)])
subprocess.run(argv,check=True)
PY
```

The additional Lean module `lean/ACE/CertificateV2.lean` establishes only
structural implications of pinned policy acceptance. Compiling it does not
prove the cryptographic verifier or the probabilistic inference semantics.

## Interpretation

This patch is an auditability and reproducibility milestone. It does not
claim an improvement over well-specified robust Bayesian inference, which
continues to match ACE under identical assumptions in the v0.6 benchmarks.
