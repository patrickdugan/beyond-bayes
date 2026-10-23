# v0.5 verification addendum

- 14 new Python tests cover external anchor construction, rolled-back witness
  recovery, equivocation refusal, one- and two-replica rollback, synthetic
  external-commit-before-local-crash, invalid votes, legacy-migration refusal,
  partial publication, and end-to-end witnessed certificate replay.
- 79 inherited tests from v0.4 are retained.
- Total before GitHub CI: 93 Python tests passing locally.
- One additional Lean 4 module (`AnchorQuorum.lean`) specifies conditional
  honest-quorum and recovery implications; kernel verification pending CI.
- No deployed BFT cluster or protected-effect execution is claimed.

---

# ACE v0.4 locally reproduced results | 2026-10-23

## Environment and verification

- Python 3.13; `cryptography` 46.0.4.
- `python -m unittest discover -q`: see final locally generated output;
  initial run 75 passing tests, then 4 durable-witness regression tests added.
- `python quorum_audit.py`: exhaustively enumerates receipt, checkpoint,
  and compromised-witness sets, then writes `results/quorum_intersection.json`.
- `python demo_witnessed.py`: writes a 12-source, four-witness synthetic
  certificate. Its private keys are deterministic fixtures and MUST NOT be
  used outside tests.
- `python verify_witnessed.py`: replays the signed certificate against pinned
  protocol, witness roster, challenge and checkpoint commitments.
- Lean source remains uncompiled locally; CI workflow included.
- No remote GitHub push, CI execution or live asset test.

## Exact quorum table

| n | f | Checkpoint q | Receipt r | Minimum honest receipt/checkpoint | Minimum honest checkpoint/checkpoint |
|---:|---:|---:|---:|---:|---:|
| 4 | 1 | 3 | 3 | 1 | 1 |
| 4 | 1 | 3 | 2 | 0 | 1 |
| 4 | 1 | 2 | 3 | 0 | 0 |
| 7 | 2 | 5 | 5 | 1 | 1 |
| 7 | 2 | 5 | 4 | 0 | 1 |

`test_quorum_audit.py` tests the analytic inequalities against brute-force
sets for all q, r and f values with n from 2 through 7.

## Specific adversarial checks

- Source bit tampering fails Ed25519 verification.
- Dropping or mutating a sealed report changes the checkpoint root.
- A forged log-operator signature fails source-of-truth head verification.
- A duplicated witness signature cannot increase quorum cardinality.
- A source fork seen by an honest signer with a same-epoch receipt blocks the
  omission-bearing checkpoint.
- One corrupt signer still cannot certify a missing report with `q=r=3`.
- With only two receipts and one corrupt witness, omission is accepted:
  the exact negative counterexample is deliberately present in the tests.
- Cross-epoch receipts are ineligible to prove historical intake obligations.
- Same-epoch split views are rejected by the honest witness state, including
  when a new process restores the signed SQLite state snapshot.
- An unauthorized certificate cannot change the gate's pinned head.
- An authorized certificate can be consumed only once across gate restarts.
- RFC 9162-style inclusion/consistency verifies for every position and every
  pair of tree sizes up to 35; mutation and prefix-substitution checks fail.

## Conditions still requiring independent validation

Physical independence of the enrolled sampling domains, source key custody,
operational delivery deadlines, correct corruption bound, witness availability,
and rollback-resistant storage are unverified system dependencies. The
existing 20% correlated-sensor falsifier against nominal alpha=0.05 remains.
