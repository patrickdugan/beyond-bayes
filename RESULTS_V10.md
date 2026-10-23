# ACE v0.10 reproducible results

**Research status:** local Python tests pass on the v0.10 source tree. The repo CI should compile the new Lean module against Lean 4.35 before it is considered formally checked.

## Verification

- `python -m unittest discover -q`: **224 tests passing** in the local environment, including all inherited v0.5–v0.9 regressions.
- `python demo_measurement.py --output /tmp/measure.json --pins /tmp/pins.json` creates deterministic signed start, device, and evidence-log fixtures.
- `python verify_measurement.py /tmp/measure.json --pins /tmp/pins.json` independently replays pinned policies, quorum signatures, canonical instrument samples, witnessed log, and the v2 inference decision.
- `test_root_registry.py` verifies one active principal/resource scope, admin approval, nonrefundable rollover budget, counterfeit closing histories and one-/two-replica rollback behavior.
- `test_measurement_start.py` rejects prestart measurement, forged device and source reports, stale parent scopes, duplicated start nonces, overlapping counter windows, repeated reservation starts, and corrupted journals.
- `test_measurement_gate.py` verifies one-time action consumption and rejection of stale root enrollment after rollover.

## Synthetic data peeking

`python benchmark_measurement.py --trials 100000 --seed 1010 --output results/v10_measurement_benchmark.json` gives:

| Condition | Observed rate | Exact model probability |
|---|---:|---:|
| See 20 independent candidate p-values before allocation | 64.18% | 64.1514% |
| One valid post-start independent observation | 5.046% | 5.0% |

The benchmark uses independent `Uniform(0,1)` draws under the null. The difference illustrates a broken conditional null under advance information. The simulator does not measure physical instrument independence.
