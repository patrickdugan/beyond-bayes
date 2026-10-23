# ACE v0.9 results and verification

Reproduce the synthetic null with `python benchmark_scope.py --trials 100000 --seed 9209 --output results/v09_scope_benchmark.json`.

| Twenty potential child attempts | Exact false-open rate | Seeded 100k simulations |
|---|---:|---:|
| Each child resets a fresh 5% allowance | 64.1514% | 64.256% |
| One 5% parent cap, split across all 20 children | 4.8830% | 4.916% |
| Attacker inspects 20 candidate p-values before reserving 5% | 64.1514% | 64.435% |

All p-values are independent Uniform(0,1) under the synthetic null. Preallocation selection violates the conditional-null premise and illustrates why signature and ledger verification alone cannot establish statistical validity. The experiment compares accounting policies, not optimal decision algorithms.

The tests cover full budget exhaustion, duplicate child grants, child-policy and principal/resource substitution, tampered vote signatures, externally pinned head mismatches, one- and two-replica rollback, half-completed writes, scoped action replay, resource substitution, deterministic offline fixtures, duplicate JSON keys, and exhaustive small-budget model paths. `python -m unittest discover -q` also runs every inherited v0.5 through v0.8 regression.

The Lean module `lean/ACE/Scope.lean` contains deterministic grant-cap and monotonicity lemmas. Until GitHub Actions compiles the module, the Lean source is an unchecked proof candidate. The conditional multi-campaign family-wise probability theorem remains a written argument with explicitly identified sampling assumptions.
