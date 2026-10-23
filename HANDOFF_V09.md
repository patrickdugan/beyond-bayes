# ACE v0.9 engineering and mathematics handoff

Branch: `research/ace-v0.9-risk-scope` in `patrickdugan/beyond-bayes`; stack after merged v0.8.

Source:
- `scope.py`: parent-scope policy, signed nonrefundable campaign grants, quorum-anchored journal and guarded execution path to the child `CampaignActionGate`.
- `verify_scope.py`: independently pinned offline parent grant replay, including duplicate JSON-key rejection.
- `demo_scope.py`: deterministic public synthetic signed vectors. The test private keys are intended for fixtures only.
- `test_scope.py`, `test_scope_cli.py`, `test_scope_model.py`, `test_benchmark_scope.py`: adversarial protocol and statistical comparisons.
- `lean/ACE/Scope.lean`: conditional deterministic implications for the root budget.

Reproduce:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -q
python demo_scope.py --output /tmp/ace-v09-scope.json --pins /tmp/ace-v09-pins.json
python verify_scope.py /tmp/ace-v09-scope.json --pins /tmp/ace-v09-pins.json
python benchmark_scope.py --trials 100000 --seed 9209 --output results/v09_scope_benchmark.json
```

Next proof target: one filtered probability space for every experiment across all descendant campaigns, with predictable parent grants and per-attempt alpha spends. Formalize the stopping-time familywise event bound without assuming independent campaigns. Validate the Python model against a bounded temporal transition-system checker rather than only positive-path tests.

Next engineering target: protect the **scope registry** itself from duplicate or reset parent policies, sign a grant finalization prior to measurement collection, integrate scope-aware policies into witness endorsements, and bind executor effect IDs to the same root. The current scoped gate is a research wrapper; callers that bypass it bypass the parent cap. Real-asset execution is prohibited.
