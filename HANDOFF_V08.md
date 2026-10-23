# ACE v0.8 implementation handoff

Branch: `research/ace-v0.8-campaign-budget` in `patrickdugan/beyond-bayes`.

## Components

- `campaign.py`: exact units, committed campaign policy, authenticated replica journals, strict reserve/finalize/consume state machine, signed event quorum, fail-closed read after speculative minority commit.
- `campaign_certificate.py`: independently pinned composite authorization, mandatory `ace_campaign` action binding, live quorum action gate and durable one-time consume event.
- `verify_campaign.py`: offline, separately pinned verifier with canonical JSON duplicate-key rejection; the signed consumption proof is historical evidence, **not** a live authorization service.
- `demo_campaign.py`: deterministic **test-only** Ed25519 keys, synthetic v2 evidence, signed budget record and replay vectors.
- `benchmark_campaign.py`: repeated-testing and alpha-spending risk illustrations.
- `test_campaign*.py`: rollback/replay/provenance budget attack matrix and small exhaustive accounting reference.
- `lean/ACE/Campaign.lean`: kernel-checked deterministic accounting and event-order lemmas. The conditional-error argument remains on paper.

## Next mathematics

1. Formalize the conditional supermartingale theorem and predictable allocation under the campaign filtration in Lean using an explicit measurable space. Include an infinite-horizon argument.
2. Stress model dependence across attempts. Construct hidden common-cause scenarios where every marginal p-value is individually calibrated but conditional validity fails following adaptive denial-driven selection.
3. Match strong Bayesian decision policies under the **same global** error-budget constraint; report mean regret and false-lockdown tradeoffs with equivalent action costs and data access.

## Next engineering

1. Upgrade v2 witness endorsements to sign the campaign/cluster action policy directly. Current composition pins the action inside the signed reserve event and checks the witnessed log independently.
2. Move anchor replicas onto independently administered storage and authenticate all network traffic. Add a BFT replication protocol or documented quorum service recovery of speculative minority votes.
3. Bind the trusted campaign scope to its parent organization/principal so creating a new campaign cannot reset its budget.
4. Connect executor effect IDs to the same monotonic anchor. A quorum-signed consume before execution prevents replay, while crash after consume can lose an action; an external operation journal must reconcile safely.
5. Attest physical experiment start after the reservation is committed, and keep the entire sensor pipeline from peeking at the current attempt's data before alpha allocation.

## Reproduction

```bash
python -m pip install -r requirements.txt
python -m unittest discover -q
python demo_campaign.py --output /tmp/ace-campaign.json --pins /tmp/ace-campaign-pins.json
python verify_campaign.py /tmp/ace-campaign.json --pins /tmp/ace-campaign-pins.json
python benchmark_campaign.py --trials 200000 --seed 8208 --output results/v08_campaign_benchmark.json
```

Do not deploy for real-money authorization. The replicas are a deterministic local research model, and independence of the statistical data is an external hypothesis.
