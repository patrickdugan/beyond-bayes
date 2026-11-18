# Beyond Bayes: Adversarial Constraint Epistemics (ACE)

## November 18, 2026: Calibrated posterior recovery and disclosure timing (BB-CQ-05)

[Protocol](research/bb_cq05_protocol.md) · [Mathematical derivation](research/bb_cq05_mathematics.md) · [Results](research/bb_cq05_results_20261118.md) · [Exact receipt](results/bb_cq05_exact_v1.json).

BB-CQ-05 fixes when a compressed predictor learns which reports were provisional. When the schedule arrives before encoding, a calibrated valid-count state matches full Bayes throughout correction. Under delayed disclosure, answering every legal named correction exactly requires 4,096 encoder states for twelve old bits, even though the initial regime posterior has only thirteen count labels. The largest label fiber needs ten supplementary fixed-width tag bits if that posterior label is stored separately.

Exact rational enumeration measures how disclosing old values repairs the delayed mixed-count posterior. With six replacements, five individual old-value disclosures recover **72.288984%** of the known Brier gap; all six reach the registered 90% target. A verifier holding the archive can instead send the old corrected-slot match total using **three message bits**, enabling exact numeric recovery. Its archive and verification costs remain part of the system. Every posterior is calibrated under its own information; the score gap measures lost information.

The independent raw-history oracle, finite continuation witnesses, and archive checks are covered by eleven new tests. Run `python -m unittest test_posterior_recovery -v` and `python bb_cq05_exact.py --check results/bb_cq05_exact_v1.json`. This is an exact mathematical development result motivated by CQ04's already observed Brier gap. CQ04 retains `HEADROOM_BLOCKED`; recurrent learning and a protected confirmation study require separate experiments.

## November 18, 2026: Original ECA-04 revision headroom (BB-CQ-04)

[Protocol](research/bb_cq04_protocol.md) · [Registered result](research/bb_cq04_results_20261118.md) · [Exact source-only receipt](results/bb_cq04_exact_v1.json) · [Frozen native GRU development receipt](results/bb_cq04_native_dev_v1.json).

A prospectively specified twelve-sentinel revision fixture retains the original ECA-04 Bayesian channel laws, with independent fair provisional values in 1/3/6 preselected report slots. Exact rational enumeration compares full historical Bayes, externally verified source-aware deltas and the **correct Bayesian posterior given only the aggregate observations**. The primary six-replacement authorization headroom is **0.00620676** cost units per case against a frozen practical minimum of **0.02**, producing the registered `HEADROOM_BLOCKED` verdict. At the same time the exact posterior Brier gap is **0.06446269**, indicating more meaningful calibration than authorization differences for this synthetic task.

A frozen-checkpoint native CPU development run on 256 public deterministic pilot roots finds full GRU replay expected authorization cost **0.196706** versus exact Bayes **0.196611**, while a stale provisional GRU scores **0.263205** with six replacements. This supports the importance of consuming corrected evidence; source-verified online recurrent memory remains untested. The separate public 64-root order-permutation control includes a cost nuisance outlier of **0.1575**, so there is no claimed causal mechanism or 95/95 sham resolution. Historical ECA-04 heldout roots and protected model confirmation samples remain untouched.

Run `python -m unittest test_bb_cq04_core -v` and `python bb_cq04_exact.py --check results/bb_cq04_exact_v1.json`. The optional native runner requires the original SHA-pinned ECA-04 `gru_state_dict.pt` from its [registered archived artifact](https://github.com/MoralityLabAI/Control-Harness/actions/runs/44145067899/artifacts/14355808052); Beyond Bayes CI does not fetch original test rows.

## November 18, 2026: Evidence amendments and verified-delta memory (BB-CQ-03)

[BB-CQ-03](research/bb_cq03_verified_amendment_memory.md) specializes the original ECA-04 single-issuer twelve-sentinel model to individually addressable report amendments. The exact current Bayesian posterior has 13 possible match-count labels, while the 4,096 distinct report histories are pairwise distinguishable by named revisions. Any self-contained exact updater needs at least 12 bits, and a representation retaining the current posterior label requires up to 10 supplementary bits.

[The exact source-only implementation](amendment_memory.py) checks 98,304 report corrections and derives a sharp **0.012832873470** expected squared posterior-vector imitation floor for a source-blind aggregate-only state under an explicitly defined IID original-data and independently assigned overwrite design. A toy versioned archive can issue the old-to-new delta needed for exact numerical updates, provided an independent full-archive verifier authenticates that delta. Neither the digest nor numeric-only updater provides such authority by itself.

Reproduce with `python -m unittest test_amendment_memory -v` and `python benchmark_amendment_memory.py --check results/bb_cq03_exact_v1.json`. The [Lean arithmetic kernel](lean/ACE/AmendmentMemory.lean) proves the conditional count identities and one-step distinctness; its scope excludes the full bit lower-bound theorem and Bayesian risk identity. This is a finite mathematical engineering result, with no new neural confirmation or ACE action authority.

## November 18, 2026: Revocable Bayesian memory and ECA-04 (BB-CQ-02)

[BB-CQ-02 research and results](research/bb_cq02_revocable_bayes_eca04.md) extend the finite continuation quotient to exact ECA-04 three-channel Bayesian inference with separately revocable **hypothetical** evidence groups. The [exact module](revocable_bayes.py) proves by finite continuation witnesses that `g` one-report groups require `3**g` revocation states, even though the current exact posterior has far fewer values. A prospective one-report-per-group observe/revoke contract includes an explicit invalid-event sink. [The committed receipt](results/bb_cq02_exact_v1.json) is independently checked against a pair-product BFS oracle.

A [native frozen-GRU development assay](native_eca04_continuation.py) uses the original ECA-04 16-unit PyTorch checkpoint (caller supplied, hash verified) and 256 public deterministic issuer fixtures. Paired host-simulated reissues correct one matching and one mismatching report within the prefix; this preserves the exact Bayesian posterior and the final six reports while testing learned recurrent output sensitivity. The original source-only local observation found 152 eligible pairs and 3 changes in the model's top-regime classification. This is a development diagnostic, with no new statistical confirmation, physical signer protection or authorization. Original ECA-04 protected heldout seeds were not loaded.

Reproduce the exact part with `python -m unittest test_revocable_bayes test_native_eca04_continuation -v` and `python benchmark_revocable_bayes.py --check results/bb_cq02_exact_v1.json`. The native part requires `gru_state_dict.pt` from the [original registered ECA-04 artifact](https://github.com/MoralityLabAI/Control-Harness/actions/runs/44145067899/artifacts/14355808052).

## November 18, 2026: Continuation-quotient bridge (BB-CQ-01)

[BB-CQ-01 research and exact finite results](research/continuation_quotient_bridge_v0_1.md) connect the merged [Dot Matrix continuation-state model](research/dot_matrix_continuation_sufficiency_v0_1.md) and [source-group identifiability diagnostic](research/broken_verifier_identifiability.md) to BPD delayed causal observability and EvalMath's audit discipline. The new [diagnostic](continuation_quotient.py) checks whether a compressed state can reproduce every declared future output **and** update its own retained label after interventions. It reports shortest counterexample event sequences and the minimal additional fixed-width tag bits required for an exact online repair in a finite deterministic contract.

The [replayable exact receipt](results/continuation_quotient_v1.json) covers 2–5 root revocation fixtures, a delayed-swap observer and 96 deterministic development machines with a separate pair-product BFS oracle. Run `python -m unittest test_continuation_quotient -v` and `python benchmark_continuation_quotient.py --check results/continuation_quotient_v1.json`.

**Evidence status:** finite mathematical derivation and development-only exact checks. No new causal model result or Lean certificate; no extra ACE action authority. The v0.10 conditional e-process/measurement guarantees and matched robust-Bayes equivalence remain unchanged. PR #15 (audit completeness) and PR #16 (theorem-audit allocation) remain separate unmerged research proposals.

## v0.10: immutable root enrollment and signed measurement starts

See [RESEARCH_V10.md](RESEARCH_V10.md), [RESULTS_V10.md](RESULTS_V10.md) and [HANDOFF_V10.md](HANDOFF_V10.md). The new `root_registry.py` admits exactly one active scoped budget per externally pinned principal/resource and permits administrator-approved rollover with signed historical allocations carried forward. `measurement_start.py` binds a witnessed instrument start to the live registry head, parent grant, child reservation and full v2 policy, then signs every sample with a monotone registered instrument counter. `verify_measurement.py` independently replays the full stack and checks that every logged source report has a matching instrument signature and counter.

This is a synthetic acquisition-order model, **not physical timestamp attestation**. The caller supplies sample values to the simulated device and can still pre-peek them. The four SQLite signers and local action lock are research fixtures. All conditional probability guarantees depend on the real sample-generation and information-flow assumptions.

```sh
python -m unittest discover -q
python demo_measurement.py --output /tmp/ace-v10.json --pins /tmp/ace-v10-pins.json
python verify_measurement.py /tmp/ace-v10.json --pins /tmp/ace-v10-pins.json
```


## v0.9: parent-scope error budgets across campaigns

ACE now supports an **externally pinned principal/resource risk scope** that
issues nonrefundable, quorum-signed alpha grants to child campaigns. A child
is admitted only with a scope-derived ID, its exact budget and signer policy,
and a live root grant. `ScopeActionGate` demands a matching `ace_scope`
commitment inside the v2 action and then invokes the existing child
`CampaignActionGate`. The standalone signed-history verifier is `verify_scope.py`.

The central claim is conditional: if each child's attempts satisfy their
error bounds given **all previous parent-scope evidence** and the root cap is
`A`, then the probability of any false authorization across child campaigns
is at most `A`. Authentication and accounting enforce one component of this
argument; the sampling model and timely experiment-start attestations are
external requirements. The synthetic benchmark demonstrates both a reset
attack and the consequences of preallocation data peeking.

```sh
python -m unittest discover -q
python demo_scope.py --output /tmp/ace-root.json --pins /tmp/ace-root-pins.json
python verify_scope.py /tmp/ace-root.json --pins /tmp/ace-root-pins.json
python benchmark_scope.py --trials 100000 --seed 9209 --output results/v09_scope_benchmark.json
```

See [v0.9 research](RESEARCH_V09.md), [results](RESULTS_V09.md), and
[handoff](HANDOFF_V09.md). Scope registry integrity, network-separated
replicas, protected measurement start times and executor idempotency remain
future research. This is a synthetic prototype, unsuitable for real assets.

## v0.6: conditional evidence and dependent-source clusters

**Status: research prototype, 23 October 2026.** The new signed-input inference layer
uses a separately pinned, exact-cover statistical cluster plan (`clustered.py`)
and a finite-state conditional-null e-process (`conditional.py`). Corrupted and
erased cluster readings are scored by a lower-envelope dynamic program that
reconstructs each candidate *clean* history before evaluating predictable bets.
It gives an anytime false-authorization guarantee **conditional on** verified
cluster assignments, the model's full-history conditional-probability bounds,
and the precommitted number of corrupted clusters.

```sh
python -m pip install -r requirements.txt
python -m unittest discover -q
python benchmark_clusters.py --trials-per-truth 4000 --seed 82064 \
  --output results/v06_clustered_benchmark
```

The baseline includes a policy-matched robust Bayesian posterior under exact
IID null and an interval-valued rectangular credal-Bayes comparator. The
policy-matched robust Bayes makes exactly the same decisions as ACE under its
matched IID assumptions. Details: [research note](RESEARCH_V06.md),
[reproducible results](RESULTS_V06.md), and [handoff](HANDOFF_V06.md).

**Certificate boundary:** v0.6 cluster decisions are standalone; existing
v0.5 witnessed authorization certificates only attest to the prior v0.5
statistical model. Signed source reports authenticate enrolled keys, not
physical independence. Do not deploy this prototype for real asset custody.

## Previous v0.5 implementation and historical results

**v0.5 research prototype | October 23, 2026**

ACE is an experiment in authorization decisions backed by explicitly enrolled
sources, adversarially robust sequential evidence, and auditable witness
commitments. It combines known tools from sequential inference, provenance,
cryptographic transparency logs, and fault-tolerant state replication. Its
claim is a *systems-level research hypothesis*, not a theorem that Bayesian
reasoning itself is defective or that ACE beats optimal Bayesian procedures.

## What is implemented

- A fixed, signed evidence roster with source-root deduplication and explicit
  erasure handling (`provenance.py`, `robust.py`).
- A robust lower-envelope e-process with bounded accepted-source corruption
  and an anytime false-authorization bound under the stipulated null (`ace.py`).
- RFC 9162-style Merkle evidence logs, quorum receipts, signed head proofs,
  independently replayed certificates and a SQLite action gate (`witnessed.py`,
  `merklelog.py`, `relying_party.py`).
- Durable witness journaling, including detection of modified snapshots
  (`durable_witness.py`).
- **v0.5:** independently durable Ed25519 anchor replicas, a witnessed-state
  hash chain, quorum certificates, latest-head reads, and rollback recovery
  (`anchor.py`, `anchored_witness.py`).
- Independent pinned anchor certificate verifier (`verify_anchor.py`) and
  deterministic signed research fixture (`demo_anchor.py`).
- Lean 4 source for the abstract inference and quorum implications in
  `lean/ACE/`. Cryptographic and probabilistic assumptions are kept external.

## Run the code

```bash
python -m pip install -r requirements.txt
python -m unittest discover -q
python quorum_audit.py --output /tmp/ace-quorum.json
python demo_witnessed.py --output /tmp/ace-witness.json
```

CI also compiles each Lean file with pinned Lean `v4.35.0`. Existing v0.4
example certificates use deterministic test keys; see the historical README
below for the exact offline-verification invocation.

## v0.5 witness antirollback boundary

Four independent anchor identities, `f=1` faulty, and quorum `q=3` satisfy

\[
2q > n+f.
\]

Each anchor replica signs an immutable successor record under its own key and
persists it before returning the vote. The record commits to its predecessor
and to a signed snapshot of the original witness's complete state, including
its receipts and epoch signing history. The witness publishes a receipt or
head signature to callers only after a quorum of replicas records the new
state. On startup and before each signing event, it reads the highest
quorum-backed snapshot and reconstructs its local journal when necessary.

**Safety assumptions:** at most one anchor replica can violate monotonic
persistence; the remaining replicas have protected signing keys and retained
SQLite journals; the original witness signing key is secure; enrollment and
first checkpoint are trusted; read and write quorums are consulted before
releasing a signature. Two faulty/rolled-back anchors cause the prototype to
suspend signing. Network partitions and incomplete anchor transitions may
also prevent progress, by design.

**Important limitations:** the prototype passes Python objects between
replicas instead of using authenticated network transport. It has no
independent deployment, remote hardware root of trust, cross-process
transaction coordinator, automatic repair for partially published anchor
commits, or atomic handshake with an external protected action. A whole-store
rollback at more than `f` independent anchors breaks the premise. A signed
anchor certificate is not itself proof of freshness; freshness requires the
quorum read and external policy pin. Source signatures likewise do not prove
statistical independence. This code is unsuitable for real-money custody or
safety-critical authorization.

## Experiments and next research

Run `python -m unittest test_anchor -v` for the v0.5 adversarial tests,
including a direct baseline rollback double-signing counterexample, whole-database rollback, one compromised replica, two-replica
failure, fake votes, stale parents, partially published transitions, and a
full end-to-end evidence certificate after a witness database rollback.

The next protocol step should be a real authenticated anchor-to-anchor
transport with recovery certificates and deadlines. The quantitative next
step should evaluate ACE and a policy-aware Bayesian oracle with identical
provenance, witness and computational budgets, measuring both unsafe actions
and unnecessary denials.

## Historical baseline

The following v0.4 report documents the foundation inherited by this branch.

---
# ACE v0.4: Witnessed Epistemics

**Research prototype · 23 October 2026**

Adversarial Constraint Epistemics (ACE) treats an authorization as the output
of a precommitted evidence model, an authenticated sampling plan and a
replayable, adversarially constrained decision rule. v0.4 adds a **quorum-
witnessed append-only intake** to the v0.3 signed roster and anytime robust
e-process. The provenance system is an inference substrate, not a general
replacement for Bayesian probability calculus.

**Python suite:** 79 tests passing on the initial development run. **Lean:**
three proposed modules, not kernel-compiled locally. All findings concern
specified threat models and synthetic examples.

## One-minute reproduction

```bash
python -m pip install -r requirements.txt
python -m unittest discover -q
python quorum_audit.py --output results/quorum_intersection.json
python demo_witnessed.py --output results/witnessed_demo.json
python verify_witnessed.py results/witnessed_demo.json \
  --expected-protocol 0e0f0962d842116796eb4afeaefeb0b77367a109cccb18ebe919f0b755cb4777 \
  --expected-policy 313640a768e64959de8ce0bb86c90566561d7267053fa2230f5dc525926ef15c \
  --expected-challenge 8c7b7b5f1f44d9e32e493f85a6a5fddb \
  --expected-epoch 0 \
  --expected-previous-digest 0000000000000000000000000000000000000000000000000000000000000000
```

**Every key in the demonstration is deterministic and test-only.** The CLI
requires caller-pinned digests, nonce, epoch and previous checkpoint digest;
never infer these from the presented, untrusted certificate.

Optional `--consume-db results/local_gate.sqlite` persists checkpoints and
one-use action challenges in SQLite. The action executor must bind an actual
action to the pinned challenge and tolerate crash-after-consume semantics.

## How the witnessed admission works

1. A trusted experiment manifest enrolls fixed sample slots, Ed25519 keys,
   dependence domains, a model, a null, a bet, and an error budget `alpha`.
2. An independently pinned witness policy specifies the log operator and `n`
   witness keys, a maximum fault count `f`, a signed-checkpoint quorum `q`,
   and a signed receipt quorum `r`.
3. Direct submission to each receiving witness creates an Ed25519-signed
   receipt for **the report digest and the witness's next unsigned epoch**.
   Reaching `r` valid acknowledgements defines a quorum-accepted submission.
4. A collector sends the **complete, canonical signed-observation log** to
   each checkpoint signer. A witness verifies the log signature and Merkle
   root, verifies source signatures, checks that all of its acknowledged
   reports are present, checks append-only history and signs at most one
   view per epoch.
5. A relying party verifies `q` distinct endorsements, checks the signed
   checkpoint against caller-pinned policy/nonce/epoch/previous head, verifies
   the full included log and RFC 9162-style consistency proof, then recomputes
   the v0.3 robust anytime decision. It consumes the action challenge once.

For `n` enrolled witnesses, at most `f` of which are corrupt, a quorum
intersection contains at least one honest witness if:

```
2*q > n+f     (two checkpoint quorums cannot certify split views)
q+r > n+f     (each checkpoint quorum intersects each receipt quorum honestly)
```

For `n=4,f=1,q=3,r=3`, exact enumeration obtains a minimum of **one honest
witness** for each kind of intersection. An omission of an epoch-specific,
quorum-acknowledged report blocks a valid certificate, provided honest
witnesses persisted their earlier receipts and checked the full log.

## What the guarantee does and does not mean

Let `E_t(X)` be a nonnegative test martingale under the precommitted clean
null model. For an observed trace `Y` with erasures and at most `k` corrupted
admitted slots, let `R_t(Y)` be the infimum of `E_t(x)` over all compatible
clean traces. Then, pathwise, `R_t(Y) <= E_t(X)` if the actual clean trace is
compatible. Ville's inequality yields the anytime bound

```
Pr[ever authorize under the risky clean null] <= alpha
```

conditional on the precommitted model, correctly bounded source corruption,
trusted roster, witness-quorum honesty, authentic messages, and effective
receipt/cutoff procedures. The witnessed log adds *conditional reporting
completeness for receipt-quorum-accepted submissions*. It does not validate
the null's iid or independence assumptions.

Specific limitations:

- A report lacking `r` acknowledgements can be withheld. The numerical
  erasure rule remains fail-safe relative to its formal assumptions; an
  unreported conflict can affect historical audit conclusions.
- Reports received after a sealed epoch produce receipts for the **next**
  epoch. No certificate proves no future conflicting source statement exists.
- Honest witness receipts and single-view histories must survive crashes.
  `durable_witness.py` uses transactional SQLite and signed snapshots for
  ordinary process recovery. A rollback of the entire database is outside
  its protection; a remote monotonic anchor or equivalent is needed.
- Witness commitments do not establish independence of sensor physics,
  protection against stolen enrolled keys beyond `k`, liveness during
  network partitions, or a guaranteed end-of-intake network delivery bound.
- The implementation uses Python's documented canonical JSON encoding,
  not a cross-language canonicalization standard or an audited production
  cryptographic protocol.
- The relying-party SQLite gate is not atomic with external effects. Its
  nonce is recorded before granting the caller permission to attempt an
  effect, so a crash can prevent a legitimate action from occurring.

## Executable counterexamples

`test_witnessed.py` includes a dishonest collector that withholds a validly
signed conflicting observation. With three timely witness receipts the
collector cannot obtain the required three checkpoint endorsements, even
when one witness is corrupt. With only two receipts, the attacker can use one
corrupt signer and two honest signers who never saw the conflicting report to
obtain an apparently authorized checkpoint. This is why `q+r > n+f` is
mandatory.

The earlier v0.3 correlation falsifier remains valid: 24 distinct signed
sensor slots sharing one Bernoulli(.8) latent cause can reach 20% unsafe
authorization against the nominal 5% budget. Authentication and quorum
logging do not repair model misspecification or common-cause dependence.

## Repository map

| File | Purpose |
| --- | --- |
| `merklelog.py`, `test_merklelog.py` | Prefix-separated SHA-256 Merkle roots, inclusion, consistency proofs |
| `witnessed.py`, `test_witnessed.py` | Receipt epochs, witness quorum, checkpoints, sealed decisions |
| `durable_witness.py`, `test_durable_witness.py` | Process-crash journal and signed snapshots |
| `relying_party.py`, `test_relying_party.py` | SQLite nonce consumption and checkpoint anchor |
| `quorum_audit.py`, `test_quorum_audit.py` | Exact witness-quorum intersection enumeration |
| `demo_witnessed.py`, `verify_witnessed.py` | Synthetic certificate generator and relying-party CLI |
| `provenance.py`, `robust.py`, `certificates.py` | v0.3 enrolled evidence and statistical authorization |
| `lean/ACE/*.lean` | Conditional deterministic lemmas; Lean kernel check pending |
| `RESEARCH.md`, `RESULTS.md`, `HANDOFF.md` | Proof boundary, measured results, next-stage instructions |
| `history/`, `results/` | Earlier baselines and reproducibility artifacts |

## Related work

- RFC 9162: [Certificate Transparency v2, Merkle inclusion and consistency proofs](https://www.rfc-editor.org/rfc/rfc9162)
- Ramdas, Grünwald, Vovk and Shafer (2023): [Game-theoretic statistics and anytime-valid inference](https://doi.org/10.1214/23-STS894)
- Douceur (2002): [The Sybil Attack](https://www.microsoft.com/en-us/research/publication/the-sybil-attack/)
- Walley (2000): [Imprecise probability](https://doi.org/10.1016/S0888-613X(00)00031-1)

The quorum construction and Merkle trees are standard ideas. ACE's proposed
contribution is their compositional use as a verifiable inference and
authorization contract, tested against a strong set of probabilistic baselines.


## ACE v0.7: witnessed clustered certificates (draft PR)

`clustered_certificate.py` binds the signed v0.5 checkpoint log to the v0.6
cluster plan and a structured action intent through separately pinned v2
commitments. `independent_cluster_verifier.py` recomputes cluster membership,
erasures, contradictions and finite-state conditional e-scores without calling
the production scorer. `clustered_action_gate.py` persists single-use action
nonces and log heads; `verify_clustered.py` is the strict v2 CLI.

```sh
python -m unittest discover -q
python demo_clustered.py --output /tmp/v07-cert.json --pins /tmp/v07-pins.json
```

Use the exact required external pins printed to `/tmp/v07-pins.json` in the
`verify_clustered.py --expected-*` arguments. The demo uses deterministic
synthetic test keys. `RESEARCH_V07.md` describes the theorem assumptions,
`RESULTS_V07.md` records the test coverage, and `HANDOFF_V07.md` covers the
remaining policy-endorsement and antirollback work. Existing v1 witnessed
certificates are invalid under the v2 verifier.

## ACE v0.8: global risk budget for repeated authorizations

The campaign ledger extends the per-experiment ACE guarantee to repeated adaptive attempts. Each challenge reserves integer alpha units **before** new reports, finalizes one v2 log/certificate, and obtains at most one quorum-signed authorization consumption. Denials and crashes do not return alpha. The fixed campaign scope, exact alpha and cumulative spend are embedded inside the v2 action commitment and its associated signed campaign record.

```bash
python -m unittest test_campaign test_campaign_cli test_campaign_state -v
python demo_campaign.py --output /tmp/ace-campaign.json --pins /tmp/ace-campaign-pins.json
python verify_campaign.py /tmp/ace-campaign.json --pins /tmp/ace-campaign-pins.json
python benchmark_campaign.py --trials 200000 --seed 8208 --output results/v08_campaign_benchmark.json
```

The conditional risk argument and known deployment limitations are in [RESEARCH_V08.md](RESEARCH_V08.md); the attack tests in [RESULTS_V08.md](RESULTS_V08.md) and the engineering follow-up in [HANDOFF_V08.md](HANDOFF_V08.md). The 4-replica anchor service is a local fault-injection simulation. No real-asset permission is implied by passing tests.
