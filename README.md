# Beyond Bayes: Adversarial Constraint Epistemics (ACE)

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
