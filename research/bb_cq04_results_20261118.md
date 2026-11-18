# BB-CQ-04: Source-aware evidence memory has limited authorization headroom

**18 November 2026 | Registered exact population analysis + original frozen ECA-04 CPU development.**
Registration: [BB-CQ-04 protocol](bb_cq04_protocol.md), committed as `a12132e402036790924f6bc5fb8b08dd2fcc7286` before any BB-CQ-04 scoring. The complete source-only implementation, test suite and CI reproduction artifact were frozen at commit `9d231c05d0590fb409e4076a901bd092a99e139f` before opening the native public development inputs. [Source-only verification run #44307698283](https://github.com/patrickdugan/beyond-bayes/actions/runs/44307698283) passed Python and existing Lean checks.

**Registered primary verdict: `HEADROOM_BLOCKED`.** A source-aware exact Bayesian posterior gives a strictly positive but below-threshold expected authorization benefit over the *strongest correctly specified aggregate-only Bayes control* when six of twelve records are replaced. The frozen 16-unit GRU improves substantially when the whole revised public input is replayed instead of retaining a stale pre-revision output, but this is an **input-replay effect** and not a demonstrated neural compactification or causal-fiber effect. No protected confirmation cohort was generated.

## 1. A calibrated data-version problem

A simulated issuer belongs to one of the original ECA-04 three channel regimes with priors `(.45,.35,.20)` and per-sentinel match probabilities `(.95,.65,.15)`. Twelve final accepted known-label/report observations are IID conditional on that latent regime. Before the final accepted version, `j=1,3,6` preselected slots contain independent fair provisional report bits; every other record is already valid. The selected slots and their original provisional bits are supplied by a reproducible public generator, independent of report outcomes. A host-authorized correction replaces each provisional record with the final genuine report.

The archived *old provisional* bit is independent fair noise. Once replaced, it contains no additional information about the regime beyond the final accepted data. The full exact ECA-04 posterior over the accepted twelve-record dataset is therefore the calibrated Bayesian reference even relative to the full historical information filtration under this precise synthetic generator. This fixes the critical limitation of replacing valid IID reports with arbitrary report bits and interpreting the result as calibrated IID evidence.

The `AGGREGATE_OPTIMAL` policy sees `m_old`, the provisional aggregate match count, `q`, the count of new authoritative matches in the known `j` replacement slots, and `j`. It integrates over the hidden old matched bits using the **correct fair-provisional likelihood**, making it the optimal probability forecast under its restricted information. Its exact formula and an independently written bit-pattern oracle agree for small domains. The `DELTA_EXACT` policy receives an externally checked old-to-new archive delta; its final posterior exactly equals independent full-data replay. These are hypothetical versioned source contracts with no physical signer attestation.

## 2. Preregistered exact population authorization result

For each root and regime, score the expected `2 FP + FN` decision cost over five original ECA-04 case priors and both possible future audit report values. Future case labels and audit bits are analytically integrated; the independent experimental unit is the issuer root. The source-only exact population calculation enumerates regime, unchanged true matches, overwritten provisional fair matches, and newly admitted authoritative matches with exact `Fraction` weights. It uses the true report-generating model for each conditional action cost and includes a privileged true-regime reference.

| Replacement count | Full exact Bayes cost | Optimal aggregate-only cost | Bayes information gain | Aggregate regime Brier | Full regime Brier |
| --- | ---: | ---: | ---: | ---: | ---: |
| j=1 | 0.197514842 | 0.199029088 | **0.001514247** | 0.126593463 | 0.106036369 |
| j=3 | 0.197514842 | 0.202424777 | **0.004909935** | 0.158992259 | 0.106036369 |
| j=6, primary | 0.197514842 | 0.203721599 | **0.006206757** | 0.170499060 | 0.106036369 |

The fixed practical threshold was `0.02` cost units per case. The six-revision benefit of `0.006206757142` is **31.03% of that threshold**, so the registered `HEADROOM_BLOCKED` verdict follows exactly under the stipulated model. The coarse-vs-fine action disagreement rate is 2.65%, 3.66%, and 4.55% of the ten registered future action contexts for j=1,3,6 respectively. The pooled-prior cost is 0.314916667 and the true-regime privileged reference cost is 0.186833333.

### A larger mathematically identifiable calibration effect

The six-revision fine-versus-coarse **Brier gap** is `0.064462690845`, much larger numerically than the authorization difference in its different scoring units. Its value also equals the exact expected squared-L2 distance between the fine posterior and the conditional coarse posterior:

```
E ||P_fine - Y||² - E ||P_coarse - Y||²
      = - E ||P_fine - P_coarse||²,
equivalently
E Brier(coarse,Y) - E Brier(fine,Y)
      = E ||P_fine - P_coarse||².
```

Here `Y` is the true regime one-hot vector. This is the standard conditional-expectation/Pythagorean theorem: the fine posterior is the conditional expectation of `Y` given all accepted evidence, and the coarse posterior is the conditional expectation of that fine posterior given the admitted aggregate. The identity is exact under the registered likelihood. It establishes **proper-score headroom** without asserting improved authorization outcomes. It supplies a cleaner candidate outcome for a future paper on revision-aware compact belief states.

## 3. Actual frozen ECA-04 native development

The [original ECA-04 artifact](https://github.com/MoralityLabAI/Control-Harness/actions/runs/44145067899/artifacts/14355808052) supplies the unchanged `GRU(2,16)` state dict, SHA-256 `49bf2db1316942a23b91943843eb0398043c806cadd40421371af571aa15b3d8`. No original ECA-04 heldout seeds, old trained representations, or test responses were used to generate BB-CQ-04 roots. PyTorch `2.10.0+cpu` executed the exact frozen model with 64 **public deterministic** calibration roots and 256 distinct **public deterministic** pilot roots, all three replacement sizes paired within each issuer. Each candidate policy saw the same post-revision case priors and future audit decision family; host-private regime was used only in scoring.

| Arm | j=1 pilot loss | j=3 pilot loss | j=6 pilot loss |
| --- | ---: | ---: | ---: |
| Independent full exact Bayes | 0.19661133 | 0.19661133 | 0.19661133 |
| Archive-verified delta Bayes | 0.19661133 | 0.19661133 | 0.19661133 |
| Strong aggregate-only Bayes | 0.19803874 | 0.20018880 | 0.19980632 |
| **Frozen GRU with full revised input replay** | **0.19670573** | **0.19670573** | **0.19670573** |
| Frozen GRU with stale provisional input | 0.20484049 | 0.22092285 | **0.26320475** |
| Pooled reliability prior | 0.31074870 | 0.31074870 | 0.31074870 |
| Privileged true-regime oracle | 0.18522949 | 0.18522949 | 0.18522949 |

The full accepted record sequence is the same for all three `j` arms by construction; consequently its Bayesian and native full-replay predictions also remain the same. The provisional transcript becomes increasingly corrupted with larger `j`. The full-replay GRU is within **0.0000944 cost units per case** of exact Bayes in this 256-root deterministic pilot. Its posterior Brier score was **0.104855**, close to full exact Bayes **0.099881**. The six-revision stale GRU had Brier **0.805155**, and the calibrated aggregate-only Bayes had Brier **0.140237**.

### Replay gain, descriptive pairing

| Replacements | Mean stale-to-full native replay gain | Paired descriptive 95% root bootstrap |
| --- | ---: | --- |
| 1 | 0.008135 | [0.004588, 0.012196] |
| 3 | 0.024217 | [0.017603, 0.031261] |
| 6 | **0.066499** | **[0.054554, 0.078332]** |

Only 125, 383 and 749 provisional report bits, respectively, changed across the 256 pilot issuers; all selected replacements remained in the analysis, including no-op ones. In the six-slot arm, native stale versus native replay differed on **1.871 of the ten future decision contexts per issuer**, on average. The source-aware/aggregate Bayes decision difference averaged **0.449 of ten contexts**. Both quantities use repeated contexts within each issuer and are not independent-case counts.

The six-revision *sampled* source-aware Bayes advantage was **0.003195**, with descriptive paired 95% interval **[-0.000973, 0.007109]**; this finite-sample contrast is subordinate to the exact population result, whose registered headroom verdict is already decisive.

### Order nuisance floor and causal limits

On the separate 64 development calibration issuers, run eight deterministic, independently labeled permutations of the **same final accepted twelve-report multiset** per root. Every permutation preserves the original exact Bayesian posterior. The frozen native GRU exhibits:

- Mean maximum per-root expected authorization cost variation across eight permutations: **0.0132617**.
- Largest root-level maximum cost variation: **0.1575**.
- Mean native predictive total-variation distance for these permuted counterparts: **0.0375520**.

These public deterministic roots do not supply a statistical 95/95 matched-sham tolerance certificate. The maximum nuisance outlier exceeds the observed mean stale-to-replay gain. The native pilot therefore supports a **development input-replay improvement** under a synthetic amendment interface, while leaving neural-source-revision mechanism identification, causal feature uniqueness and a fixed-budget compact state-updater claim untested. An authorized data correction would need real source and version authentication; the small in-process archive checker provides a structural fixture only.

## 4. Reproducibility and boundaries

The first native readout was performed after source CI froze the original code. A second run using the identical original public ECA-04 checkpoint produced byte-for-byte identical summary and per-root JSONL output under Python 3.13 / PyTorch 2.10 CPU. Raw 960 root/arm rows (`320 roots × 3 j-arms`) are available as a companion generated artifact and can be reconstructed from the checked-in deterministic source code plus pinned public checkpoint.

- Native raw JSONL SHA-256: `5fd08ac172a8972d419000c9d4c16d4a7c0d5877e72b4fe8e5605d303814ee7c`.
- Native summary SHA-256: `62c4f7750244388de7b80bbde0596de211c2c50f18be0a2e64c44620ca15b70f`.
- BB-CQ-04 exact module SHA-256: `e8d04588759a59436b091bc4a1f18eb2b82e8fd71a56c5fe0724e9b956372aa4`.
- BB-CQ-04 native runner SHA-256: `53d67dc8f303d2682c0b54b0fd5b19348dcfcfe182aac13a298e67cb123169ea`.
- Original preregistered protocol SHA-256: `0baa49c7f5bd107d7c225b02f445a4c8d4559495985b8b316866b0c3820b36c6`.
- Source-only exact receipt: [`bb_cq04_exact_v1.json`](../results/bb_cq04_exact_v1.json), generated by independent exact rational enumeration and archive-invariant checks. The native summary receipt is a separately reported output; it is verified against the local raw JSONL SHA and identical CPU replay.
- Full native model checkpoint retrievable from [Control-Harness original ECA-04 artifact](https://github.com/MoralityLabAI/Control-Harness/actions/runs/44145067899/artifacts/14355808052).

```sh
python -m unittest test_bb_cq04_core -v
python bb_cq04_exact.py --check results/bb_cq04_exact_v1.json

# Supply ONLY the original checkpoint state dict from its archived run.
python bb_cq04_native.py \
  --checkpoint /path/to/gru_state_dict.pt \
  --out-dir /tmp/bb-cq04-native
```

The exact mathematical checks and repository-wide Python/Lean suite run in CI; the original frozen neural checkpoint is not embedded in Beyond Bayes and is not silently downloaded by its CI workflow.

## 5. Research consequence

BB-CQ-01/02/03 identify information that a compressed research state must retain to support future evidence changes. BB-CQ-04 adds a calibrated decision loss measurement. On ECA-04's own task, substantial exact posterior information can be lost while task authorization regret remains small. Task-specific equivalence classes are coarser than exact posterior-value equivalence classes under these five case priors and fixed cost ratio.

The next meaningful experiment would register **proper-score recovery or revision-conditional calibrated forecasts** as the primary endpoint, preserving full historical Bayesian replay and optimal reduced-information Bayes as strong baselines. A learned online state-updater must be tested by genuinely sequential post-correction updates, with exact task loss, measured memory and compute, authenticated revision status and an independent matched-causal sham. Given the present exact `HEADROOM_BLOCKED` result, no protected authorization-focused confirmation is justified under this same loss contract. Keep ECA-04/05 historical science outputs and all protected BPD cohorts untouched.
