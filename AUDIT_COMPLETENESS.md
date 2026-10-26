# ACE external-inventory audit: what a complete signed log can leave out

**Status:** Deterministic finite-population theorem with executable adversarial enumeration. This is an optional diagnostic, independent of the probabilistic e-process and signed-certificate gates. It adds no authorization capability.

An append-only signed log can prove that a **record it received** was retained. It cannot establish that every relevant decision, adverse output, refused report, or observation was *supplied* to the log. This is an additional epistemic boundary of ACE's signed-measurement-start protocol. An institution controlling the input-event roster can censor events before receipt generation.

## Sharp theorem without missing-at-random assumptions

Fix an **independently attested** universe of N > 0 expected event identifiers before auditing. Independent reviewers classify n events and flag b adverse outcomes according to a preregistered Boolean predicate. With m = N-n missing classifications, the overall adverse rate R satisfies:

```text
                    b/N <= R <= (b+m)/N
```

Every reviewed adverse event contributes one violation. At most all m missing outcomes can be adverse. Both bounds are attained by completing all unknown outcomes as benign or adverse, respectively. The interval is therefore **sharp** under even adversarially selected omissions.

For a deterministic risk budget epsilon, an external audit can guarantee R <= epsilon only if (b+m)/N <= epsilon. With 80 reviewed out of 100 expected events and two adverse reviews, the compatible adverse fraction lies in [0.02, 0.22]. Even 95 clean reviews out of 100 leave an upper bound of 5%.

This is a finite-population bound, **not a statistical confidence interval**. It assumes that the expected event roster is independently complete and that reviewed outcome classifications are correct. Independence, identically distributed outcomes and random missingness are unnecessary.

## Reproduce

```python
from fractions import Fraction
from audit_completeness import bound_omitted_traces

expected = [f"event-{i}" for i in range(100)]  # independently sealed
reviewed = {event: False for event in expected[:95]}
receipt = bound_omitted_traces(expected, reviewed)
assert receipt.upper == Fraction(1, 20)
assert not receipt.certifies_at_most("0.01")
```

The function returns exact rational endpoints, observed and missing counts, and a deterministic SHA-256 commitment to the sorted universe of IDs. The hash needs comparison with an **independently held pin**: a digest produced after the audited operator has omitted events proves nothing about the completeness of that event inventory. Duplicate IDs, extraneous reviewed IDs and ambiguous verdict values are rejected. Floating-point policy thresholds are rejected in favor of rational or decimal-string budgets.

```bash
python -m unittest test_audit_completeness -v
python -m unittest discover -q
```

The tests exhaustively enumerate every adverse-vector and every observation/missingness mask for populations of size 1 through 5, checking inclusion of the actual adverse rate and constructive sharpness at each endpoint.

## Boundary relative to Beyond Bayes

`merklelog.py`, `anchor.py`, `root_registry.py`, and `measurement_start.py` make distinct **conditional** guarantees about evidence admitted to the system, durable witnesses, and authorization budget accounting. The new bound concerns events never admitted to the log. It does not infer whether undocumented events existed, adjudicate the truth of a reported harm, replace the statistical inference layer, or establish a complete upstream event inventory.

For institutional-deference benchmarks, pin the case roster and expected response slots outside the model provider's control, preserve omitted and unreconciled slots, and use independently verified adverse labels. This supports accountable review coverage without conferring any new political or system-control powers.
