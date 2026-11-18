"""Development-only frozen ECA-04 native continuation counterexample.

The original Control-Harness ECA-04 16-unit GRU checkpoint is supplied by the
caller and SHA-256 verified. No archived training/heldout seeds are imported.
256 synthetic issuer fixtures use public deterministic SHA-256 roots; paired
host re-signing flips one matching and one mismatching report in the first six
events. The entire six-event suffix stays fixed, and all exact Bayes posteriors
are unchanged. This is a model-output diagnostic, not a protected safety or
causal-interpretability confirmation experiment.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, replace
from hashlib import sha256
import hmac
import json
from pathlib import Path
import random

from revocable_bayes import (
    ECA04_ORIGINAL_MODEL_SHA256, posterior_full_replay,
)

COUNT = 256
PREFIX = 6
CHANNEL_MATCH = (.95, .65, .15)
PRIOR = (.45, .35, .20)
DOMAIN = "bb-cq02-public-development-v1/root/"


@dataclass(frozen=True)
class SignedRecord:
    slot: str
    known_label: int
    report: int
    mac: str = ""


@dataclass(frozen=True)
class Pair:
    root_sha256: str
    regime: int
    original: tuple[SignedRecord, ...]
    corrected: tuple[SignedRecord, ...]
    positions: tuple[int, int]


def _record_body(record: SignedRecord) -> bytes:
    return json.dumps((record.slot, record.known_label, record.report),
                      separators=(",", ":")).encode("utf-8")


def sign(record: SignedRecord, key: bytes) -> SignedRecord:
    return replace(record, mac=hmac.new(key, _record_body(record), sha256).hexdigest())


def valid(record: SignedRecord, key: bytes) -> bool:
    return hmac.compare_digest(record.mac, sign(record, key).mac)


def pairs(records: tuple[SignedRecord, ...]) -> tuple[tuple[int, int], ...]:
    return tuple((s.known_label, s.report) for s in records)


def generate(index: int) -> Pair | None:
    """A fixed public generator chosen during development, never a test holdout.

    Ineligible roots with all six first reports matching or all six disagreeing
    have no compensating pair; the generator returns None instead of resampling.
    """
    if type(index) is not int or not 0 <= index < COUNT:
        raise ValueError("invalid root index")
    seed = sha256((DOMAIN + str(index)).encode("utf-8")).digest()
    key = sha256(seed + b"/hypothetical-signer").digest()
    rng = random.Random(int.from_bytes(seed, "big"))
    regime = rng.choices(range(3), PRIOR, k=1)[0]
    reports = []
    for j in range(12):
        label = int(j % 2 == 1)
        agree = int(rng.random() < CHANNEL_MATCH[regime])
        report = label if agree else 1 - label
        reports.append(sign(SignedRecord(f"slot:{j}", label, report), key))
    rng.shuffle(reports)
    eligible = [(a, b) for a in range(PREFIX) for b in range(a + 1, PREFIX)
                if (reports[a].known_label == reports[a].report) !=
                   (reports[b].known_label == reports[b].report)]
    if not eligible:
        return None
    a, b = eligible[rng.randrange(len(eligible))]
    corrected = list(reports)
    for j in (a, b):
        corrected[j] = sign(replace(corrected[j],
                                    report=1 - corrected[j].report, mac=""), key)
    assert all(valid(s, key) for s in reports + corrected)
    assert pairs(tuple(reports[PREFIX:])) == pairs(tuple(corrected[PREFIX:]))
    assert posterior_full_replay(pairs(tuple(reports[:PREFIX]))) == (
        posterior_full_replay(pairs(tuple(corrected[:PREFIX]))))
    assert posterior_full_replay(pairs(tuple(reports))) == (
        posterior_full_replay(pairs(tuple(corrected))))
    return Pair(seed.hex(), regime, tuple(reports), tuple(corrected), (a, b))


def run(checkpoint: Path) -> dict:
    try:
        import torch
        from torch import nn
    except ImportError as exc:
        raise RuntimeError("Native pilot requires PyTorch; source-only tests do not") from exc

    if sha256(checkpoint.read_bytes()).hexdigest() != ECA04_ORIGINAL_MODEL_SHA256:
        raise ValueError("frozen ECA-04 checkpoint SHA-256 mismatch")
    torch.set_num_threads(1)

    class OriginalRegimeGRU(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.gru = nn.GRU(2, 16, batch_first=True)
            self.classifier = nn.Linear(16, 3)

        def forward(self, tensor):
            _, state = self.gru(tensor)
            return self.classifier(state[-1])

    model = OriginalRegimeGRU()
    model.load_state_dict(torch.load(checkpoint, map_location="cpu", weights_only=True),
                          strict=True)
    model.eval()
    fixture = [generate(i) for i in range(COUNT)]
    eligible = [f for f in fixture if f is not None]
    originals = torch.tensor([pairs(f.original) for f in eligible], dtype=torch.float32)
    amended = torch.tensor([pairs(f.corrected) for f in eligible], dtype=torch.float32)

    with torch.no_grad():
        y0, y1 = model(originals), model(amended)
        p0, p1 = y0.softmax(-1), y1.softmax(-1)
        h0 = model.gru(originals[:, :PREFIX])[1]
        h1 = model.gru(amended[:, :PREFIX])[1]
        suffix0 = model.classifier(model.gru(originals[:, PREFIX:], h0)[1][-1])
        suffix1 = model.classifier(model.gru(amended[:, PREFIX:], h1)[1][-1])
        split_error = max(float((y0 - suffix0).abs().max()),
                          float((y1 - suffix1).abs().max()))
        max_logits = (y0 - y1).abs().amax(-1)
        tv = (p0 - p1).abs().sum(-1) / 2
        hidden_l2 = (h0 - h1).square().sum(-1).sqrt().flatten()
        changed = y0.argmax(-1) != y1.argmax(-1)
        if not torch.isfinite(y0).all() or not torch.isfinite(y1).all():
            raise AssertionError("nonfinite native model outputs")
        if split_error > 1e-5:
            raise AssertionError("native GRU full/split computation mismatch")
        if not torch.all(max_logits > 1e-6):
            raise AssertionError("declared development nonzero response witness changed")

    def score(idx: int) -> dict:
        f = eligible[idx]
        return {
            "root_sha256": f.root_sha256,
            "correction_positions": list(f.positions),
            "prefix_original": [list(v) for v in pairs(f.original)[:PREFIX]],
            "prefix_corrected": [list(v) for v in pairs(f.corrected)[:PREFIX]],
            "final_original_logits": [float(v) for v in y0[idx]],
            "final_corrected_logits": [float(v) for v in y1[idx]],
        }

    return {
        "schema": "ace-bb-cq02-frozen-eca04-native-dev-v1",
        "evidence_class": "deterministic_public_development_only",
        "authorizes_action": False,
        "checkpoint_sha256": ECA04_ORIGINAL_MODEL_SHA256,
        "torch_version": torch.__version__,
        "source_generator": DOMAIN,
        "source_roots": COUNT,
        "eligible_opposite-match_prefix_roots": len(eligible),
        "ineligible_roots_without_opposing_prefix_match": COUNT - len(eligible),
        "same_exact_bayes_prefix_and_final": len(eligible),
        "changed_native_logits_above_1e-6": int((max_logits > 1e-6).sum()),
        "final_native_regime_class_changes": int(changed.sum()),
        "max_split_suffix_parity_error": split_error,
        "mean_root_max_abs_logit_difference": float(max_logits.mean()),
        "median_root_max_abs_logit_difference": float(max_logits.median()),
        "max_root_max_abs_logit_difference": float(max_logits.max()),
        "mean_root_probability_total_variation": float(tv.mean()),
        "max_root_probability_total_variation": float(tv.max()),
        "mean_prefix_hidden_l2_difference": float(hidden_l2.mean()),
        "max_prefix_hidden_l2_difference": float(hidden_l2.max()),
        "first_root_witness": score(0),
        "native_patch_interpretation": "two report reissues with same Bayes match count and unchanged suffix",
        "protected_test_roots_sampled": 0,
        "historical_eca04_heldout_seeds_loaded": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.checkpoint)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if not isinstance(v, dict)},
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
