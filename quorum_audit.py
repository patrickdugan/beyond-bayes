"""Exact finite quorum audit. All witness and corrupt sets are enumerated.

This proves cardinal quorum intersection in a finite computational model;
it cannot establish that deployed witnesses really keep their signatures safe.
"""
import argparse
import json
from itertools import combinations
from pathlib import Path


def exact_audit(n: int, f: int, q: int, r: int) -> dict:
    if not (0 <= f < n and 0 < q <= n and 0 < r <= n):
        raise ValueError('invalid parameters')
    universe=set(range(n))
    ckpts=[set(x) for x in combinations(range(n),q)]
    rcpts=[set(x) for x in combinations(range(n),r)]
    faults=[set(x) for x in combinations(range(n),f)]
    receipt_min=min(len((a&b)-bad) for a in ckpts for b in rcpts for bad in faults)
    split_min=min(len((a&b)-bad) for a in ckpts for b in ckpts for bad in faults)
    return {'n':n,'fault_budget':f,'checkpoint_quorum':q,'receipt_quorum':r,
            'worst_honest_receipt_checkpoint_overlap':receipt_min,
            'worst_honest_checkpoint_overlap':split_min,
            'receipt_omission_excluded':receipt_min >= 1,
            'split_view_excluded':split_min >= 1,
            'arithmetic_receipt_bound':q+r>n+f,
            'arithmetic_split_bound':2*q>n+f,
            'checked_receipt_configurations':len(ckpts)*len(rcpts)*len(faults),
            'checked_split_configurations':len(ckpts)*len(ckpts)*len(faults)}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',default='results/quorum_intersection.json')
    args=parser.parse_args()
    rows=[exact_audit(4,1,3,3), exact_audit(4,1,3,2),
          exact_audit(4,1,2,3), exact_audit(7,2,5,5),
          exact_audit(7,2,5,4)]
    path=Path(args.output)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(rows,indent=2)+'\n',encoding='utf8')
    for r in rows:
        print('n={n} f={fault_budget} q={checkpoint_quorum} r={receipt_quorum} '
              'min honest receipt/checkpoint={worst_honest_receipt_checkpoint_overlap} '
              'min honest checkpoint/checkpoint={worst_honest_checkpoint_overlap}'
              .format(**r))


if __name__=='__main__':main()
