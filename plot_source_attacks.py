"""Render an exact synthetic-risk chart from locally generated CSV results.

Requires matplotlib only for this optional chart (not a project runtime dep).
"""
import csv
from pathlib import Path


def main() -> None:
    import matplotlib.pyplot as plt
    data=list(csv.DictReader(open('results/source_attack_exact.csv',encoding='utf8')))
    scenarios=list(dict.fromkeys(row['scenario'] for row in data))
    labels=['Clean','16 forged','8 erased','Forged + erased','+ 2 stolen keys']
    a=[]; b=[]
    for scenario in scenarios:
        a.append(100*float(next(row['unsafe_open_rate'] for row in data if
                                row['scenario']==scenario and row['truth']=='risky'
                                and row['method']=='ID-blind-e-process')))
        b.append(100*float(next(row['unsafe_open_rate'] for row in data if
                                row['scenario']==scenario and row['truth']=='risky'
                                and row['method']=='ACE-v0.3-admission')))
    x=list(range(len(a)))
    fig, ax=plt.subplots(figsize=(9,4.8))
    w=.38
    ax.bar([t-w/2 for t in x],a,width=w,label='ID-blind e-process')
    ax.bar([t+w/2 for t in x],b,width=w,label='ACE v0.3 signed roster')
    ax.set_ylabel('P(unsafe authorization | risky world), %')
    ax.set_ylim(0,105)
    ax.set_xticks(x,labels)
    ax.legend(loc='upper left')
    ax.set_title('Source-forgery attack: exact finite-horizon probability')
    ax.grid(axis='y',alpha=.3)
    ax.set_axisbelow(True)
    fig.tight_layout()
    p=Path('results/provenance_attack_exact.png')
    fig.savefig(p,dpi=160)
    print(p)


if __name__=='__main__':main()
