"""Independent exact-source BB-CQ-04 registration check and receipt generator."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from bb_cq04_core import source_only_receipt


def run() -> dict:
    result=source_only_receipt()
    result["source_file_sha256"]={
        path:sha256(Path(path).read_bytes()).hexdigest()
        for path in ("bb_cq04_core.py","bb_cq04_native.py",
                     "research/bb_cq04_protocol.md")
    }
    return result


def main() -> None:
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output",type=Path)
    group.add_argument("--check",type=Path)
    args=parser.parse_args()
    payload=json.dumps(run(),indent=2,sort_keys=True)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(payload,encoding="utf-8")
        print(payload)
    else:
        if args.check.read_text(encoding="utf-8") != payload:
            raise SystemExit("FAIL: BB-CQ-04 registered exact-source receipt differs")
        print("PASS: BB-CQ-04 exact-source receipt replay")


if __name__=="__main__":
    main()
