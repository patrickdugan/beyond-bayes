# ACE v0.10 handoff and remaining proof boundaries

Modules: `root_registry.py` (administrator-approved global root admission/rollover and signed history), `measurement_start.py` (signed start window, journal, instrument mock and measured action gate), `verify_measurement.py` (independent full-chain replay), `demo_measurement.py` (fixed signed vectors), `benchmark_measurement.py` (prestart-peeking counterexample), `lean/ACE/RootOrdering.lean` (deterministic lemmas).

Run:

```shell
python -m pip install -r requirements.txt
python -m unittest discover -q
python demo_measurement.py --output /tmp/ace-v10.json --pins /tmp/ace-v10-pins.json
python verify_measurement.py /tmp/ace-v10.json --pins /tmp/ace-v10-pins.json
python benchmark_measurement.py --trials 100000 --seed 1010 --output /tmp/ace-v10-benchmark.json
```

Next research: (1) prevent out-of-process races between live registry rollover and action consumption with a linearization protocol, (2) instrument acquisition trusted by a secure monotonic counter and protected measurement circuitry rather than caller-supplied sample bits, (3) root-governance lifecycle with audited administrator key rotation, and (4) source-dependence calibration conditional on all campaign observations, including aborts and hidden preselection.

Important limitations: the registry and start quorums are simulated independent SQLite signers on one computer. The local `RegistryActionGate` lock is process scoped. No causal acquisition-time proof, physical independence attestation, production network consensus, deployment-grade key management, or real-asset authorization is claimed.
