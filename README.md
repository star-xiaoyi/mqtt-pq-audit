# Offline Auditability in MQTT

Experiment code for *Offline Auditability in MQTT: Semantic Boundaries and Post-Quantum Evidence*.

## Environment

- Linux (the measurements used WSL2 on x86-64)
- Python 3.12.13
- CMake 3.20 or newer and a C++17 compiler
- OpenSSL and Mosquitto 2.0.x

## Run

Start a local Mosquitto broker, then run the quick reproducibility profile:

```bash
mosquitto -d
python experiments/run_stage4_protocol.py --mode quick
```

Use `--mode full` for the complete experiment profile. Run it from a clean Git worktree.

Generated artifacts use the implementation label A6 for construction A5 in the paper.
