# Offline Auditability in MQTT

Experiment code for *Offline Auditability in MQTT: Semantic Boundaries and Post-Quantum Evidence*.

## Environment

- Linux (the measurements used WSL2 on x86-64)
- Python 3.12.13
- CMake 3.20 or newer and a C++17 compiler
- OpenSSL and Mosquitto 2.0.x
- liboqs 0.16.0 and liboqs-python at commit `35eceb69d2b363cb0421085cf1ae1c682dee1acc`

```bash
conda create -n firstpaper python=3.12.13 -y
conda activate firstpaper
python -m pip install -r experiments/requirements.txt

git clone --branch 0.16.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git build/liboqs
cmake -S build/liboqs -B build/liboqs/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$PWD/build/liboqs-install" \
  -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD='KEM_ml_kem_768;SIG_ml_dsa_65;SIG_slh_dsa_pure_sha2_128f'
cmake --build build/liboqs/build -j
cmake --install build/liboqs/build

git clone https://github.com/open-quantum-safe/liboqs-python.git build/liboqs-python
git -C build/liboqs-python checkout 35eceb69d2b363cb0421085cf1ae1c682dee1acc
OQS_INSTALL_PATH="$PWD/build/liboqs-install" python -m pip install ./build/liboqs-python
```

## Run

Start a local Mosquitto broker, then run the quick reproducibility profile:

```bash
mosquitto -d
python experiments/run_stage4_protocol.py --mode quick
```

Use `--mode full` for the complete experiment profile. Run it from a clean Git worktree.
