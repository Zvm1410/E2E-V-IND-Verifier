# Benchmarking on the Raspberry Pi

What the paper reports: per-ballot cost of encryption and proof generation
on the target hardware, as distributions (not averages), at least 500
ballots, and how it scales with the number of candidates m.

`harness/bench.py` measures exactly that on the real prover:
`encrypt_selection` (encryption alone) and `encrypt_and_prove` (encryption
and all m + 1 proofs), per ballot, for each m. It verifies the first ballot
of every m with the independent verifier, so a broken prover cannot produce
a timing table. Peak memory is read from the OS.

## Setup

```
git clone <repository URL> && cd E2E-V-IND-Verifier
python3 -m venv .venv && source .venv/bin/activate
pip install cryptography pytest          # PyQt6 is only needed for the kiosk GUI
```

Before running:

- Fit a heatsink or fan and use the official power supply. A long run that
  throttles measures the cooling, not the cryptography.
- Run headless (SSH or a console), with nothing else running.
- Start it inside `tmux` or with `nohup` so a dropped connection does not
  kill it.
- Record `vcgencmd measure_temp` and `vcgencmd get_throttled` before and
  after. `throttled=0x0` both times means the numbers are clean; anything
  else should be reported with them.

## Runs

1. **Calibrate, about a minute.**
   `python -m harness.bench --ballots 5 --warmup 1 --m 6`
   Prints seconds per ballot; multiply by 500 for the main run's length.
2. **Main figure: m = 6 (five candidates and NOTA), 500 ballots.**
   `python -m harness.bench --ballots 500 --m 6`
3. **Scaling with m: 100 ballots each at m = 2, 4, 8.**
   `python -m harness.bench --ballots 100 --m 2,4,8`

Or everything at 500 ballots overnight: `python -m harness.bench`.

Each run writes `results/bench_<host>_<time>.csv` (one row per ballot) and a
`.json` summary. Copy them back into `results/`; `python -m harness.tables`
puts the newest summary into Table 7.

## How long

Measured on the development machine (x86-64, single core, CPython 3.11),
seconds per ballot for `encrypt_and_prove`:

| m | per ballot | 500 ballots |
|---|---|---|
| 2 | 2.1 | 18 min |
| 4 | 3.8 | 32 min |
| 6 | 5.6 | 46 min |
| 8 | 7.0 | 58 min |

The cost is dominated by 3072-bit modular exponentiations and grows linearly
in m. A Pi will differ from this machine by a factor the calibration run
measures; plan on the main run taking one to two hours on a Pi 4, less on a
Pi 5, and the scaling run about the same again. The progress line every 25
ballots prints a remaining-time estimate.

## Optional

- `--verify` also times the verifier per ballot. The
  verifier normally runs on any computer, not on the voting machine, so this
  is not part of the hardware figures and roughly doubles the run.
- The kiosk's admin panel ("RUN 500 BALLOTS") times the full cast path
  through the GUI service, including building the board record. It is a
  spot check; the paper's figures come from `harness/bench.py`.
