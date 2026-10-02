# Results

Detection rates are proportions over 2000 simulated elections of 200 ballots, with Wilson 95% intervals in brackets.

## Table 1. Vote redirection detected, by configuration (p = 1/20)

| k redirected | C0 paper audit (SRS) | C1 no test ballots | C2 test ballots | 1-(1-p)^k |
|---|---|---|---|---|
| 1 | 0.056 [0.047, 0.067] | 0.000 [0.000, 0.002] | 0.047 [0.039, 0.057] | 0.050 |
| 2 | 0.090 [0.078, 0.103] | 0.000 [0.000, 0.002] | 0.106 [0.094, 0.121] | 0.098 |
| 5 | 0.236 [0.218, 0.255] | 0.000 [0.000, 0.002] | 0.222 [0.204, 0.241] | 0.226 |
| 10 | 0.408 [0.387, 0.430] | 0.000 [0.000, 0.002] | 0.405 [0.384, 0.427] | 0.401 |
| 20 | 0.646 [0.625, 0.667] | 0.000 [0.000, 0.002] | 0.637 [0.616, 0.658] | 0.642 |
| 50 | 0.936 [0.925, 0.946] | 0.000 [0.000, 0.002] | 0.917 [0.905, 0.929] | 0.923 |

## Table 2. Fingerprinting adversaries under C2 (p = 1/20)

| Adversary (C2) | k=1 | k=2 | k=5 | k=10 | k=20 | k=50 |
|---|---|---|---|---|---|---|
| A0 blind | 0.047 [0.039, 0.057] | 0.106 [0.094, 0.121] | 0.222 [0.204, 0.241] | 0.405 [0.384, 0.427] | 0.637 [0.616, 0.658] | 0.917 [0.905, 0.929] |
| AOracle | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] |
| A1 temporal, disciplined tester | 0.054 [0.045, 0.065] | 0.091 [0.080, 0.105] | 0.231 [0.213, 0.249] | 0.403 [0.381, 0.424] | 0.638 [0.617, 0.659] | 0.923 [0.911, 0.934] |
| A1 temporal, naive tester | 0.053 [0.044, 0.064] | 0.091 [0.080, 0.105] | 0.222 [0.204, 0.240] | 0.382 [0.360, 0.403] | 0.645 [0.624, 0.666] | 0.924 [0.912, 0.935] |
| A2 interaction, disciplined tester | 0.055 [0.046, 0.066] | 0.092 [0.081, 0.106] | 0.232 [0.214, 0.250] | 0.405 [0.384, 0.427] | 0.645 [0.624, 0.666] | 0.937 [0.925, 0.947] |
| A2 interaction, naive tester | 0.005 [0.003, 0.010] | 0.015 [0.010, 0.021] | 0.030 [0.024, 0.039] | 0.052 [0.044, 0.063] | 0.107 [0.095, 0.122] | 0.220 [0.202, 0.239] |
| A3 leakage 0.0 | 0.061 [0.052, 0.073] | 0.104 [0.091, 0.118] | 0.234 [0.216, 0.253] | 0.414 [0.393, 0.436] | 0.658 [0.637, 0.679] | 0.934 [0.922, 0.944] |
| A3 leakage 0.25 | 0.036 [0.029, 0.045] | 0.070 [0.059, 0.081] | 0.184 [0.168, 0.202] | 0.341 [0.321, 0.362] | 0.555 [0.533, 0.577] | 0.880 [0.866, 0.894] |
| A3 leakage 0.5 | 0.028 [0.021, 0.036] | 0.051 [0.043, 0.062] | 0.127 [0.113, 0.142] | 0.250 [0.232, 0.269] | 0.441 [0.419, 0.463] | 0.749 [0.730, 0.768] |
| A3 leakage 0.75 | 0.016 [0.011, 0.022] | 0.026 [0.020, 0.034] | 0.068 [0.058, 0.080] | 0.113 [0.099, 0.127] | 0.237 [0.219, 0.257] | 0.502 [0.480, 0.524] |
| A3 leakage 1.0 | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] | 0.000 [0.000, 0.002] |

## Table 3. C2 with a blind adversary, by test rate

| test rate p | k=1 | k=2 | k=5 | k=10 | k=20 | k=50 |
|---|---|---|---|---|---|---|
| 1/50 | 0.021 [0.015, 0.028] | 0.043 [0.035, 0.053] | 0.099 [0.087, 0.113] | 0.180 [0.164, 0.197] | 0.345 [0.325, 0.367] | 0.632 [0.611, 0.653] |
| 1/20 | 0.047 [0.039, 0.057] | 0.106 [0.094, 0.121] | 0.222 [0.204, 0.241] | 0.405 [0.384, 0.427] | 0.637 [0.616, 0.658] | 0.917 [0.905, 0.929] |
| 1/10 | 0.100 [0.087, 0.113] | 0.211 [0.194, 0.229] | 0.408 [0.387, 0.430] | 0.649 [0.628, 0.670] | 0.867 [0.851, 0.881] | 0.995 [0.991, 0.997] |

## Table 4. Paper-audit baseline at segment scale (B10)

| votes moved | booths touched | C0 cluster (ECI practice) | C0 SRS (upper bound) |
|---|---|---|---|
| 1000 | 5 | 0.097 | 1.0000 |
| 1000 | 25 | 0.412 | 1.0000 |
| 1000 | 125 | 0.970 | 1.0000 |
| 250 | 250 | 1.000 | 0.9936 |

## Table 5. Attack attribution on full-crypto boards (D7)

| Attack | Hook | Expected | Verifier |
|---|---|---|---|
| Vote redirection | A8 | P3 | P3 |
| Ballot stuffing | A9 | P4 | P4 |
| Malformed ballot injection | B12 | P2 | P2 |
| Tally manipulation | C10 | P5 | P5 |
| Retroactive board edit | C11 | P1 | P1 |
| (clean run) | - | Accept | Accept |
| (configuration C1) | - | Accept, P3 not exercised | Accept, P3 not exercised |

## Table 6. Full-crypto runs (D10 and fast-model check)

| Measure | Value |
|---|---|
| clean elections verified | 12 |
| false rejections | 0 |
| redirection runs, verifier agrees with model | 12 / 12 |
| of which detected (P3) | 3 |
| ballots per election, serials redirected per run | 40, 8 |

## Table 7. Per-ballot cost on the target hardware (A11)

| m | encrypt p50 | prove p50 | total p50 | total p99 |
|---|---|---|---|---|
| — | — | — | — | — |

## Sanity checks (D9)

- A0 under C2 reproduces 1-(1-p)^k across 18 cells (Bonferroni family-wise 95%): True
- Cells outside their own 95% interval (about 1 in 20 expected by chance): p=1/10 k=2
- Highest AOracle detection rate: 0.0
