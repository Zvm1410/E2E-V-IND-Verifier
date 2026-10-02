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

At the same sampling rate, test ballots (C2) and a simple random sample of slips (C0) detect a blind redirection equally; the comparison that matters is at matched effort against current practice (Table 4).

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

Detection under C2 assumes an honest, disciplined tester. A tester whose behaviour differs from voters' (the naive regime) lets A2 evade most challenges: at k = 50 detection is 0.22 against 0.92 for a blind adversary. A compromised tester is outside the threat model.

## Table 3. C2 with a blind adversary, by test rate

| test rate p | k=1 | k=2 | k=5 | k=10 | k=20 | k=50 |
|---|---|---|---|---|---|---|
| 1/50 | 0.021 [0.015, 0.028] | 0.043 [0.035, 0.053] | 0.099 [0.087, 0.113] | 0.180 [0.164, 0.197] | 0.345 [0.325, 0.367] | 0.632 [0.611, 0.653] |
| 1/20 | 0.047 [0.039, 0.057] | 0.106 [0.094, 0.121] | 0.222 [0.204, 0.241] | 0.405 [0.384, 0.427] | 0.637 [0.616, 0.658] | 0.917 [0.905, 0.929] |
| 1/10 | 0.100 [0.087, 0.113] | 0.211 [0.194, 0.229] | 0.408 [0.387, 0.430] | 0.649 [0.628, 0.670] | 0.867 [0.851, 0.881] | 0.995 [0.991, 0.997] |

## Table 4. Assembly segment: detection at matched effort

A segment of 250 booths of 800 voters. Units handled by each mechanism:

| Mechanism | What is done | Units per segment | When |
|---|---|---|---|
| C0 cluster (current practice) | 5 booths hand-counted | 4,000 slips | after the poll |
| C0 simple random sample | individual slips at the same rate | 4,000 slips | after the poll |
| C2, p = 1/50 | 16 test ballots per booth | 4,000 test ballots | during the poll |
| C2, p = 1/20 | 40 test ballots per booth | 10,000 test ballots | during the poll |

Probability that the same manipulation is detected (blind adversary, honest paper trail for C0, honest and disciplined tester for C2):

| votes moved | booths touched | C0 cluster | C0 random sample | C2, p = 1/50 | C2, p = 1/20 |
|---|---|---|---|---|---|
| 10 | 1 | 0.020 | 0.183 | 0.183 | 0.401 |
| 50 | 1 | 0.020 | 0.636 | 0.636 | 0.923 |
| 50 | 5 | 0.097 | 0.636 | 0.636 | 0.923 |
| 200 | 5 | 0.097 | 0.982 | 0.982 | 1.000 |
| 1000 | 5 | 0.097 | 1.000 | 1.000 | 1.000 |
| 1000 | 25 | 0.412 | 1.000 | 1.000 | 1.000 |
| 1000 | 125 | 0.970 | 1.000 | 1.000 | 1.000 |
| 250 | 250 | 1.000 | 0.994 | 0.994 | 1.000 |

C2 at p = 1/50 handles the same number of units as current practice. Per unit handled it detects exactly as well as a simple random sample of slips, and better than cluster sampling whenever the manipulation is concentrated in a few booths; spread one vote per booth, cluster sampling is marginally ahead. Units are not labour: a test ballot is cast, challenged and compared, which costs more than counting a slip, and C2's units fall during the poll at every booth. The comparison holds for a blind adversary; Table 2 shows how fingerprinting reduces C2's detection, and C0's detection falls in turn if the paper trail itself is unreliable (baseline_c0's parameter d).

## Table 5. Attack attribution on full-crypto boards

| Scenario | Expected | Verifier |
|---|---|---|
| Vote redirection | P3 | P3 |
| Ballot stuffing | P4 | P4 |
| Malformed ballot injection | P2 | P2 |
| Tally manipulation | P5 | P5 |
| Retroactive board edit | P1 | P1 |
| (clean election) | Accept | Accept |
| (configuration C1) | Accept, P3 not exercised | Accept, P3 not exercised |

Each board is verified with its tester's record (SPEC 11.1). Without it the redirection board is accepted: the machine opened the challenged ballots truthfully, which is consistent on the board.

## Table 6. Full-crypto runs: false rejection and the fast-model check

| Measure | Value |
|---|---|
| clean elections verified | 12 |
| false rejections | 0 |
| redirection runs, verifier agrees with model | 12 / 12 |
| of which detected (P3) | 3 |
| ballots per election, serials redirected per run | 40, 8 |

## Table 7. Per-ballot cost on the target hardware

| m | encrypt p50 | prove p50 | total p50 | total p99 |
|---|---|---|---|---|
| — | — | — | — | — |

## Sanity checks

- A0 under C2 reproduces 1-(1-p)^k across 18 cells (Bonferroni family-wise 95%): True
- Cells outside their own 95% interval (about 1 in 20 expected by chance): p=1/10 k=2
- Highest AOracle detection rate: 0.0
