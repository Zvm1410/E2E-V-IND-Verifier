# C0: paper-audit baseline

`baseline_c0.py` computes the detection probability of post-election paper
audits in two regimes: cluster sampling of whole polling stations (current
practice) and simple random sampling of individual ballots at the same rate
(a generous upper bound). Arithmetic is exact. `test_baseline_c0.py` checks
it against closed forms, a Monte Carlo simulation and the vector in
`spec/vectors/baseline_c0.json`. The evaluation harness uses it for the C0
configuration; the verifier does not.
