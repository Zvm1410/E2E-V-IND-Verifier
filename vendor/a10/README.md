# A10, fingerprinting adversaries (basket A)

`app/services/adversary.py` and `app/services/poll_state.py`, copied
unmodified from basket A's machine code. The harness imports the adversary
classes (A0Blind, A1Temporal, A2Interaction, A3Leakage, AOracle) and the
`AdversaryFeatures` dictionary so the evaluation runs A's rules exactly.
The verifier never imports them.
