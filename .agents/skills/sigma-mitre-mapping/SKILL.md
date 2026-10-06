---
name: sigma-mitre-mapping
description: Use when implementing or testing the Sigma detection engine (sigma_engine.py) or writing Sigma rule test cases.
---

[Paste the full Sigma↔MITRE mapping table from our earlier session here —
 all tactics, technique IDs, Sigma rule concepts, log sources, and
 detection artifacts. This is the authoritative rule-to-technique
 contract; the engine must implement real pySigma matching against
 real SigmaHQ-syntax rules, not keyword string matching.]

Testing requirement: every technique tag the engine outputs must cite
the matched event's evidence (mirror the existing
test_attack_technique_labels_grounded pattern in the test suite).