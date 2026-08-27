# ADEXA Dataset Pipeline

This directory contains the dataset-generation, corruption, validation, and verification pipeline used to support ADEXA's SQL injection repair research.

The pipeline is designed around the following flow:

```text
Valid Payload
    ↓
Controlled Corruption
    ↓
Failure Classification
    ↓
Repair Strategy
    ↓
Repaired Payload
    ↓
Validation
    ↓
Verification

