# Code Verification Engine Aggregation Hardening Specification

## 1. Purpose

This document defines the hardening requirements for canonical issue aggregation.

## 2. Requirements

1. deterministic clustering
2. stable issue IDs and fingerprints
3. preserved counter-evidence
4. source-summary integrity
5. no semantic dependence on generic findings

## 3. Test Focus

- overlap merge
- family merge
- contradiction retention
- synthetic evidence fallback for incomplete seeds
- stable candidate ordering
