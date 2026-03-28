# Code Verification Engine Confidence Calibration Plan

## 1. Purpose

This document defines how confidence calibration is validated after canonical issue flow is complete.

## 2. Calibration Targets

- release-blocking rules rank above heuristic-only issues when support is stronger
- contradiction lowers confidence consistently
- degraded analyzers lower confidence consistently
- partial boundary lowers confidence consistently

## 3. Required Fixtures

- true positive
- false-positive guard
- contradiction
- degraded or incomplete
- unsupported

## 4. Exit Criteria

Calibration is complete only when expected ordering is stable across the benchmark corpus and no score depends on finding-first bridge metadata.
