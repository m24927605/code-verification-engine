// Package engine orchestrates the code verification pipeline.
//
// The engine is a deterministic verification system that:
//
//	Input:  repo path / git ref / verification profile
//	Output: deterministic findings + evidence + partial/unknown markers
//
// It does NOT:
//   - Use LLM for verdict decisions
//   - Score candidates
//   - Drive business workflows
//
// Its sole purpose is to produce auditable code verification verdicts
// backed by structured evidence. Every finding is either:
//   - pass:    evidence confirms the claim
//   - fail:    evidence contradicts the claim
//   - unknown: evidence is insufficient to determine
//
// The engine prefers conservative unknown over false confidence.
package engine
