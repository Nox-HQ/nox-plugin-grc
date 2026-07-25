# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- chore(deps): Go 1.26.5 and nox SDK v1.17.0 (#30)
- build(deps): bump actions/setup-go from 6.5.0 to 7.0.0 (#22)


## [Unreleased]

## [v0.7.3] - 2026-07-25

### Changed

- **The advertised framework count is now correct, and pinned to the table.**
  The plugin described itself as covering "10 frameworks" long after it had
  grown to 15 selectable baselines across 13 frameworks, and because
  `plugin.yaml` is what generates the registry index entry, that stale figure
  was what users saw when browsing the marketplace. FedRAMP Low/Moderate/High
  are three baselines of one framework, so the headline number collapses them
  (13) and reports the baseline count alongside (15). A test now derives both
  numbers from the framework table and asserts the manifest and README agree,
  so a framework added in future cannot leave the advertised number behind.

## [v0.7.2] - 2026-07-25

### Fixed

- **An unknown or missing framework no longer returns a silent empty report.**
  `gap_report` and `evidence` returned an empty response when `framework` was
  absent or unrecognised. For a compliance tool that is the worst available
  failure: an empty gap report reads as "no gaps", so a plausible typo produced
  a clean bill of health for a framework that was never assessed — measured,
  `soc-2`, `SOC2`, `iso-27001` and `nonsense` all returned zero findings and no
  explanation, while the correct `soc2` returned eight. Both tools now attach a
  warning diagnostic naming the unknown framework and listing the valid IDs.
  The response still carries no findings, because there is genuinely nothing to
  report about a framework that was not assessed; what changes is that the
  operator is told. A valid framework emits no diagnostic, asserted by test so
  this cannot decay into background noise.

## [v0.7.0] - 2026-07-18

### Added

- Agentic-AI control mappings (AGENT-001..003) against ISO 27001 Annex A

  Reconciles work that had accumulated only in nox's `plugins/` directory,
  where a duplicate copy of this plugin lived. That copy has now been removed;
  this repository is the single source.


## [0.2.0] - 2026-02-24

### Added
- FedRAMP Low, Moderate, and High compliance baselines (`fedramp.go`)
- 25/38/42 NIST 800-53 controls per baseline with full rule mappings
- 302/523/595 unique nox rules covered per baseline
- `TestFedRAMPBaselineInclusion` — verifies High ⊇ Moderate ⊇ Low
- `TestFedRAMPControlCounts` — verifies expected control counts per baseline

### Changed
- Frameworks increased from 10 to 12 (replaced single `fedramp` with 3 baselines)
- `assessFrameworkSpecific` SC-28 encryption check scoped to Moderate/High only
- `TestFrameworksByName` updated for 12 frameworks

## [0.1.0] - 2026-02-22

### Added
- Initial GRC plugin with 10 compliance frameworks
- 3 tools: assess, gap_report, evidence
- 10 rules (GRC-001 through GRC-010)
- Gap analysis with coverage percentage and priority remediation
- Evidence collection mapped to framework controls
- Opt-in AI-powered gap analysis via `ai_assess: true`
- 7-provider LLM support (OpenAI, Anthropic, Gemini, Ollama, Cohere, Bedrock, Copilot)
- SDK conformance and track conformance tests
- CI/CD, lint config, pre-commit hooks
