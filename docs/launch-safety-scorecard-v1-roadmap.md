# Launch Safety Scorecard v1 Roadmap

## Goal

Build the first conversion path for the Launch Safety platform: a visitor pastes a public URL, receives a useful Launch Safety Scorecard, understands what to fix before launch, and sees a relevant Launch Safety Pro upgrade path.

This roadmap captures the product decisions from the grilling session. It is not an implementation PR by itself.

## First Scenario

Optimize for a vibe-coded entrepreneur who is about to launch a SaaS landing page and app preview built with AI coding tools. They have a public URL, may have a GitHub repository, lack security confidence, and need to know today whether they are about to embarrass themselves.

## Product Sequence

Scorecard v1 is the first product surface after the single-repo MCP merge.

Do not start with a full redesign or customer-facing GitHub Action before the Scorecard v1 conversion path works. The Launch Safety PR Reviewer should follow after scorecard reports are useful and repeatable.

## Free Scorecard Scope

The free Scorecard should:

- Run a real unauthenticated assessment of public URL behavior.
- Show useful progress immediately.
- Aim to complete within 2-5 minutes for normal public URLs.
- Return the first useful result without requiring an account or payment.
- Present a Launch Readiness Score, Launch Blocker count, and top validated findings.
- Include evidence, fix-before-launch actions, and a safe-to-share public summary.

If deeper validation takes longer than the acquisition flow can tolerate, show a partial scorecard first and continue in the background.

## Paid Boundaries

Launch Safety Pro should be introduced when the user wants:

- Authenticated pages.
- Repeat monitoring.
- More than the top findings.
- Remediation help.
- Dependency or CVE analysis.
- GitHub pull request comments.
- Team history.
- Proof that a fix worked.

The first useful result should not be gated.

## Report Privacy

The full report should be private by default.

The optional safe-to-share summary should hide sensitive evidence, exact exploit payloads, secrets, private paths, and detailed reproduction steps. Its purpose is social proof and lightweight sharing without increasing the user's risk.

## Minimum Report Shape

Scorecard v1 must include:

- Launch Readiness Score.
- Launch Blocker count.
- Top validated findings with evidence.
- Fix-before-launch actions.
- Safe-to-share public summary.
- Launch Safety Pro upsell.

## Metrics

Measure Scorecard v1 with:

- Scan start rate.
- Scan completion rate.
- Report view rate.
- Launch Safety Pro call-to-action click rate.

## Non-goals

Scorecard v1 should not optimize for enterprise compliance, SOC2 evidence, deep network scanning, internal asset discovery, WAF tuning, bug bounty workflows, full SAST coverage, or exhaustive pentest claims.

Scorecard v1 should not include the customer-facing GitHub Action. The PR Reviewer is the next wedge once scorecard outputs are useful.

## Implementation Slices

1. Scorecard result model

   Map existing validated findings into Launch Readiness Score, Launch Blocker count, top findings, fix-before-launch actions, and safe-to-share summary fields.

2. Free scan entry flow

   Adjust the existing web app entry path so a new visitor can paste a public URL and run the unauthenticated scorecard without account creation.

3. Scorecard report view

   Render the private report, safe-to-share summary, evidence, and Launch Safety Pro upsell clearly.

4. Conversion instrumentation

   Record scan start, scan completion, report view, and Pro CTA click events.

5. Regression coverage

   Add focused tests for scorecard shaping, launch-blocker classification, safe-summary redaction, and the public URL scan flow.

## Acceptance Criteria

- A new visitor can paste a public URL and start a free scorecard without an account.
- The scorecard renders a Launch Readiness Score, Launch Blocker count, top findings, evidence, and fix-before-launch actions.
- The report includes an optional safe-to-share summary that redacts sensitive details.
- Launch Safety Pro upsell appears only after a useful result or a clear free-product boundary.
- The flow records scan start, scan completion, report view, and Pro CTA click events.
- No customer-facing GitHub Action work is included in Scorecard v1.
