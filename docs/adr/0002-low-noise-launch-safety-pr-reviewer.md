# ADR 0002: Low-noise Launch Safety PR Reviewer

## Status

Accepted.

## Context

Launch Safety Pro needs a workflow that fits how vibe-coded entrepreneurs already ship: pull requests, preview deployments, and fast iteration.

A GitHub Action can create a useful acquisition and retention loop by commenting directly on risky changes. The risk is that security bots often become noisy linters, produce speculative findings, or block useful work without enough evidence.

## Decision

Build the Launch Safety PR Reviewer as a low-noise pull request reviewer, not a general security linter.

The reviewer should comment only on new or worsened Launch Blockers and high-confidence risks, using preview URL evidence and lightweight repository checks by default. Paid credentials unlock authenticated preview scans, deeper repo-aware checks, dependency and CVE intelligence, remediation comments, history, blocking policies, and team controls.

The reviewer should not make code changes automatically, post secrets in comments, scan private or internal URLs unless explicitly configured, or block merges for low-confidence issues.

## Consequences

The free Action can be useful without training users to ignore it.

Paid value comes from depth, history, authentication, remediation quality, and policy controls rather than from more frequent comments.

The product must invest in evidence quality and deduplication before expanding comment volume.
