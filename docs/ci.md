# Keep authorization checks in continuous integration

Use disposable tenants and fresh credentials on every continuous integration (CI) run.
The [FastAPI example](../examples/fastapi/README.md) provides a complete local setup.
The [Supabase example](../examples/supabase/README.md) uses real local database and authentication containers.
Its `supabase-recipe` workflow checks broken and repaired policies on every pull request.
It uses disposable local credentials and requires no hosted Supabase secrets.

For an existing application, place these steps after its normal test setup:

1. Start the test application.
2. Seed two tenants and one private record with a unique canary.
3. Run your application's login helper for each test user.
4. Supply `VPT_ALICE_TOKEN` and `VPT_BOB_TOKEN` through the job environment.
5. Run the contract and retain its redacted report.
6. Remove test fixtures and stop the application.

For user isolation, two ordinary users replace the two-tenant fixture requirement.
Supabase also requires `VPT_SUPABASE_KEY`, containing a publishable or legacy `anon` key.

```sh
vpt check vpt-contract.json \
  --allow-origin http://127.0.0.1:8000 \
  --format sarif \
  --output authorization.sarif
```

Keep the command's exit code. Codes `1` and `2` must fail the job.
Upload the report from an `always()` step so failures retain evidence.
Use GitHub's `upload-artifact` action for all repositories.
GitHub code scanning accepts SARIF only where the repository's plan and settings permit it.
The report has stable case identifiers; it does not claim source-code line locations.

Never expose staging credentials to code from an untrusted pull request.
Use ephemeral local fixtures for fork contributions.
Keep real staging runs behind your repository's trusted workflow policy.

## Distribution status

The new package builds from this checkout with `uv build`.
Its wheel and source archive include the runner. The source archive also includes skills and examples.
The authorization workflow builds artifacts on Linux, macOS, and Windows.
The draft-release workflow builds, tests, installs, and attaches artifacts to a GitHub draft release.
It runs only when a maintainer dispatches it.

No Python Package Index release is assumed by these instructions.
Before publishing there, confirm the package name and configure trusted publishing for the repository.
After a GitHub release exists, replace checkout instructions with an exact released tag or verified wheel URL.
Keep a tested checkout path available for users who cannot use that package registry.
