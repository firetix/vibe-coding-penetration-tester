# FastAPI: catch a missing tenant filter

This local example includes two users, two tenants, and one private invoice.
Its fixed tokens are training fixtures. Do not use this authentication code in production.

Run all commands from the repository root.

## See the failure

Start the broken application:

```sh
uv run --with fastapi --with uvicorn python examples/fastapi/app.py --vulnerable
```

In another terminal:

```sh
export VPT_ALICE_TOKEN=demo-alice
export VPT_BOB_TOKEN=demo-bob
uv run vpt check examples/fastapi/contract.json --allow-origin http://127.0.0.1:8000
```

The owner check passes. Bob receives Alice's private canary. The command exits with code `1`.

## Verify the fix

Stop the example with Control-C. Restart without `--vulnerable`:

```sh
uv run --with fastapi --with uvicorn python examples/fastapi/app.py
```

Run the same check again. Bob receives `403`. Anonymous access receives `401`. The command exits with code `0`.

The relevant fix compares the authenticated tenant with the record's tenant.
Production applications should enforce this rule in their existing data access layer.
Use the authenticated tenant when selecting records. Never trust a tenant supplied by the request alone.

## Run the whole example automatically

```sh
uv run --with fastapi --with uvicorn python examples/fastapi/verify.py
```

The script starts each version, checks it, and stops its local server.
The repository's authorization workflow runs this example in continuous integration.

## Adapt your application

Use your real test login helper to mint two short-lived bearer tokens.
Seed separate tenants and a record containing a unique private canary.
Change the identity pointers and record path in the example contract.
Keep those values stable across the broken and fixed checks.
Do not copy production customer data into the fixture.

For each CI run: seed fixtures, mint fresh tokens, export dedicated variables, run checks, then remove fixtures.
Keep that login step outside VibePenTester. Authentication differs between applications.
