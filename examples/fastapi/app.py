"""Local training fixture. Never deploy this fixed-token authentication example."""

import argparse

import uvicorn
from fastapi import FastAPI, Header, HTTPException

app = FastAPI()
app.state.vulnerable = False
USERS = {
    "Bearer demo-alice": {"id": "alice", "tenant_id": "tenant-alice"},
    "Bearer demo-bob": {"id": "bob", "tenant_id": "tenant-bob"},
}
INVOICE = {
    "id": "invoice-alice",
    "tenant_id": "tenant-alice",
    "private_note": "vpt-private-fixture-alice-7f38d2",
}


def authenticate(authorization):
    user = USERS.get(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Sign in.")
    return user


@app.get("/api/me")
def me(authorization: str | None = Header(default=None)):
    return authenticate(authorization)


@app.get("/api/invoices/{invoice_id}")
def invoice(invoice_id: str, authorization: str | None = Header(default=None)):
    user = authenticate(authorization)
    if invoice_id != INVOICE["id"]:
        raise HTTPException(status_code=404, detail="Invoice not found.")
    if not app.state.vulnerable and user["tenant_id"] != INVOICE["tenant_id"]:
        raise HTTPException(status_code=403, detail="Access denied.")
    return INVOICE


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Disposable local authorization fixture")
    parser.add_argument("--vulnerable", action="store_true")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    app.state.vulnerable = args.vulnerable
    uvicorn.run(app, host="127.0.0.1", port=args.port, access_log=False)
