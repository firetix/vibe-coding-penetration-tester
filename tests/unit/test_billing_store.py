import threading

from utils.billing_store import BillingStore


def test_try_consume_entitlement_for_scan_is_atomic_for_free_scan(tmp_path):
    db_path = tmp_path / "billing_store_atomic.db"
    store = BillingStore(str(db_path))
    account_id = "acct-atomic"
    store.ensure_account(account_id)

    barrier = threading.Barrier(2)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        decision = store.try_consume_entitlement_for_scan(account_id, "quick")
        with lock:
            results.append(decision)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    allowed_count = sum(1 for item in results if item["allowed"])
    free_consumes = sum(1 for item in results if item.get("consume") == "free")
    assert allowed_count == 1
    assert free_consumes == 1

    entitlements = store.get_entitlements(account_id)
    assert entitlements["free_scans_remaining"] == 0


def test_refund_consumption_restores_free_scan(tmp_path):
    db_path = tmp_path / "billing_store_refund.db"
    store = BillingStore(str(db_path))
    account_id = "acct-refund"
    store.ensure_account(account_id)

    decision = store.try_consume_entitlement_for_scan(account_id, "quick")
    assert decision["allowed"] is True
    assert decision["consume"] == "free"
    assert store.get_entitlements(account_id)["free_scans_remaining"] == 0

    store.refund_consumption(account_id, "free")
    assert store.get_entitlements(account_id)["free_scans_remaining"] == 1
