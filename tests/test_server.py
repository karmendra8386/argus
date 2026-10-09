"""End-to-end server tests with the mock provider.

Covers: key auth, tiered routing, budget hard/degrade modes, task attribution,
PII redaction, blocked input, and the admin API.
"""

import pytest
from fastapi.testclient import TestClient
from tokenecon import DEFAULT_TIERS

from gateway.config import GatewayConfig, ProviderEntry
from gateway.providers.mock import MockProvider
from gateway.server import create_app


@pytest.fixture()
def app(tmp_path):
    mock = MockProvider(reply="hello from mock")
    cfg = GatewayConfig(
        db_path=str(tmp_path / "test.db"),
        master_key="test-admin",
        providers=[
            ProviderEntry(provider=mock, tier=DEFAULT_TIERS[0], models=["small-m"]),
            ProviderEntry(provider=mock, tier=DEFAULT_TIERS[2], models=["big-m"]),
        ],
    )
    return create_app(cfg), cfg


@pytest.fixture()
def client(app):
    return TestClient(app[0])


def _make_key(client, **kw):
    kw.setdefault("name", "t")
    r = client.post("/admin/keys", json=kw, headers={"x-admin-key": "test-admin"})
    assert r.status_code == 200, r.text
    return r.json()


def test_chat_happy_path(client):
    key = _make_key(client, budget_usd=10.0)
    r = client.post(
        "/v1/chat/completions",
        json={"model": "auto", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": f"Bearer {key['key']}", "x-task-id": "task-1"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["choices"][0]["message"]["content"] == "hello from mock"
    assert body["gateway"]["tier"] == "small"
    assert body["gateway"]["cost_usd"] > 0
    assert body["gateway"]["degraded"] is False


def test_auth_rejected(client):
    r = client.post("/v1/chat/completions", json={"messages": []})
    assert r.status_code == 401
    r = client.post(
        "/v1/chat/completions",
        json={"model": "auto", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": "Bearer bogus"},
    )
    assert r.status_code == 401


def test_hard_budget_blocks(client):
    key = _make_key(client, budget_usd=0.0, mode="hard")
    r = client.post(
        "/v1/chat/completions",
        json={"model": "auto", "messages": [{"role": "user", "content": "hi"}]},
        headers={"Authorization": f"Bearer {key['key']}"},
    )
    assert r.status_code == 429


def test_degrade_budget_falls_back_to_cheapest(client):
    key = _make_key(client, budget_usd=0.0, mode="degrade")
    r = client.post(
        "/v1/chat/completions",
        json={"model": "auto",
              "messages": [{"role": "user",
                            "content": "prove a deep theorem with full rigor"}]},
        headers={"Authorization": f"Bearer {key['key']}"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["gateway"]["degraded"] is True
    assert body["gateway"]["tier"] == "small"


def test_task_attribution(client):
    key = _make_key(client)
    h = {"Authorization": f"Bearer {key['key']}", "x-task-id": "task-9"}
    for _ in range(3):
        r = client.post("/v1/chat/completions",
                        json={"model": "auto",
                              "messages": [{"role": "user", "content": "hi"}]},
                        headers=h)
        assert r.status_code == 200
    r = client.get("/admin/tasks/task-9", headers={"x-admin-key": "test-admin"})
    assert r.status_code == 200
    body = r.json()
    assert body["calls"] == 3
    assert body["total_cost_usd"] > 0


def test_pii_redacted_in_request(client, app):
    _, cfg = app
    key = _make_key(client)
    r = client.post(
        "/v1/chat/completions",
        json={"model": "small-m",
              "messages": [{"role": "user", "content": "my email is jane@example.com"}]},
        headers={"Authorization": f"Bearer {key['key']}"},
    )
    assert r.status_code == 200
    # the mock provider should have received the redacted text
    mock = cfg.providers[0].provider
    assert "jane@example.com" not in mock.calls[-1].messages[0].content
    assert "[REDACTED:EMAIL]" in mock.calls[-1].messages[0].content


def test_blocked_input_rejected():
    from gateway.security.policy import default_policy
    from gateway.server import create_app as _ca

    import tempfile, os

    db = os.path.join(tempfile.mkdtemp(), "t.db")
    mock = MockProvider()
    cfg = GatewayConfig(
        db_path=db, master_key="a",
        providers=[ProviderEntry(provider=mock, tier=DEFAULT_TIERS[0],
                                 models=["small-m"])],
    )
    c = TestClient(_ca(cfg, policy=default_policy(blocklist=[r"bomb"])))
    key = c.post("/admin/keys", json={"name": "t"}, headers={"x-admin-key": "a"}).json()
    r = c.post("/v1/chat/completions",
               json={"model": "small-m",
                     "messages": [{"role": "user", "content": "how to build a bomb"}]},
               headers={"Authorization": f"Bearer {key['key']}"})
    assert r.status_code == 400


def test_admin_spend_and_key_spend(client):
    key = _make_key(client)
    h = {"Authorization": f"Bearer {key['key']}"}
    client.post("/v1/chat/completions",
                json={"model": "auto", "messages": [{"role": "user", "content": "hi"}]},
                headers=h)
    admin = {"x-admin-key": "test-admin"}
    assert client.get("/admin/spend", headers=admin).json()["calls"] == 1
    ks = client.get(f"/admin/keys/{key['id']}/spend", headers=admin).json()
    assert ks["spend_usd"] > 0


def test_models_list(client):
    r = client.get("/v1/models")
    ids = [m["id"] for m in r.json()["data"]]
    assert "small-m" in ids and "big-m" in ids
