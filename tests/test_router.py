"""Router: difficulty-driven tier selection."""

from tokenecon import DEFAULT_TIERS

from gateway.config import GatewayConfig, ProviderEntry
from gateway.providers.mock import MockProvider
from gateway.router import select_route


def _cfg():
    mock = MockProvider()
    return GatewayConfig(providers=[
        ProviderEntry(provider=mock, tier=DEFAULT_TIERS[0], models=["small-m"]),
        ProviderEntry(provider=mock, tier=DEFAULT_TIERS[1], models=["mid-m"]),
        ProviderEntry(provider=mock, tier=DEFAULT_TIERS[2], models=["big-m"]),
    ])


def test_easy_request_goes_cheap():
    route = select_route(_cfg(), "hi")
    assert route.entry.tier.name == "small"
    assert not route.degraded


def test_hard_request_goes_big():
    route = select_route(
        _cfg(),
        "Prove by induction that every comparison sort needs Omega(n log n) "
        "comparisons, then compare three proof strategies in detail.",
    )
    assert route.entry.tier.name == "large"


def test_model_pin_skips_tiering():
    route = select_route(_cfg(), "hi", model="big-m")
    assert route.model == "big-m"
    assert route.entry.tier.name == "large"


def test_unknown_model_pin_raises():
    import pytest

    cfg = _cfg()
    with pytest.raises(ValueError, match="not served"):
        select_route(cfg, "hi", model="nope")


def test_force_cheapest_degrades():
    route = select_route(_cfg(), "prove everything", force_cheapest=True)
    assert route.entry.tier.name == "small"
    assert route.degraded
