import pytest
@pytest.fixture(autouse=True)
def _trace_persist_failures(monkeypatch, request):
    import src.mirai.entrypoint as ep
    original = ep.log_to_file
    def traced(msg):
        if "Failed to persist bootstrap config" in str(msg):
            print(f"\n>>> EXCEPTION AVALÉE dans {request.node.name}: {msg}")
        return original(msg)
    monkeypatch.setattr(ep, "log_to_file", traced)
    yield
