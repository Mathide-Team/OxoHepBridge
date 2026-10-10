"""Stack HOMER7 de démonstration (deploy/homer/compose.yml, issue #47)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml  # fourni par pre-commit (extra dev)

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE = REPO_ROOT / "deploy" / "homer" / "compose.yml"


@pytest.fixture(scope="module")
def services() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]


def test_trois_services(services):
    assert set(services) == {"db", "heplify-server", "homer-app"}


def test_ports_alignes_sur_la_config_de_demo(services):
    ports = services["heplify-server"]["ports"]
    assert "9060:9060/udp" in ports
    assert "9060:9060/tcp" in ports
    assert "9061:9061/tcp" in ports
    assert "9080:80" in services["homer-app"]["ports"]
    demo = (REPO_ROOT / "config" / "oxo-hep-bridge.homer-demo.toml").read_text(encoding="utf-8")
    assert "port = 9060" in demo


def test_heplify_ecrit_dans_la_base_de_la_stack(services):
    env = services["heplify-server"]["environment"]
    db = services["db"]["environment"]
    assert env["HEPLIFYSERVER_DBDRIVER"] == "postgres"
    assert env["HEPLIFYSERVER_DBADDR"] == "db:5432"
    assert env["HEPLIFYSERVER_DBUSER"] == db["POSTGRES_USER"]
    assert env["HEPLIFYSERVER_DBPASS"] == db["POSTGRES_PASSWORD"]
    assert services["homer-app"]["environment"]["DB_PASS"] == db["POSTGRES_PASSWORD"]
    # Dossier existant et inscriptible : le certificat auto-signé y est
    # généré au démarrage (un dossier absent fait échouer le listener TLS).
    assert env["HEPLIFYSERVER_TLSCERTFOLDER"] == "/tmp"


def test_images_officielles_sipcapture(services):
    assert services["heplify-server"]["image"].startswith("ghcr.io/sipcapture/heplify-server")
    assert services["homer-app"]["image"].startswith("ghcr.io/sipcapture/homer-app")


def test_documentation_de_la_demo():
    doc = (REPO_ROOT / "deploy" / "homer" / "README.md").read_text(encoding="utf-8")
    for attendu in ("--pcap-retime", "no partition", "--hep-compress-payload", "keepalive"):
        assert attendu in doc
    assert "deploy/homer" in (REPO_ROOT / "README.md").read_text(encoding="utf-8")
