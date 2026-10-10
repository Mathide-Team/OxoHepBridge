"""--pcap-retime (issue #47) : relecture d'une capture ancienne vers HOMER7.

heplify-server + PostgreSQL range chaque paquet dans une partition datée ;
les partitions n'existent qu'autour de la date du jour. Vérifié contre
heplify-server 1.60.9 : les captures d'exemple (2017-2018) étaient toutes
rejetées (« no partition of relation hep_proto_100_default found for row »).
"""

from __future__ import annotations

import time
from pathlib import Path

from oxo_hep_bridge.bridge import Bridge
from oxo_hep_bridge.cli import _apply_cli_args, build_parser
from oxo_hep_bridge.config import Config, apply_env
from oxo_hep_bridge.hep import HepPacket
from oxo_hep_bridge.sender import Sender

PCAP = "tests/fixtures/ua3g_freeseating_ipv4.pcap"
REPO_ROOT = Path(__file__).resolve().parent.parent


class RecordingSender(Sender):
    def __init__(self) -> None:
        self.sent: list[HepPacket] = []

    def send(self, packet) -> bool:
        self.sent.append(packet)
        return True


def _run(retime: bool, pcap: str | None = PCAP, interface: str | None = None) -> list[HepPacket]:
    config = Config()
    config.capture.pcap = pcap
    config.capture.interface = interface
    config.capture.pcap_retime = retime
    config.dry_run = True
    bridge = Bridge(config)
    recorder = RecordingSender()
    bridge.sender = recorder
    bridge.run()
    return recorder.sent


def _us(pkt: HepPacket) -> int:
    return pkt.timestamp_sec * 1_000_000 + pkt.timestamp_usec


def test_sans_retime_les_horodatages_de_la_capture_sont_conserves(fake_popen):
    sent = _run(retime=False)
    assert sent
    assert all(p.timestamp_sec < 1_600_000_000 for p in sent)  # capture de 2017


def test_retime_premier_paquet_a_l_heure_courante(fake_popen):
    avant = time.time()
    sent = _run(retime=True)
    apres = time.time()
    assert avant - 1 <= sent[0].timestamp_sec <= apres + 1


def test_retime_conserve_les_ecarts_relatifs(fake_popen):
    brut = _run(retime=False)
    recale = _run(retime=True)
    assert len(brut) == len(recale)
    ecarts_bruts = [_us(b) - _us(brut[0]) for b in brut]
    ecarts_recales = [_us(r) - _us(recale[0]) for r in recale]
    assert ecarts_bruts == ecarts_recales
    assert all(0 <= r.timestamp_usec < 1_000_000 for r in recale)


def test_retime_sans_effet_en_capture_live():
    config = Config()
    config.capture.interface = "eth0"
    config.capture.pcap_retime = True
    bridge = Bridge(config)
    pkt = HepPacket(timestamp_sec=1_500_000_000, timestamp_usec=42)
    assert bridge.retime(pkt) is pkt


def test_retime_desactive_par_defaut():
    assert Config().capture.pcap_retime is False


def test_cli_pcap_retime():
    config = Config()
    _apply_cli_args(config, build_parser().parse_args(["--pcap", "/tmp/c.pcap", "--pcap-retime"]))
    assert config.capture.pcap_retime is True


def test_cli_sans_pcap_retime_n_ecrase_pas_toml_ni_env():
    config = Config()
    config.capture.pcap_retime = True
    _apply_cli_args(config, build_parser().parse_args(["--pcap", "/tmp/c.pcap"]))
    assert config.capture.pcap_retime is True


def test_toml_pcap_retime(tmp_path):
    toml = tmp_path / "c.toml"
    toml.write_text('[capture]\npcap = "x.pcap"\npcap_retime = true\n', encoding="utf-8")
    assert Config.load(toml_path=toml).capture.pcap_retime is True


def test_env_pcap_retime(monkeypatch):
    monkeypatch.setenv("OXOHEP_PCAP_RETIME", "1")
    config = Config()
    apply_env(config)
    assert config.capture.pcap_retime is True


def test_config_de_demo_homer_active_le_retime():
    config = Config.load(toml_path=REPO_ROOT / "config" / "oxo-hep-bridge.homer-demo.toml")
    assert config.capture.pcap_retime is True
    assert config.capture.pcap and Path(REPO_ROOT / config.capture.pcap).is_file()
    assert (config.hep.host, config.hep.port) == ("127.0.0.1", 9060)
