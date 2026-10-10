"""Current-object command-line interface (CLI) transport exhaustion controls.

Fault injection models an allocation outage observed in actual full qualification.
It is not evidence of native checker accuracy or host availability.
"""
from argparse import Namespace
from io import BytesIO
import json

import pytest

from verifier.domains.contracts.current_object_routes import CurrentObjectRouteRefusal
from verifier.runtime import current_object_cli as cli


def test_small_real_file_reads_exact_bytes_and_boundary(tmp_path):
    selected = tmp_path / 'certificate.json'
    selected.write_bytes(b'finite')
    assert cli._read_bounded(str(selected), 6) == b'finite'
    with pytest.raises(CurrentObjectRouteRefusal):
        cli._read_bounded(str(selected), 5)


def test_small_transport_does_not_request_maximum_allocation(monkeypatch):
    class RestrictedStream(BytesIO):
        def read(self, size=-1):
            if size > 65536:
                raise MemoryError('explicit allocation-constrained transport')
            return super().read(size)
    monkeypatch.setattr(cli.Path, 'open', lambda *args, **kwargs: RestrictedStream(b'finite'))
    assert cli._read_bounded('fixture', 16*1024*1024) == b'finite'


def test_actual_allocation_outage_returns_unknown(monkeypatch, capsys):
    def unavailable(*args, **kwargs):
        raise MemoryError('explicit observed-failure control')
    monkeypatch.setattr(cli, '_read_selection', unavailable)
    args = Namespace(current_object_command='check', semantic_version='verifier-current-object-obligations-1',
        objective='OBJECT-1.1', represented_kind='VERIFIER', request='fixture', policy='fixture', certificate='fixture', json=True)
    assert cli.handle_current_object_command(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['replay_status'] == 'UNAVAILABLE' and result['computational_status'] == 'UNKNOWN'
