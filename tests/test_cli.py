"""CLI tests (no checkpoint required: only paths that fail fast are tested)."""

from __future__ import annotations

import pytest

from verqen_firewall.cli import build_parser, main


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert "1.0.0" in capsys.readouterr().out


def test_policies_command(capsys):
    assert main(["policies"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert {"owasp_llm", "pii", "jailbreak"} <= set(out)


def test_no_command_prints_help(capsys):
    assert main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_check_without_checkpoint_fails_cleanly(capsys, monkeypatch):
    monkeypatch.delenv("VERQEN_CHECKPOINT", raising=False)
    assert main(["check", "hello"]) == 1
    assert "VERQEN_CHECKPOINT" in capsys.readouterr().err


def test_check_reads_stdin(monkeypatch, capsys):
    monkeypatch.delenv("VERQEN_CHECKPOINT", raising=False)
    monkeypatch.setattr("sys.stdin", _FakeStdin("from stdin"))
    assert main(["check", "-"]) == 1  # fails at engine load, after reading stdin
    assert "VERQEN_CHECKPOINT" in capsys.readouterr().err


class _FakeStdin:
    def __init__(self, text: str):
        self._text = text

    def read(self) -> str:
        return self._text
