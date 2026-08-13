#!/usr/bin/env python3
"""CLI for the frozen Lawyer Assistance v0.4.0 release contract."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from release.release_contract import (
    ContractError,
    ContractLoadError,
    load_contract,
    validate_repository,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate the v0.4.0 release contract")
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("current", "formal"))
    parser.add_argument("--mcp-binary", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        contract = load_contract(args.contract)
    except ContractLoadError as error:
        print(f"RELEASE_CONTRACT_LOAD: {error}", file=sys.stderr)
        return 2
    try:
        result = validate_repository(args.root, contract, args.mode, args.mcp_binary)
    except ContractError as error:
        print(f"RELEASE_CONTRACT_{error.code}: {error}", file=sys.stderr)
        return 1
    print(f"release contract {result.mode} OK: {result.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
