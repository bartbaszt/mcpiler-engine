#!/usr/bin/env python3
"""Render deterministic runtime third-party notices from nuget-license JSON output."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: render-notices.py <inventory.json> <output.md>", file=sys.stderr)
        return 64

    inventory_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    packages = json.loads(inventory_path.read_text(encoding="utf-8-sig"))

    rows = sorted(
        (
            str(item["PackageId"]),
            str(item["PackageVersion"]),
            str(item["License"]),
        )
        for item in packages
    )

    lines = [
        "# MCPiler Engine third-party runtime notices",
        "",
        "This file is generated from the transitive dependency graph of",
        "`src/MCPiler.Engine.Host/MCPiler.Engine.Host.csproj`. Build/test-only analyzer packages are",
        "excluded. Regenerate and verify it with `eng/check-licenses.sh`.",
        "",
        "| Package | Version | Licence |",
        "| --- | --- | --- |",
    ]

    for package_id, version, license_id in rows:
        lines.append(f"| `{package_id}` | `{version}` | `{license_id}` |")

    exceptional = [row for row in rows if row[2] == "MCPILER-APPROVED-OSMFEULA"]
    if exceptional:
        lines.extend(
            [
                "",
                "## Reviewed JSON-Everything binary terms",
                "",
                "The official binaries listed below carry the OSMFEULA file distributed inside their",
                "NuGet packages. They are accepted only at the exact reviewed versions shown above and",
                "are intentionally not represented as ordinary MIT package binaries:",
                "",
            ]
        )
        lines.extend(f"- `{package_id} {version}`" for package_id, version, _ in exceptional)

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
