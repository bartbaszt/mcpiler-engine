#!/usr/bin/env python3
"""Build the deterministic MVMX v1 vector fixture used by this example."""

import json
import struct
from pathlib import Path

ids = ["list-pets", "get-pet"]
vectors = [
    (1.0, 0.0, 0.0),
    (0.0, 1.0, 0.0),
]

header = {
    "formatVersion": 1,
    "dimension": 3,
    "count": len(ids),
    "elementType": "float32",
    "normalization": "l2",
    "ids": ids,
}
header_bytes = json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

payload = bytearray(b"MVMX")
payload.extend(struct.pack("<i", len(header_bytes)))
payload.extend(header_bytes)

for row in vectors:
    for value in row:
        payload.extend(struct.pack("<f", value))

Path(__file__).with_name("vectors.bin").write_bytes(payload)
print(f"wrote vectors.bin: {len(payload)} bytes")
