Geo Profiler JSON Format

Overview
- The profiler emits a single JSON array file containing aggregated per–source-line hotspots for the Motorola 68000 (M68K) CPU.
- Each element in the array is a JSON object with required fields describing a unique source file:line and optional fields added by post‑processing tools.
- The JSON file is written to the path specified by the GEO_PROF_JSON environment variable when the core exits or on demand.

Schema
- Top level: array of objects
- Object fields (required):
  - file: string
    - The source filename associated with this line entry as reported by DWARF .debug_line.
    - May be a basename or a relative path; the corresponding directory is provided via the DWARF line table and is used internally to locate source text.
  - line: integer (>= 1)
    - 1-based source line number.
  - cycles: integer (64-bit)
    - Total 68K CPU cycles accumulated for all PCs that map to this source line.
    - Cycles are exact: they are summed from the CPU core’s per‑instruction cycle counts.
  - count: integer (64-bit)
    - Total number of samples attributed to PCs that map to this line.
    - Sampling rate is fixed at 1/(2^GEO_PROF_SAMPLING_SHIFT) with GEO_PROF_SAMPLING_SHIFT = 4 by default (i.e., 1/16). Use count << 4 to approximate instruction counts if needed.
  - address: string
    - Hex string with 24-bit program counter for a representative instruction on this line, formatted as "0xHHHHHH".
    - The representative PC is the one with the highest cycle total among the PCs that mapped to this line.
  - source: string
    - Best‑effort copy of the source line’s text. Empty if the file could not be found.
    - Whitespace is normalized (leading indentation trimmed; tabs converted to spaces). Length is truncated to fit the on‑screen overlay.

- Object fields (optional; may be added by post‑processing):
  - function_chain: string
    - A demangled inline chain in the form "callee -> ... -> caller" (top → bottom), when available from an external resolver (e.g., addr2line/llvm-symbolizer).
  - Additional fields are permitted. Resolvers may add fields but should not remove required fields.

Semantics and notes
- Aggregation
  - PCs sampled during execution are mapped to file:line using DWARF .debug_line and aggregated by line.
  - cycles/count include all PCs that mapped to the same line.
- Address space
  - The 68K address space is 24-bit; addresses in the JSON reflect this and are formatted as 6 hex digits.
- Ordering
  - The array is not guaranteed to be pre‑sorted. Consumers should sort by cycles or count as needed.
- Stability
  - Field names and their types are stable. New optional fields may be introduced in the future.

Environment
- The core requires environment variables to be set before enabling the profiler:
  - GEO_PROF_ELF: absolute path to an ELF binary with DWARF debug info for .debug_line mapping.
  - GEO_PROF_JSON: absolute path where the JSON file will be written.
- The resolver script can enrich the JSON and also supports:
  - GEO_PROF_SRC_BASE (optional): source tree root for reading source lines by basename if the ‘source’ field is missing.

Example
[
  {
    "file": "game.c",
    "line": 123,
    "cycles": 9876543,
    "count": 4567,
    "address": "0x02A3F0",
    "source": "update_player(&state);",
    "function_chain": "update_player -> main_loop"
  },
  {
    "file": "sprite.c",
    "line": 88,
    "cycles": 543210,
    "count": 321,
    "address": "0x01BCDE",
    "source": "draw_sprite(&spr);"
  }
]

Consumer guidance
- Treat ‘cycles’ as the primary ranking metric for hotspots; ‘count’ is useful for sanity‑checking coverage given the sampling rate.
- Do not depend on array order; explicitly sort by cycles or count.
- ‘source’ is a convenience field and may be empty when the source file cannot be located; use GEO_PROF_SRC_BASE with the resolver to improve coverage.

