# Aggregating profiler stream packets into the canonical JSON format

Each IPC stream packet now carries the per-frame deltas that `geo_profiler_dump()` would later emit as JSON. A typical packet looks like:

```json
{"stream":"profiler","enabled":"enabled","hits":[{"pc":"0x00A3F2","samples":12,"cycles":4567},...]}
```

You can turn a sequence of these packets into the same aggregated JSON array described in `docs/profile-json.md` by replaying them through the same logic that the core already uses for dumping. The steps below outline how to do that manually and explicitly call out that aggregation happens on `file:line`.

1. **Read packets until the run finishes**  
   * Only consider messages where `"stream":"profiler"`. Command responses and other notifications use different keys and should be ignored.  
   * The `"hits"` array contains per-PC deltas since the previous frame; each object has `pc` (24-bit hex), `samples`, and `cycles`.  
   * Skip packets where `"enabled":"disabled"` if you only want the profile data from when sampling was active (the stream still emits zero-hit frames even when disabled).

2. **Maintain a PC accumulator**  
   * Keep a map keyed by the numeric PC value.  
   * For each hit, add the incoming `samples` and `cycles` to that PC’s running totals.  
   * Do not reset the map until you are ready to flush the final JSON, unless you intentionally want per-session segments.

3. **Map PCs to file/line (this is the aggregation key)**  
   * `geo_profiler_dump()` uses the DWARF `.debug_line` info from `GEO_PROF_ELF` to resolve a PC to a source `file` and `line`, then sums all PCs that share the same line.  
   * If you want the same `file`, `line`, and `source` fields, reuse the ELF reader (see `src/geo_profiler_elf.c`) or an external tool to build a line table and lookup PCs.  
   * When the ELF data is unavailable, fall back to emitting PC-level objects; the JSON schema accepts entries with just `pc`, `samples`, and `cycles` (see `docs/profile-json.md`, “Consumer guidance”).

4. **Aggregate into per-file-line entries (the canonical aggregation)**  
   * The dump is sorted around `file:line`, not raw addresses, so group every PC whose DWARF row shares the same file index and line number.  
   * Sum their `cycles` and `samples` so the JSON reports line-level totals, and choose the PC with the highest cycle count as the representative `address` string (formatted as `"0xHHHHHH"`).  
   * Use the best-effort source text for that line (the same file resolution logic used by `geo_profiler_dump()` can populate `source`).

5. **Serialize the JSON array**  
   * Emit one object per line entry with at least the required fields (`file`, `line`, `cycles`, `count`, `address`, `source`).  
   * The `cycles`/`count` values come directly from your grouped totals; `count` corresponds to the summed `samples`.  
   * Write the array to `GEO_PROF_JSON` or `GEO_PROF_TXT`; the core currently prefers `GEO_PROF_JSON` and falls back to `GEO_PROF_TXT` when the former isn’t set.

6. **Reset or reuse as needed**  
   * After writing the file you can clear the accumulators to start a new session or keep them for cumulative profiling.  
   * Streaming packets can also be forwarded to the on-disk JSON dump while you continue aggregating; the stream is already safe to read in parallel because it only reports deltas.

Because the stream already observes the same PCs the dump method does, the aggregator only needs to reproduce the lookup/aggregation logic from `geo_profiler_dump()` rather than re-sampling the emulator state. This approach keeps the stream feed compatible with the on-disk JSON format while still allowing light, frame-by-frame reporting.
