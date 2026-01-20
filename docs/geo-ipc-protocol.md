# Geo IPC Protocol

This document describes the lightweight JSON-over-TCP protocol exposed by `geo_ipc` at `127.0.0.1:9000`. The listener accepts one client at a time, keeps the socket non-blocking, and treats each newline-delimited line as a single JSON command. Each command enqueues a single action, the emulator thread applies it once per frame, and the remote controller receives exactly one JSON result in response.

## Connection lifecycle

1. **Connect** – open a TCP connection to `127.0.0.1` on port `GEO_IPC_PORT_DEFAULT` (9000). The server expects loopback-only clients.
2. **Send commands** – transmit ASCII JSON objects terminated by `\n`. The server parses each line independently.
3. **Read command responses** – after the emulator applies a command, it sends one JSON acknowledgement describing the result, then waits for the next command.
4. **Disconnect** – close the socket when finished; the server gracefully handles client disconnects and accepts a new client thereafter.

## Command format

Each command is a single JSON object terminated by `\n`. The supported commands are:

```json
{"cmd":"profiler_start","stream":false}
{"cmd":"profiler_start"}
{"cmd":"profiler_stop"}
{"cmd":"profiler_state"}
```

The parser is simplistic (`strstr` based), so commands must match the lowercase strings exactly. Unknown commands are silently ignored.

The server replies asynchronously by applying the command in the emulator thread-side `geo_ipc_apply_pending` call and immediately writing an acknowledgement back to the socket.

## Command responses

Each command produces exactly one JSON response once the emulator thread has applied the queued action. Responses are newline-terminated and look like:

```json
{"cmd":"profiler_start","result":"enabled"}
{"cmd":"profiler_stop","result":"disabled"}
{"cmd":"profiler_state","result":"enabled"}
```

Fields:

- `cmd`: echoes the incoming command name for easy matching.
- `result`: a short status string describing what happened (`"enabled"`/`"disabled"` for profiler commands and queries, `"streaming"`/`"stopped"` when toggling the stream).

There are no other command responses, so the socket stays idle between commands unless the controller issues another action. Only profiler start/stop/state/stream toggles exist in this API.

## Streaming frames

When streaming is active the emulator sends one extra message per frame containing the new hits recorded since the previous frame. Streaming messages look like:

```json
{"stream":"profiler","enabled":"enabled","hits":[{"pc":"0x00A3F2","samples":12,"cycles":4567},{"pc":"0x00B1C0","samples":2,"cycles":128},...]}
```

Fields:

- `stream`: always `"profiler"` for these periodic updates.
- `enabled`: current profiler status (`"enabled"` or `"disabled"`).
- `hits`: an array (up to ~128 entries) of the PCs touched since the last frame; each entry includes the 24-bit PC, the number of samples attributed to it, and the accumulated cycles.

Streaming frames are emitted right after each `geo_ipc_apply_pending` call when the most recent `profiler_start` included streaming (the default). Sending `{"cmd":"profiler_start","stream":false}` disables the per-frame messages even while the profiler is running. Every streaming message is newline-terminated, and the next command may arrive at any time. The emulator does not aggregate or sort these hits—the client is expected to collate and summarize them per frame.

## Debug text events

The emulator exposes a simple debug console hook: whenever the emulated 68K writes a byte to the special `GEO_DBG_TEXT_ADDR` register (where the byte is normally tossed into ROM), the same byte is printed to stdout *and* broadcast as a JSON event to connected IPC clients. Each event looks like:

```json
{"event":"debug","byte":65,"char":"A"}
```

Fields:

- `event`: always `"debug"` for these notifications.
- `byte`: numeric value written to `GEO_DBG_TEXT_ADDR` (0‑255).
- `char`: a JSON string representation of the byte (control characters are escaped with `\u00XX` so the payload remains valid JSON).

Messages are newline-terminated and emitted immediately as the byte is written—clients do not need to enable any profiler streaming options to receive them.

## Implementation guidance

- Always read lines until a newline terminator; partial reads should be buffered until completion.
- Ignore or log JSON you do not understand. The parser is intentionally simple (`strstr`-based), so commands must match the exact string (double quotes, lowercase names).
- Commands are idempotent: starting an already running profiler simply resets counters and leaves profiling enabled, and stopping an already stopped profiler turns it off.
- There is no authentication, so keep access limited to local systems (the port is already bound to `INADDR_LOOPBACK`).

## Future extensions

Add new commands by naming the `cmd` string and handling it in `geo_ipc_apply_pending`. The port and format are fixed but the parser and message queue can accommodate additional boolean or numeric controls by enqueuing new `cmd_kind_t` values.
