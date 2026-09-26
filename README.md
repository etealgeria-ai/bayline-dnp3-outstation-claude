# Bayline DNP3 outstation simulator (lab use)

A DNP3/TCP outstation for testing DNP3 masters, including Secure Authentication
v5 (IEEE 1815-2012). **For lab use only.** It prints its update key to the
console and allows SAv2 or authentication off, on purpose, so masters can be
tested against those configurations.

```powershell
py -3.14 -m pip install -r requirements.txt
py -3.14 outstation.py                 # window
py -3.14 outstation.py --headless      # console only
py -3.14 -m bayline.selfcheck          # built-in protocol and feature tests
```

Defaults: TCP port 20000, outstation address 4, master address 100, SAv5 user 1.
The update key is loaded from `bayline-update-key.hex` (created with owner-only
permissions on first run) and printed at start-up so you can load it into the
master. A key file that is not a valid 32-octet hex key is an error; it is never
overwritten.

## Point database

```powershell
py -3.14 outstation.py --dump-points my-rtu.json      # start from the built-in database
py -3.14 outstation.py --points examples/minimal-rtu.json
```

Each point has `kind` (bi, bo, ai, ao, ctr), `index`, and optionally `name`,
`value`, `units`, `class` (0-3), `deadband`, `static_var`, `event_var`,
`feedback` (bo → bi index that follows it), `op_counter` (bo → counter index),
and `low` / `high` for analog outputs (out-of-range commands return status 12).
The file also sets `outstation`, `master`, `event_max` and `simulate`.
`--outstation` and `--master` override the file. The simulated analog movement
only suits the built-in database, so it is off for loaded files unless
`"simulate": true`.

## Fault injection

Faults act on outgoing link frames at the TCP layer, so the outstation's own
protocol state stays correct, as on a real noisy channel.

| Option | Effect |
|---|---|
| `--drop PCT` | Outgoing frames silently lost |
| `--corrupt PCT` | One CRC bit flipped; the master must reject the frame |
| `--duplicate PCT` | Frame sent twice |
| `--delay MS`, `--jitter MS` | Extra latency before each reply |
| `--seed N` | Repeat exactly the same fault sequence |
| `--challenge-reads` | SAv5: challenge Read requests as well |

In the window, the **Lab** tab changes all of these live, adds **Silent** (dead
RTU), **Reject the next N valid authentications** (the master sees error 1 and
must recover), and **Expire session keys now** (the master must rekey).

## Wire capture

`--capture run1.jsonl` appends every frame to a JSON Lines file: `time` (UTC),
`dir` (`rx`, `tx`, `note`), `peer`, `hex`, `summary`, `ok`, and `fault`
(`corrupt`, `duplicate`, `dropped`, `silent`) when a frame was altered or
withheld. Dropped and silent frames are recorded but were not sent, so the
capture shows what the master should have received.

## Network

`--host 127.0.0.1` keeps the simulator on the local PC. On a shared network use
`--allow-ip` for the master's address, since anyone who can connect can operate
the simulated equipment.

## Limits

This outstation has not been through DNP Users Group conformance testing. When a
master fails against it, confirm the result against a reference implementation
before concluding the master is at fault. Single association, single SAv5 user,
single transport segment per request; no file transfer; remote update-key change
is off and not implemented to the standard.
