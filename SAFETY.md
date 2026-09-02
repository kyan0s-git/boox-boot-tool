# Safety design

This document explains what stops this tool from bricking your tablet, and what
you have to do yourself. Read the last section before your first write.

## The threat model

Two failure modes are documented in the community and both are recoverable only
with an EDL cable or mainboard test points:

1. **Foreign image.** Someone pulls a boot image, patches it, and writes an image
   that came from a *different Boox model* to `boot_a`. The device stops reaching
   fastboot and recovery.
2. **Slot confusion.** The device is A/B. Writing the inactive slot appears to do
   nothing, so people write the other slot too — and lose the good copy that was
   their fallback.

Everything below is arranged around those two, plus the ordinary failures: a bad
cable, a truncated file, a crash halfway through.

## 1. Preflight — prove the escape hatch before you need it

If a write goes wrong, the only way out is to write the partition again from a
backup over EDL. So before taking any risk, the tool confirms — on this device,
with this cable, in this session — that the recovery path works.

No write is permitted until all of these pass:

| Check | Why |
|---|---|
| device model matches the profile | catches the wrong profile early |
| Sahara handshake completes | records HWID / JTAG / PBL hash, which bind the backup to this unit |
| loader accepted, Firehose alive | a loader "matching by name" proves nothing; only a handshake does |
| partition table readable, names as expected | a misread GPT means every offset after it is wrong |
| journal clean | a previous run may have left a partition half-written |
| **read round-trip** — one partition read twice, hashes compared | a flaky USB link corrupts transfers; finding out while reading is free |
| **write round-trip** — `misc` rewritten with its own bytes, then re-read | proves the write path works while the device is still healthy. Semantically a no-op |

Only then is a **write token** issued. It is bound to the device's identity,
expires after an hour, and carries whether a backup and stock firmware exist.

## 2. Two independent restore sources

A write requires both:

- **A verified device backup.** Every partition read *twice* and compared, then
  hashed into a `manifest.json` that records the device identity, the partition
  table, and the active slot. `boox backup` refuses to finish if the images do
  not match their own manifest.
- **Decrypted official firmware.** `update.upx` → AES-CFB → `payload.bin` →
  stock images, each checked against the payload manifest's own SHA-256.

They cover different things. Firmware gives a reference that did not come from
your possibly-already-broken tablet. The backup covers the partitions firmware
never contains: `devinfo`, `frp`, `persist`, `modemst1/2`, `fsg`.

If you accept having only the backup, `--allow-missing-golden` says so
explicitly. It is not the default.

## 3. The verifier

Nothing is written unless the image passes every applicable check:

- **not empty, not all zeroes**
- **fits the partition**, per the real GPT
- **magic matches the target class** — `ANDROID!` for boot/init_boot/recovery,
  `VNDRBOOT` for vendor_boot, `AVB0` for vbmeta, ELF for abl/xbl
- **header parses and is internally consistent** — sizes and offsets within the
  file, plausible page size, supported header version
- **provenance** — the load-bearing one, below
- **root patch actually present**, when rooting
- **ramdisk differs from stock**, when rooting — catches "forgot to patch it"
- **device binding** — the backup's identity matches the device in front of us
- **slot explicit** — a slotted base name with no resolved slot is an error, never
  a guess

### Provenance

> The candidate must be demonstrably derived from an image we already trust for
> *this* device — either your own backup of that partition, or the stock firmware.

For an image with a kernel this is exact. Magisk rewrites the ramdisk and leaves
the kernel alone, so the kernel must be **byte-identical**. A different kernel
means a different build or a different device. This single check is what would
have prevented failure mode 1.

`init_boot` is ramdisk-only and has no kernel to compare, so provenance there
falls back to matching the header fingerprint — which encodes the Android version
and security patch level of the build — and requiring at least 60% of the
reference ramdisk's files to still be present.

## 4. Blast-radius tiers

Every partition is classified, and **unrecognised partitions are treated as
CATASTROPHIC**. Fail closed: an unknown partition could be anything.

| Tier | Partitions | Gate |
|---|---|---|
| `SAFE` | boot, init_boot, recovery, vendor_boot, dtbo | standard |
| `DANGEROUS` | vbmeta, misc, frp, devinfo, userdata, super… | extra confirmation, fresh backup |
| `CATASTROPHIC` | abl, xbl, tz, hyp, modem, persist, GPT, *anything unknown* | expert gate: `--i-understand`, a typed phrase, a same-session backup covering every partition written, stock firmware present, and a full preflight pass |

A profile may raise a partition's tier. It can never lower one.

## 5. Journal and read-back

Before every write, an intent record — partition, source file, its SHA-256, and
where the backup lives — is appended to `journal.jsonl` and **fsynced**. After
every write the partition is **read back and compared**. No exceptions.

On mismatch the backup is restored immediately, before control returns. If that
restore also fails to verify, the tool stops and prints the exact `boox rescue`
command, because that is the one state where continuing makes things worse.

If the process dies mid-write, `boox doctor` and `boox rescue diagnose` read the
journal and name the partition that was in flight and where its backup is.

## 6. Slot strategy

**The active slot only, by default.** The inactive slot stays stock and is a live
fallback. `--both-slots` exists, and warns that it removes that fallback.

The active slot comes from `ro.boot.slot_suffix` over adb. If it cannot be
determined and the device is A/B, the tool stops rather than guessing.

## 7. Dry run and the simulated device

`--dry-run` prints the exact `edl` invocations and every verification result
without writing. The test suite runs the entire flow against a file-backed mock
device with injected faults — a flaky cable, a write that silently lands wrong,
a crash mid-write, a persistently corrupt link — so those paths are exercised
without hardware.

---

# Recovery

`boox rescue playbook` prints this. Work down; stop at the first tier that
responds.

- **T0 — boots, adb works.** `boox rescue restore --partition boot_a`
- **T1 — no Android, but EDL responds.** Fully recoverable; this is the state the
  tool is designed around. Get into EDL (`edl reset --resetmode=edl` from
  fastboot, or the key combo), then restore.
- **T2 — nothing over normal USB.** Use an **EDL ("deep flash") cable**, which
  shorts D+ to force the boot ROM into 9008 regardless of software state.
- **T3 — still nothing.** Mainboard EDL test points, which means opening the
  device. Look up the locations for your model first.
- **No cables needed:** Onyx's recovery can reinstall firmware from a microSD
  card, which this model has a slot for. Costs root and possibly your data, but
  needs no tools.

**Buy an EDL cable before you start, not after.** They are inexpensive, and the
scenario where you want one is the scenario where you cannot order one and wait.

---

# Hardware checklist

**Nobody has run this against a physical Go Color 7 Gen II yet.** The profile
ships `verified = false` for exactly that reason. Preflight measures your actual
device rather than trusting the profile, so the safety gates hold either way —
but the steps below are how you establish that the profile itself is right, in
an order where each step is recoverable from the one before.

Do them in order. Stop at the first thing that surprises you.

1. **`boox doctor`** — no device writes. Confirm the model is detected and the
   profile matches.
2. **`boox loader fetch`, then `boox doctor --preflight --read-only`** — proves
   the loader works and reading is stable. Still no writes.
3. **`boox firmware fetch`** — no device involvement at all. Confirm the images
   extract and hash correctly.
4. **`boox backup`** — reads only. Then check `manifest.json`: does the partition
   list look like a real device, are the sizes plausible, is the HWID recorded?
5. **`boox doctor --preflight`** — the first write, and it is `misc` rewritten
   with its own bytes. If this fails, stop: it means writes are not landing, and
   you have learned that without risking anything.
6. **Restore an unmodified partition** — `boox rescue restore --partition boot_a`
   from the backup you just took. This writes the same bytes back and proves the
   whole recovery path on real hardware. **Do not skip this.** It is the single
   most valuable step in the list.
7. **`boox root prepare` / `boox root apply`** — the real thing.
8. **`boox unroot`** — confirm you can get back to stock.
9. **`boox root prepare` / `boox root apply`** again — confirm it is repeatable.

Once all of that passes, set `verified = true` in the profile and record the HWID
preflight reported in `expected_hwids`, so the next person gets a mismatch
warning if their device differs.

## Firmware updates once rooted

- **Full OTAs** (over ~1 GB) install fine. They remove root; re-root afterwards.
- **Incremental OTAs** (a few hundred MB) refuse to install on a rooted device.
  Restore stock with `boox unroot` first. Do not hand-write old boot images to
  get around it — that is how at least one Go 10.3 got soft-bricked.
