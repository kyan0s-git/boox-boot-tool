# boox-boot-tool

Rooting, backup and hardening for Onyx Boox e-ink tablets, built around one
constraint: **do not brick the device.**

Primary target is the **BOOX Go Color 7 (Gen II)**. Other Boox models are
supported through a declarative profile format.

> This voids your warranty. The `unlock-bootloader` command can hard-brick a
> device in a way that needs an EDL cable or mainboard test points to recover.
> Nothing else here goes near the boot chain, and root does not require it.

## Why this is not a normal rooting tool

On this hardware the usual route does not exist:

- **Fastboot is broken.** `fastboot flash` answers `unknown command` on firmware
  past roughly 3.52, and `fastboot oem unlock` reports `OKAY` while leaving the
  bootloader locked.
- **EDL is the write channel.** Qualcomm Emergency Download mode (USB 9008)
  speaks Sahara, then Firehose, and writes raw partitions beneath the bootloader
  entirely. That is why every working community guide uses it.
- **The device is A/B.** Writing the slot the device is not booting from does
  nothing at all, which has confused people into writing both and losing their
  fallback.

Two documented ways people have bricked these tablets:

1. writing a boot image taken from a **different Boox model**, and
2. **slot confusion** — writing the inactive slot, seeing no effect, then
   overwriting the good slot too.

Both are designed against directly. See [SAFETY.md](SAFETY.md).

## Install

```bash
pip install -e ".[firmware]"

# The EDL implementation is a separate project, driven as a subprocess:
pip install git+https://github.com/bkerler/edl
```

You also need Android `platform-tools` on PATH. On Windows, `edl.exe` from
temblast.com works too (`--backend temblast`), and the device needs the QDLoader
driver, installed with Zadig.

## Use

```bash
boox wizard                 # guided, runs the steps in the order that is safe
```

Or step by step:

```bash
boox doctor                 # what can the tool reach? is the journal clean?
boox loader fetch           # download an EDL loader for this model
boox firmware fetch         # official firmware, as an independent reference
boox backup                 # full verified backup — required before any write
boox root prepare           # stage the stock image for Magisk to patch
#   ... patch it in the Magisk app on the tablet ...
boox root apply             # verify hard, then write the active slot
```

Then, once rooted:

```bash
boox debloat --tier safe --tier aggressive
boox harden --all
```

Every command takes `--dry-run`, which prints the exact EDL invocations and all
verification results without writing anything.

If something goes wrong:

```bash
boox rescue diagnose
boox rescue playbook
boox rescue restore --partition boot_a
```

## What each part does

| Command | |
|---|---|
| `doctor` | environment, device, journal; `--preflight` also tests the EDL read/write path |
| `backup` | reads every partition twice, hashes it, writes a manifest binding it to this device |
| `firmware` | Onyx `update.upx` → AES-CFB decrypt → `payload.bin` → stock images |
| `verify` | run the verifier against any image, without a device attached |
| `root` | choose the ramdisk-bearing partition, stage it, verify what Magisk returns, write it |
| `unroot` | put the stock image back, from the backup or from stock firmware |
| `rescue` | diagnose which tier of trouble the device is in, and restore |
| `debloat` | `pm uninstall --user 0` only — reversible, no root needed, protected list enforced |
| `harden` | NTP and captive-portal endpoints, a systemless hosts module, firewall guidance |
| `unlock-bootloader` | writes a foreign ABL. Expert-gated. Not needed for anything else. |

## Debloating and hardening

Debloating never deletes anything. It uses `pm uninstall --user 0`, which hides
a package from the current user and is undone with
`boox debloat --restore <package>`. A protected list is enforced in code —
on these devices the Onyx launcher is also the settings UI, so removing it
leaves a tablet you cannot configure.

Hardening has three layers:

- **settings** — moves NTP and connectivity checks off Chinese endpoints. No root.
- **hosts** — a systemless Magisk module null-routing Onyx's telemetry and cloud
  domains. Needs root, writes no partition, uninstalling the module undoes it.
- **firewall** — yours to configure. A hosts file cannot block `119.23.143.188`,
  which Onyx reaches directly by IP over plain HTTP and which receives the
  device's MAC address. Use AFWall+ or NetGuard, and add an explicit deny.

Blocking these disables Boox account sync, the app store and OTA checks. That is
the intended effect.

## Adding a device

Copy `boox/profiles/_template.toml`, fill it in, and leave `verified = false`
until you have run the hardware checklist in SAFETY.md on that model. Writes are
authorised by preflight measuring the device in front of it, not by that flag —
but the flag is how you tell the next person whether anyone has actually tried
this.

## Credits

This stands on work by others: [bkerler/edl](https://github.com/bkerler/edl) and
its loader collection, Renate's [EDL utility](https://www.temblast.com/edl.htm),
[Hagb/decryptBooxUpdateUpx](https://github.com/Hagb/decryptBooxUpdateUpx) for the
firmware decryption scheme and key database,
[jdkruzr](https://github.com/jdkruzr/BooxPalma2RootGuide) and carlosonunez for
the procedures this automates,
[dynamicfire/boox-ams-fix](https://github.com/dynamicfire/boox-ams-fix), and
[JordanEJ/Onyx-Boox-Blocklist](https://github.com/JordanEJ/Onyx-Boox-Blocklist).

The key database is **not** redistributed here — `boox firmware keys --fetch`
downloads it from upstream.

## Licence

GPLv3.
