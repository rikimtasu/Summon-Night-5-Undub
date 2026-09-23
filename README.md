# Summon Night 5 (USA) Undub

Restores Japanese story voices (and the JP opening movie) to the USA release,
keeping English text. Verified in PPSSPP.

> **Scope: the prologue chapter only.** The voice table is keyed per script
> context, and the audit below shows later chapters use a *different,
> non-overlapping* voice-id range that the current table does not cover. See
> "Known limitations".

## Method (summary)

- USA stripped story voices two ways: (1) engine clamp in the slot-65 voice
  handler forces every voice id `< 0x9088` to idle, (2) 339 voice triggers
  deleted from the prologue event script.
- v2: NOP the 3-instruction clamp in `EBOOT.BIN`.
- v4: hook the text-display handler with a baked
  `(context, text-line -> voice-id)` table (split across loader-verified memory
  gaps); the CALL195 delta is benign text reflow, not missing triggers.
- Voice line mapping audited bilingually (JP owning line vs USA attached line).
  Round 6 corrected the systematic one-line offset, cross-version line-order
  swaps, localizer-inserted lines, and wrongly dropped entries
  (`build_v6fix.py`): **338 triggers** in 11 chunks.
- Backlog: voice triggers now also fill the backlog replay slot, so restored
  voices replay with X and close with Circle.
- v5: JP `SV00-17.DAT` (voice archives) + JP `04.DAT` (opening movie) swapped
  into the USA ISO.
- Distributable: xdelta patch USA ISO -> undub ISO (built locally, not tracked).

Details: `work/RE_notes.md`. Mapping table: `work/v3_entries.txt`.

## Patch

| | |
|---|---|
| Input | `Summon Night 5 (USA).iso` (SHA-256 `64977f15…f98c`, 897,253,376 B) |
| Output | `Summon Night 5 (USA) Undub.iso` (SHA-256 `292e69eb…a10e`, 1,369,059,328 B) |
| Patch | `Summon Night 5 (USA) Undub.xdelta` (SHA-256 `dbfcc426…f28ae`, 466,051,116 B, decode-verified) |
| Tool | xdelta3 3.0.11, encoded with `-B 1073741824 -W 16777216` |

```
xdelta3 -d "Summon Night 5 (USA).iso" "Summon Night 5 (USA) Undub.xdelta" out.iso
```

## What the patch changes (verified by `work/release_manifest.py`)

| Path | Change |
|---|---|
| `/PSP_GAME/SYSDIR/EBOOT.BIN` | same size (3,018,032 B), content replaced by the patched ELF (clamp NOPed, hooks + voice table) |
| `/PSP_GAME/USRDIR/SV00-17.DAT` | **added** — 18 JP voice archives (~450 MB total). The USA release ships *no* voice archives at all; this is what makes the restored triggers audible |
| `/PSP_GAME/USRDIR/04.DAT` | JP opening movie (14,786,560 → 14,790,656 B) |
| everything else | byte-identical (10 USRDIR + 2 SYSDIR files unchanged) |

## Known limitations (audited 2026-09-23)

Coverage is per script context, and the amount of table needed varies by
chapter. Measured so far:

| context | chapter | JP const | USA const | deleted | table rows |
|---|---|---|---|---|---|
| `c10=38381` | prologue | 392 | 68 | 324 (+15 f2) | 338 |
| `c10=50098` | chapter 1 | 657 | 656 | **1** (vid 2287) | 1 |

- The **prologue is provably complete**: a multiset proof over every JP voice
  site gives 392 const = 68 retained by USA + 323 mapped + 1 deliberate drop
  (vid 122); 15 f2 all mapped; 505 pair-id sites untouched (they play natively).
- **Chapter 1 needed only one row** — the USA build retained nearly all of its
  const triggers, so they play natively once the clamp is NOPed. The single
  deleted trigger (vid 2287) is restored via `work/extra_entries.txt`.
- Chapters after chapter 1 have not been captured yet. `op52` call targets are
  per-block function ids, so each chapter must be diffed on its own; the audit
  tooling (`work/pair_report.py`, `work/pair_diff_voices.py`,
  `work/find_missing_site_target.py`) is ready and needs only paired PPSSPP
  save-states (USA + JP) at a matching scene.
- Extending is mechanical: rows are `(context, text-offset, voice-id)` and the
  walker already matches the live context, so `work/extra_entries.txt` can hold
  any number of chapters.

## Rebuild prerequisites (NOT tracked; provide your own)

- `Summon Night 5 (USA).iso` and `Summon Night 5 (JP).iso`
- `EBOOT_USA_decrypted.bin` / `EBOOT_JP_decrypted.bin` (decrypted EBOOTs)
- `work/JPSV/` (JP `SV00-17.DAT`), `work/JP04.DAT` (JP `04.DAT`)
- Python: `pycdlib`, `capstone`, `zstandard`; xdelta3 binary for patching

## Rebuild

```
python work/build_v4.py    # full ISO: SV swap + EBOOT patch (clamp + hook)
python work/build_v5.py    # + JP opening movie
python work/build_v6fix.py # EBOOT-only table update (after editing v3_entries.txt)
```

`build_v4.make_eboot()` is deterministic: regenerating the patched EBOOT from
the current table reproduces the bytes embedded in the shipped ISO exactly.

## Repo contents

- `work/*.py` — build + analysis + audit tooling
- `work/RE_notes.md` — reverse-engineering findings
- `work/v3_entries.txt` — audited voice-id -> text-offset table (+ `.pre_round6`)
- `work/prologue_audit_full.txt`, `work/align_dump.txt` — mapping audit artifacts
- `work/usa_loader_diff.pkl` — loader-fixup address set (build input)
