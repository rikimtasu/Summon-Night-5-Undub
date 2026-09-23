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
| Output | `Summon Night 5 (USA) Undub.iso` (SHA-256 `0b3bee61…d3e`, 1,369,059,328 B) |
| Patch | `Summon Night 5 (USA) Undub.xdelta` (SHA-256 `52bcc89f…f9fa`, 466,051,109 B) |
| Tool | xdelta3 3.0.11, encoded with `-B 1073741824 -W 16777216`, decode-verified |

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

- **Only the prologue context (`c10=38381`) is mapped.** A multiset proof over
  every JP voice site in that context shows it is complete:
  392 const = 68 retained by USA + 323 in our table + 1 deliberate drop (vid 122);
  15 f2 all mapped; 505 pair-id sites untouched (they play natively).
- **Later chapters are not covered.** Story scripts are per-chapter blocks with
  chapter-partitioned voice-id ranges: the prologue uses ids `15..435`, while the
  chapter-1 block uses `2000..2664` (657 const sites) — zero overlap. Those
  lines stay silent until their chapter is added to the table.
- Extending is mechanical: entries are `(context, text-offset, voice-id)`
  triples and the walker already matches the live context. `build_v4.py`
  currently hardcodes the prologue context and needs a per-entry context
  column. The audit tooling for this (`work/scan_all_blocks.py`,
  `work/classify_blocks.py`, `work/voice_func_resolve.py`) is ready; it needs
  paired PPSSPP save states (USA + JP) at matching scenes, because 02.DAT holds
  the script entries compressed.

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
