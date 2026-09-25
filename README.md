# Summon Night 5 (USA) Undub

Restores Japanese story voices (and the JP opening movie) to the USA release,
keeping English text. Verified in PPSSPP.

> **Scope: prologue + chapter 1.** The voice table is keyed per script
> context: the prologue (`c10=38381`) is fully audited (339 rows, zero gaps), chapter 1
> (`c10=50098`) needed exactly one row, and chapters 2+ have not been captured
> yet. See "Known limitations".

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
  (`build_v6fix.py`): **338 prologue triggers** in 11 chunks — 339 table
  entries shipped, including the one chapter-1 row.
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
| Output | `Summon Night 5 (USA) Undub.iso` (SHA-256 `e88acbfb…b8309d1`, 1,369,059,328 B; retreat-exchange fix rebuild 2026-09-25) |
| Patch | `Summon Night 5 (USA) Undub.xdelta` (SHA-256 `271d9697…ef459b`, 466,098,445 B, decode-verified 2026-09-25) |
| Tool | the current patch was encoded with xdelta3 3.2.0 (`work/bin/`, gitignored) using `-e -f -B 1073741824 -W 16777216`; any xdelta3 decodes it |

Apply (this xdelta3 build needs the `-d` flag form and `-s` for the source —
see `work/RE_notes.md`):

```
xdelta3 -d -f -s "Summon Night 5 (USA).iso" "Summon Night 5 (USA) Undub.xdelta" out.iso
```

## What the patch changes (full-tree check: `work/review_xdelta_patch.py`; per-directory detail: `work/release_manifest.py`)

| Path | Change |
|---|---|
| `/PSP_GAME/SYSDIR/EBOOT.BIN` | same size (3,018,032 B), content replaced by the patched ELF (clamp NOPed, hooks + voice table) |
| `/PSP_GAME/USRDIR/SV00-17.DAT` | **added** — 18 JP voice archives (~450 MB total). The USA release ships *no* voice archives at all; this is what makes the restored triggers audible |
| `/PSP_GAME/USRDIR/04.DAT` | JP opening movie (14,786,560 → 14,790,656 B) |
| everything else | byte-identical — the other 19 of 21 stock files are unchanged |

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

## Rebuild (DANGER: mutates the live ISO)

**Every script below overwrites the live `Summon Night 5 (USA) Undub.iso`
in place.** `build_v4.py` / `build_v5.py` regenerate the whole ISO from the
stock USA ISO *before* any guard runs — the JP-opening guard only fires at the
end of `v2.patch_eboot_extent()` (`build_undub_v2.py`), after both writes.
Never run them against the live ISO as a test; see the DANGER section in
`work/RE_notes.md` for the recorded accident (2026-09-24) and recovery.

```
python work/build_v4.py    # DESTRUCTIVE full ISO rebuild: SV swap + EBOOT patch (clamp + hook)
python work/build_v5.py    # DESTRUCTIVE full ISO rebuild: + JP opening movie
python work/build_v6fix.py # DESTRUCTIVE EBOOT-extent-only update (after editing v3_entries.txt)
```

Rules for any future rebuild:

1. Stage a copy, verify it, then install — none of these scripts stage first;
   the JP-opening guard only runs *after* the overwrite (only
   `apply_jp_opening.py` stages, verifies, then installs).
2. Any future ISO rebuild is a **single deliberate act**: rebuild once,
   re-encode the xdelta from the stock USA ISO with the same options
   (`-e -f -B 1073741824 -W 16777216`, source via `-s`), playtest, then run
   the verifiers:
   `python work/verify_shipped_patch.py` (ISO mode) and
   `python work/review_xdelta_patch.py` (both take no arguments; run from
   the repo root).
3. `work/EBOOT_USA_patched.bin` and the EBOOT inside the shipped ISO are
   byte-identical since the 2026-09-25 voice-table fix rebuild (re-established
   with a fresh single `make_eboot()` run at the retreat-exchange rebuild;
   current pair `fca047db…`, previous identical pair `08f03e9c…`). They
   HAD diverged before that (`c403283f…` vs `3b9c48ce…`, cause unrecorded)
   even though both passed the static verifier — it checks mechanism, not
   file identity. Take the EBOOT from the shipped ISO, or rebuild from
   scratch and re-verify end to end.

## Repo contents

- `work/*.py` — build + analysis + audit tooling
- `work/RE_notes.md` — reverse-engineering findings
- `work/v3_entries.txt` — audited voice-id -> text-offset table (+ `.pre_round6`)
- `work/prologue_audit_full.txt`, `work/align_dump.txt` — mapping audit artifacts
- `work/usa_loader_diff.pkl` — loader-fixup address set (build input)
