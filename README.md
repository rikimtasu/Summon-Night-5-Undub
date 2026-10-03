# Summon Night 5 (USA) Undub

Restores Japanese story voices (and the JP opening movie) to the USA
release, keeping English text. Verified in PPSSPP.

Two audiences, two halves: **For users** is what the patch is and how to
apply it; **For maintainers** is how it is built, verified and rebuilt.

---

# For users

## What you get

| | |
|---|---|
| Voices | JP story voices restored for the **prologue and chapter 1**, on top of the English text |
| Movie | the Japanese opening movie (`04.DAT`) |
| Everything else | untouched - English UI, English script, no other content changed |

## Coverage - read this before you patch

The voice table is keyed per script context, and the amount of table needed
varies by chapter. What ships today:

| context | chapter | JP const | USA const | deleted | table rows | verdict |
|---|---|---|---|---|---|---|
| `c10=38381` | prologue | 392 | 68 | 324 (+15 f2) | **339** | complete |
| `c10=50098` | chapter 1 | 657 | 656 | **1** (vid 2287) | **1** | complete |
| | | | | **total shipped** | **340** | |

- The **prologue is provably complete**: a multiset proof over every JP
  voice site gives 392 const = 68 retained by USA + 323 mapped + 1
  deliberate drop (vid 122); 15 f2 all mapped; 505 pair-id sites untouched
  (they play natively).
- **Chapter 1 needed exactly one row** - the USA build retained nearly all
  of its const triggers, so they play natively once the clamp is NOPed.
  The single deleted trigger (vid 2287) is restored from the table.
- **Chapters after chapter 1 are deferred, not broken.** Three script
  blocks remain unpaired (each needs a USA + JP save state at a matching
  scene before it can be mapped): JP `c10=49220`, USA `c10=41244`, and
  USA `c10=54606` (chapter 2). Extending coverage is mechanical - the
  table format is one row per context. This is a scope decision, recorded
  in [ADR 0001](docs/adr/0001-scope-prologue-chapter-1.md).

## Patch, hashes, tool

| | |
|---|---|
| Input | `Summon Night 5 (USA).iso` (SHA-256 `64977f15…f98c`, 897,253,376 B) |
| Output | `Summon Night 5 (USA) Undub.iso` (SHA-256 `e88acbfb…b8309d1`, 1,369,059,328 B; retreat-exchange fix rebuild 2026-09-25) |
| Patch | `Summon Night 5 (USA) Undub.xdelta` (SHA-256 `271d9697…ef459b`, 466,098,445 B, decode-verified 2026-09-25) |
| Tool | xdelta3 3.2.0, encoded with `-e -f -B 1073741824 -W 16777216`; any xdelta3 decodes it |

The **xdelta is the artifact**; the prebuilt ISO is a convenience for
people who would rather not run xdelta3.

Apply (this xdelta3 build needs the `-d` flag form and `-s` for the
source):

```
xdelta3 -d -f -s "Summon Night 5 (USA).iso" "Summon Night 5 (USA) Undub.xdelta" out.iso
```

## What the patch changes

| path | change |
|---|---|
| `/PSP_GAME/SYSDIR/EBOOT.BIN` | same size (3,018,032 B), content replaced by the patched ELF (voice-id clamp NOPed, text-handler hooks + voice table) |
| `/PSP_GAME/USRDIR/SV00-17.DAT` | **added** - 18 JP voice archives (~450 MB total). The USA release ships *no* voice archives at all; this is what makes the restored triggers audible |
| `/PSP_GAME/USRDIR/04.DAT` | JP opening movie (14,786,560 → 14,790,656 B) |
| everything else | byte-identical - the other 19 of 21 stock files are unchanged |

## Not included (scope)

This patch restores **JP story voices and the JP opening movie, and
nothing else**. Anything further is a new decision with its own
verification - that includes:

- **Japanese-only costume DLC.** Japan got extra character outfits as
  downloadable content (`DLCEXM`/`DLCITM` files). Those were never on
  disc, so there is nothing to unlock: the USA build has no such data, and
  the DLC is keyed to the JP title ID. Not supported here.
- Further chapters of JP voices (deferred, see Coverage above).
- Other JP content swaps (other movie/event archives), gameplay or engine
  changes, and any translation work.

---

# For maintainers

## Repository layout

```
README.md                     this file
docs/adr/                     decision records (created lazily; ADR 0001 = scope)
work/RE_notes.md              authoritative reverse-engineering findings
work/v3_entries.txt           prologue voice table, 339 rows
work/extra_entries.txt        later-chapter rows (currently ch.1: 1 row) -> 340 total
work/v3_entries.txt.pre_round6   pre-round-6 snapshot of the prologue table
work/usa_loader_diff.pkl      loader-fixup address set (build input)
work/voice_bilingual.tsv      census output: 340 bilingual rows, all status=present
work/voice_census_report.txt  census output: per-chapter verdicts + unpaired blocks
```

Tooling, by job:

| script | job |
|---|---|
| `paths.py` | the single place paths are resolved (see Path configuration) |
| `common.py` | shared hashing / RAM-extraction helpers |
| `build_v4.py` | full rebuild: stock USA ISO -> undub ISO (mutating; see below) |
| `build_undub_v2.py` | EBOOT extent patch (clamp NOP + hooks + packed table) |
| `apply_jp_opening.py` | the only script that stages, verifies, then installs the JP opening |
| `verify_shipped_patch.py` | static verifier of the shipped EBOOT (8 check groups) |
| `review_xdelta_patch.py` | full-tree review of what the xdelta changes |
| `release_manifest.py` | per-directory detail of the patch contents |
| `verify_caves.py` | audits the cave generator and all three hooks; prints `ALL PASS` |
| `chapter_voice_census.py` | diffs the deleted voice multiset per chapter, emits the TSV + report |
| `chapter_capture.py` / `chapter_sweep.py` | capture paired USA+JP PPSSPP save states |
| `save_editor.py` | save-state editor with chapter jump |
| `scan_all_blocks.py` | scan story blocks for voices/text (dialect-aware) |
| `disasm_align.py` | authoritative token/op-semantics header for script disassembly |
| `loader_fixups.py` | re-derives a superset of the loader fixups for recovery |

## Sign-off checklist

A build or rebuild is signed off when all of these are true:

1. `python work/verify_shipped_patch.py` → **39/39 GREEN**
2. `python work/verify_shipped_patch.py --xdelta` → **40/40 GREEN**
3. `python work/review_xdelta_patch.py` → **review CURRENT**
4. `python work/verify_caves.py` → **ALL PASS**
5. xdelta **decode-verified** against the stock USA ISO (hash compared)
6. **manual playtest** in PPSSPP: prologue + chapter 1 voices audible, JP
   opening plays - record date + artifact SHA-256: `_date ____________ /
   sha256 ____________`

Run the verifiers from the repo root. **Deliberately excluded from
sign-off:** `python work/chapter_voice_census.py --selftest` fails by
design - its chapter-1 block-pair capture is no longer in the capture set.
That is a capture-set gap, not patch integrity (both shipped chapters
report `verdict: COMPLETE`, gaps 0, all 340 rows `status: present`). Do
not read its failure as a regression.

## Coverage workflow for a new chapter

Each chapter must be diffed on its own - `op52` call targets are per-block
function ids. Keep PPSSPP's `EncryptSave` off so the save states stay
readable by the tooling.

1. Capture a **paired** PPSSPP save state per chapter, USA + JP, at a
   matching scene: `work/chapter_capture.py` / `work/chapter_sweep.py`
   (needs `SN5_PPSSPP_MEMSTICK`; states only under a canonical
   `PPSSPP_STATE` dir are trusted).
2. `python work/chapter_voice_census.py --states <dir>` → diffs the
   deleted voice multiset, emits `work/voice_bilingual.tsv` +
   `work/voice_census_report.txt`, and reports any block still unpaired.
3. Add rows to `work/extra_entries.txt` as `c10 key vid` (it accepts any
   number of chapters) and rebuild.

## Rebuilding (DANGER: mutates the live ISO)

**Every build script below overwrites the live `Summon Night 5 (USA)
Undub.iso` in place.** `build_v4.py` regenerates the whole ISO from the
stock USA ISO *before* any guard runs - the JP-opening guard only fires at
the end of `v2.patch_eboot_extent()`, after both writes. Never run them
against the live ISO as a test; see the DANGER section in `work/RE_notes.md`
for the recorded accident (2026-09-24) and recovery.

```
# full rebuild (SV swap + EBOOT patch): stock USA ISO -> undub ISO, no JP opening
python work/build_v4.py
# then restore the JP opening (the one script that stages, verifies, installs)
python work/apply_jp_opening.py

# EBOOT-only update after editing work/v3_entries.txt / work/extra_entries.txt:
python -c "import sys; sys.path.insert(0,'work'); import build_v4 as b; b.make_eboot()"
python -c "import sys; sys.path.insert(0,'work'); import build_undub_v2 as v2; v2.patch_eboot_extent()"
```

Never run `build_v4.main()` / `rebuild_audited.main()`; call
`make_eboot()` or the monkeypatched `patch_eboot_extent()` on a staged
copy only.

Prerequisites (NOT tracked; provide your own): `Summon Night 5 (USA).iso`
and `Summon Night 5 (JP).iso`, `EBOOT_USA_decrypted.bin` /
`EBOOT_JP_decrypted.bin`, `work/JPSV/` (JP `SV00-17.DAT`), `work/JP04.DAT`
(JP `04.DAT`), Python `pycdlib` + `capstone` + `zstandard`, and an
xdelta3 binary. Missing `work/extra_entries.txt` or `work/usa_loader_diff.pkl`
aborts the build with a message (both are tracked;
`git checkout <rev>^ -- work/<file>` restores them).

Rules for any future rebuild:

1. Stage a copy, verify it, then install - none of the scripts stage first;
   only `apply_jp_opening.py` stages, verifies, then installs.
2. Any ISO rebuild is a **single deliberate act**: rebuild once, re-encode
   the xdelta from the stock USA ISO with the same options (`-e -f -B
   1073741824 -W 16777216`, source via `-s`), playtest, update the hash
   table, then run the sign-off checklist.
3. `work/EBOOT_USA_patched.bin` and the EBOOT inside the shipped ISO have
   been byte-identical since the 2026-09-25 voice-table fix rebuild
   (`fca047db…`; the previous identical pair was `08f03e9c…`). They *had*
   diverged before that (`c403283f…` vs `3b9c48ce…`, cause unrecorded)
   while both still passed the static verifier - it checks mechanism, not
   file identity. Take the EBOOT from the shipped ISO, or rebuild from
   scratch and re-verify end to end.

## Path configuration

Every script resolves paths through `work/paths.py` - nothing is
hard-coded to a maintainer's disk:

| variable | meaning | default |
|---|---|---|
| `SN5_ROOT` | directory holding the ISOs, decrypted EBOOTs, `work/JPSV/`, `work/JP04.DAT` | this checkout |
| `SN5_JPSV_DIR` | JP `SV00-17.DAT` directory | `<root>/work/JPSV/PSP_GAME/USRDIR` |
| `SN5_PPSSPP_MEMSTICK` | PPSSPP memstick dir (capture/sweep/save-editor only) | *unset → those tools refuse to run* |
| `SN5_PPSSPP_EXE` | emulator binary | `PPSSPPWindows64.exe` next to the memstick |

The tracked model files are read from `<root>/work/`, so a full checkout
that also holds the ISOs needs no configuration at all. To run tracked code
from a clean clone against artifacts kept elsewhere:

```
set SN5_ROOT=D:\path\to\artifacts
python work\verify_shipped_patch.py
```

(`--root DIR` on `verify_shipped_patch.py` / `review_xdelta_patch.py` does
the same thing for a single run.)

## Pruned history

`pair_report.py`, `pair_diff_voices.py`, `find_missing_site_target.py`,
`build_v5.py` and `build_v6fix.py` were pruned from the repo; all are
recoverable with `git log --diff-filter=D -- work/` and
`git checkout <rev>^ -- <path>`.

## Where the knowledge lives

- `work/RE_notes.md` - the authoritative RE record: VM opcode semantics,
  native handlers, script block format, the voice-table mechanism, and a
  dated **Corrections 2026-09-26** section that supersedes specific earlier
  claims (native dispatch table, `16413` = 0x401D, voice thunk const,
  name-call arg). Read the corrections before trusting an older line.
- `docs/adr/` - scope and boundary decisions, created lazily. ADR 0001
  defines the shipped coverage promise. A `GLOSSARY.md` will appear only
  when a term of ours actually needs pinning.