---
status: accepted
---

# Ship prologue + chapter 1; defer the remaining chapters

The undub patch's shipped voice table covers the prologue (339 rows,
provably complete) and chapter 1 (1 row, `verdict: COMPLETE`), 340 rows
total. We decide that is the patch's scope: the remaining chapters are
**deferred, not abandoned** - three blocks stay unpaired (JP `c10=49220`,
USA `c10=41244`, USA `c10=54606`) and extending coverage is mechanical once
paired USA+JP save-state captures exist, because `work/extra_entries.txt`
accepts rows for any chapter context.

## Considered Options

- **Finish every chapter before shipping.** Rejected: it puts an
  indefinite chain of manual capture jobs in the critical path of an
  artifact that is already playtested and auditable, and it is untestable
  whether the last chapter's capture even exists.
- **Call chapters 2+ a permanent limitation.** Rejected: that overstates
  a blocker. The mechanism is proven; the work simply has not been
  requested. "Deferred" keeps the door open without implying the feature
  is broken.

## Consequences

- The README states the coverage promise explicitly; a reader seeing a
  340-row table must not infer full-game coverage.
- `chapter_voice_census.py --selftest` fails by design (its chapter-1
  block-pair capture is gone) and is **excluded from sign-off** - it is a
  capture-set problem, not patch integrity. The exclusion is written into
  the README so the failure is not misread as a regression.
- Sign-off is the four mechanical gates plus a manual playtest; see the
  README's maintainer checklist.
- Content scope is frozen at JP story voices + the JP opening movie.
  Any other content swap - including JP-only costume DLC, which is not
  loadable here - is a new decision with its own verification.