# Summon Night 5 (USA) Undub

Restores Japanese story voices (and the JP opening movie) to the USA release,
keeping English text. Tested on PPSSPP through the prologue.

## Method (summary)

- USA stripped story voices two ways: (1) engine clamp in the slot-65 voice
  handler forces every voice id `< 0x9088` to idle, (2) 339 voice triggers
  deleted from the event script.
- v2: NOP the 3-instruction clamp in `EBOOT.BIN`.
- v4: hook the text-display handler with a baked
  `(text-line -> voice-id)` table (339 triggers, split across
  loader-verified memory gaps); deleted CALL195 delta is benign text reflow.
- Voice line mapping audited bilingually (JP owning line vs USA attached
  line); 25 moves + 3 drops applied (`build_v4fix.py`), 336 triggers.
- v5: JP `SV00-17.DAT` (voice archives) + JP `04.DAT` (opening movie) swapped
  into the USA ISO.
- Distributable: xdelta patch USA ISO -> undub ISO (built locally, not tracked).

Details: `work/RE_notes.md`. Mapping table: `work/v3_entries.txt`.

## Rebuild prerequisites (NOT tracked; provide your own)

- `Summon Night 5 (USA).iso` and `Summon Night 5 (JP).iso`
- `EBOOT_USA_decrypted.bin` / `EBOOT_JP_decrypted.bin` (decrypted EBOOTs)
- `work/JPSV/` (JP `SV00-17.DAT`), `work/JP04.DAT` (JP `04.DAT`)
- Python: `pycdlib`, `capstone`, `zstandard`; xdelta3 binary for patching

## Rebuild

```
python work/build_v4.py    # full ISO: SV swap + EBOOT patch (clamp + hook)
python work/build_v5.py    # + JP opening movie
python work/build_v4fix.py # EBOOT-only table update (after editing v3_entries.txt)
```

## Repo contents

- `work/*.py` — build + analysis + audit tooling
- `work/RE_notes.md` — reverse-engineering findings
- `work/v3_entries.txt` — audited voice-id -> text-offset table (+ `.pre_audit_fix`)
- `work/audit*.txt`, `work/namescene.txt` — mapping audit artifacts
- `work/usa_loader_diff.pkl` — loader-fixup address set (build input)
