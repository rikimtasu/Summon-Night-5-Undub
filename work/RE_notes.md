# SN5 undub — Option 1 RE notes (USA decrypted EBOOT, file vaddrs, SEG_OFF=0xC0)

## Key addresses (file vaddr = file offset - 0xC0)
- `comEvMsgEntStrBase` string: 0x2134F2 (handler 0x17760, table idx 39 @0x23163C)
- `comEvMsgEntVoiceBase` string: 0x213505 (handler 0x1787C, table idx 40 @0x231644)
- `  voice %d` fmt: 0x21351C (printed via jal 0x16DE84)
- Dispatch table base: 0x231500, 8-byte entries {handler, 0}. Voice idx 40.
- Script param getter: 0x1A9C80 (u32 params, reverse-indexed)
- Script VM dispatch: 0x1A9CB0 (6-bit opcode, table @0x234340, 64 entries)
- DAT open helpers: 0xFBF0/0x108E4 (`disc0:/PSP_GAME/USRDIR/%s`), 0xFB24 (10.DAT)
- Voice handler 0x1787C: p0=voiceID (clamp 0x9088 else -1), p1=?, calls 0x8228(ctx,p0,p1), debug print
- Voice setter 0x8228: stores p0->+0x1C, p1->+0x20 of struct at *(a0+0x30)
- SV file table: `SV00.DAT`..`SV18.DAT` + `disc0:/PSP_GAME/USRDIR/%s` fmt
- Loader funcs: 0x17680 (StrBase), 0x17760?/0x1787C voice (see disasm 0x17760-0x17950)

## Script containers
- 02.DAT: USA 24221 entries / JP 24029, table@70, es=56, data~139MB bytecode+text
- 10.DAT: USA 979 / JP 984 blocks, table@32, es=56, data~1.95MB
- SV00-17: 449.9MB mono ATRAC3+ (same codec as SV18), 2048-aligned RIFF concat
- USA 02.DAT name table @~2861482 (ASCII NUL-separated); JP text compressed/bytecode

## Emulator spec (to build)
- ctx: cursor@+4, sp@+8, count@+0xC, consts +0x10=0xA818/+0x14=-1/+0x18=1, stream@+0x1C, stack@+0x20.
- op50 f1: 0-2 helpercall(0x183E2C/5C/8C, stub), 3 stack[count+fetchS], 4 u32(fetchU,fetchU:+2w),
  5 fetchS, 6 f2-1, 7 combinelookup(stub), 8 (f2<<16)|fetchU, 9/10/11 ctx+0x18/0x14/0x10.
- op53: skip 1, push f1, push count, count=sp, flag38=0. op52: skip 1, push f1,cursor,count,ctx18.
- op48: sp+=f1,count=sp. op49: sp-=f1. op54: ENTER pops v1..v4 -> 0x18,0xC,0x4,sp-=stack[v4].
- op55: cursor=(f2<<16)|opnd. op56/57: cond jump (pop cond first). op58: stack[count+fetchS]=0.
- op0 nop; op1 add; op16 lt(top<second). Validate: emulate 185->220 from prefix of observed array, must reproduce tail + sp=count=32.
- Inline DATA tables exist (coords like 696,100; jump tables) - linear decode mangles them; emulator follows control flow.
- comEv handlers reached via task table (jr tail-calls); no direct jals (verified). Updater loop 0xC7D00 also fires voices from message items.


## Story-voice strip mechanism (RESOLVED)

Voice path (JP, verified live):
- CALL214 (op52 f1=1 target 214) -> func@214 arms key 0x4041 via op53;
  op53 helper 0x184300 stores operand to ctx+0x34 (delay-slot sw a1,0x34(a0)),
  pushes [f1,count], count=sp, flag38=0.
- Outer tick calls updater (JP fva 0x69C0 / USA fva 0x12564, identical logic):
  family table JP fva 0x20E4B8 / USA fva 0x230EF8 -> family4 base + (key&0xFFF)*8.
- slot65 (0x4041): JP handler fva 0xB240 (runtime 0x0880F240), USA handler fva 0x1787C.
- Handler reads params via 0x183F4C: param(i) = stack[count-2-K+i], K = op53 f1
  (=> func214 p0 = stack[count-4], p1 = stack[count-3]; func195 K=3).
- Voice store: *((*(engine+0x30)) + 0x1C) = p0 (JP 0x191894 == USA 0x8228, identical);
  -1 = idle (observed in JP idle states). Consumer classifies ids with shared
  category boundaries 0x7D00/0x8CA0/0x9088 (32000/36000/37000) in BOTH builds.

USA strip = TWO parts:
1. ENGINE: USA slot65 handler adds a clamp absent in JP:
       0x17904 sltu a1,s0,a1 ; 0x17908 bnel a1,zero ; 0x1790C addiu s0,-1
   i.e. if voiceId < 0x9088 (37000) => store -1 (never plays).
   JP story voice ids = 36000..36835 (505 pair-id sites, values identical JP vs USA)
   + const ids 15..435 (392 JP / 68 USA) + f2-1 ids 1..15 (15 JP / 0 USA)
   => all < 37000 => ALL story voices silenced. Extra USA call 0x16DE84 = debug log (benign).
2. SCRIPT: USA deleted 339 CALL214 sites (324 const-arg + 15 f2-1), all with their
   arg push. Pair-id voice sites NOT deleted (505 = 505). CALL195 delta (-835) is
   benign text reflow (JP 2404 short lines vs USA 1569 long lines, same content).
   Per-key op53 counts identical (except 0x4043 273/274).

Other resolved items:
- op50 f1=5 pushes the ADDRESS stream+2*(c10+idx) (string pointer), not the value
  => CALL195 = text-line display (queue push via 0x191878 -> 0x18F3F8, entries 12B,
  write idx at queueobj+0x64).
- op50 f1=4 = fetch two u16 (cursor += 2); pushed value = first u16 (voice id);
  second u16 always 0 in pair sites.
- 0x9088 constant elsewhere (USA 0x243C0 / JP 0x16AAC) = shared id-category
  classifier, NOT a second clamp.
- USA slot64 (key 0x4040, text) handler = structurally identical to JP (unpatched).

v2 build (build_undub_v2.py): JP SV00-17.DAT swap (as v1) + NOP the 3 clamp
instructions in USA EBOOT (plain ELF, same size 3018032, written over
/PSP_GAME/SYSDIR/EBOOT.BIN extent in output ISO). Not yet done: re-insertion of
the 339 deleted CALL214 sites (script rebuild + cursor/string-ptr remap) = v3.

## v3 (voice-hook, no script rebuild)

Alternative to script-container rebuild: hook USA slot-64 (text) handler tail
(fva 0x1784C: move a0,s2 / 0x17850: jal -> j CAVE / nop). Cave at fva 0x23550C
(runtime 0x08A3950C, file-backed zero cave in RWX seg0) + 339-entry table
(c10=u32, text-offset=u32, voice-id=u32; key = strptr - stream, c10 = ctx+0x10).
On hit: voice store replica (lw t3,0x30(s2) / sw vid,0x1C(t3)); then displaced
move a0,s2 + jal queue wrapper (runtime 0x0880C20C) + j 0x0881B858.
Mapping: SequenceMatcher JP-vs-USA op stream; each deleted CALL214 -> first USA
CALL195 at/after anchor (spreading via used-set; 312 in-window + 27 spread, 0 dup
keys). Order-preserving; samples verified semantically (narration vids 0-6 ->
Lyndbaum war lines). Hand-assembled MIPS verified via capstone disasm
(caught rs-field errors pre-build). build_v3.py extends v2 (same ISO pipeline).

## v3 crash (FIXED): loader fixups clobber patches

v3r1 crashed at first text line (PC in table region, RA pre-hook). Root cause,
proven by file-vs-RAM diff (75,683 loader-patched words in USA seg0):
1. Hook overwrote a jal at fva 0x17850 that the loader fixup-patches at boot
   (file 0x0C002083 -> runtime 0x0E202083), so the NOP delay slot became a live
   jal again -> chaos. (v2 NOPs were safe: no fixups there.)
2. Old cave (fva 0x23550C) itself contained loader fixup addresses.
Fix (v3r2, build_v3.py): hook = j at 0x17848 + displaced sw in delay at 0x1784C
(both loader-clean; 0x17850 left for its fixup, dead code); cave moved to
loader-clean zero gap fva 0x236378 (runtime 0x08A3A378). Build asserts hook/cave
against work/usa_loader_diff.pkl (file-vs-retail-RAM fixup address set).
Verified: capstone disasm of cave, emu_cave.py full-scan MISS (2383 steps ->
queue jal) and HIT (voice store to live voiceobj+0x1C) emulation vs real RAM.
Lesson: every EBOOT code/data patch must be checked against the loader diff.

## v4 (split voice-hook, FINAL)

Probe-2 proved 14 gaps fully intact (5368B) while [0x236100,0x23E400+) is dead
(game buffer + loader-dead zone). v4 splits payload: 35-word walker + 11 chunk
descriptors in gap 0x224868 (runtime 0x08A28868); 339 table entries chunked
across 13 other gaps (greedy, key-sorted). Same hook site (0x17848).
Fresh build from decrypted (no canary/probe leftovers); asserts: hook/NOPs +
every payload word loader-clean + file-zero; final diff shows ONLY intended
ranges; file == verified assembly byte-exact; emu MISS+HIT address-sane.
LESSON (again): MIPS branch target = branch+4+imm*4 (NOT +8). v4r1 had all four
branches off by one (chunk-loop one would hang); caught by capstone target check.
ALWAYS verify assembled branch targets by disassembly, never by formula alone.

## v5 (JP opening)

04.DAT = single-PSMF opening movie (USA 14786560B, JP 14790656B; only other
movie is a PSMF inside 12.DAT, left alone). Whole-file swap JP->USA.
LESSON: pycdlib add_fp to an EXISTING path SILENTLY does nothing (v5r1 shipped
USA 04.DAT; caught by byte-verify). Must rm_file first, then add_fp.
build_v5.py: full rebuild (SVs + JP 04.DAT) + EBOOT extent overwrite + verify
(04.DAT == JP bytes, hook intact).

## xdelta patch v5 for users

xdelta3 3.0.11 official binary, checksum-verified.
Patch USA ISO to Undub v5 ISO. Default encode 736MB; re-encode with
1GB source window plus max input window gives 466MB, because the pycdlib
rebuild shifts file sectors and the small default window misses distant
matches. Verified by decode plus SHA-256 match.
Final file: Summon Night 5 Undub xdelta, 465959276 bytes.
Apply with xdelta3 decode using the USA ISO as source.

## v4 table audit fix (misplaced voices)

Audit (JP owning line vs USA attached line, bilingual read) found LOCAL
misplacements: prologue cluster vids 16-32 attached 1+ lines early (matcher
drift in reflow zone), off-by-one-late blocks (40-42, 116-117, 119, 125-127),
one wrong-branch (124, dropped - line merged into vid123s), two orphans
dropped (30 cut line, 118 merged line). Fixed 25 moves + 3 drops via
build_v4fix.py (EBOOT-only rebuild, dup-key asserted); 336 entries.
Well-aligned regions (f2 narration, summoning, name scene incl. Folth/Arca
branch pairs, late prologue) verified correct, untouched. Lesson: shape-only
alignment jitters +-1 phrase in reflow zones; bilingual content audit is the
ground truth for voice placement.
New xdelta after voice audit fix (25 moves + 3 drops, 336 voices). Same big-window settings. Verified by decode, SHA-256 match. Final patch file 465959255 bytes.Backlog voice replay: entries log voice id at +0x04 (pair ids seen live; -1 unvoiced). Replay fn 0xDE3E8 re-displays text with no voice call, so no restored voice replays (not even native pair lines). Fix: hook 0xDE430 (loader-clean, s2=entry live, t0/t1 proven free) -> 13-word cave stores entry+0x04 to voiceobj+0x1C when != -1, then displaced ops + return. Voiceobj via fixed global 0x08A27508 (loader-clean, chain verified live). EBOOT-only rebuild. Lesson: BEQ vs BNE polarity double-check by disasm.Backlog replay fix v2: added flight recorder to replay cave (count + ring of last 8 (entry,vid)) after catching systematic rs/rt hand-encoding slips (t1/t2 vs t3/t6) via disasm check. Rule: never hand-encode; use LW/SW/ORI/ADDIU/ANDI/SLL/ADDU helpers + mandatory capstone verification.Backlog voice slot divergence: USA logs voice id at entry+0x04 (+0x08 stays 0/-1); JP logs at +0x08. Replay reads +0x08, so USA voiced lines replay silent while JP voices. Fix: logger hook at 0xDDF7C copies pair-range +0x04 to +0x08 when +0x08 empty (const/f2 ids gated out until table logging verified). Cave in proven gap slack, EBOOT-only rebuild.Backlog replay diagnosis: flight recorder (count 0) proved 0xDE3E8 hook never fires usefully -> not the confirm path (or s2 wrong). Rebuilt replay cave with UNCONDITIONAL recorder (s2+vid ring) to distinguish never-fires vs fires-with-bad-entry on next test.Backlog replay gate STUBBED in USA: gate fn 0xDE5C0 always returns 0 (replay never runs); JP equivalent 0xC0ACC returns entry+0x08!=-1. Replay fn/caller/helpers otherwise identical. Fix: ported JP gate logic to cave (entry = obj+idx*200+0xE0, return +0x08!=-1), hooked 0xDE5C0. Combined with logger-copy (pair ids into +0x08) and replay-hook, pair replay should now voice. Lesson: / confusion in hand encoding - use helpers + disasm check every time.Backlog replay round 4: prior flight recorder was UNREADABLE - replay cave grew to 128B but RC sat at cave+96, so count field overlapped cave instructions (read 0x3C0908A2 = lui insn). Repacked gap 0x224868 (660/664B used): replay cave 33w@+228, log cave 27w@+360, gate cave 25w@+468, RC@+568, logRC@+636, gateRC@+648; make_eboot now asserts layout order + zeroes recorders. Also: gate cave read selected idx at -0x6920 (count word) instead of original -0x691C (imm 0x96E4) - fixed; RAM shows count=5 at obj+0x96DC, sel at +0x96E4=0, entry base obj+0xE0=0x8DE1C04, chain 5 entries with +0x08 all 0/-1 (log copy never landed, cause unknown -> log recorder now captures count + last (entry,vid-at-fire)). Replay cave now ALSO writes entry+0x08=vid (JP parity for stock readers) in addition to voiceobj+0x1C, before text re-display. Verify script caught SW(rs,rt) arg-order bug in gate recorder (sw t0,4(a0) vs sw a0,4(t0)) - always assert against capstone TEXT, not hand math. Lesson: keep instrument storage OUTSIDE grown caves; re-check layout after every cave growth.

Backlog replay round 5 (CRASH + root cause of silent +0x08): PPSSPP crashed at PC 0x088E1F80, bad access 0x11bd63c5, ALL recorders read 0. Diagnosis: fault addr 0x11bd63c5 - 0x25 = the sb \,0x25(\) right after the log hook with a0 = s4+s1 = 0x11BD63A0 (stale s4), and PC = the branch-target JIT block start. Cause: full-text branch audit found 0xddf4c beqz -> 0xddf80 landing EXACTLY on the old log hook delay slot (first render: 0x14(s1)==0), skipping the j/cave -> displaced ori s4,zero,0 never executed -> a0 overflowed -> sb faulted. Same bypass explains history: the cave (recorder + 0x04->0x08 copy) NEVER ran on first render, so +0x08 stayed 0/-1 and replay stayed silent - the earlier hook-site scan was wrong (never did a whole-text incoming-branch audit). Fix: hook moved to 0xDDF80 (j replaces the ori), delay 0xDDF84 stays NATIVE stock (never zeroed), displaced = ori only, ret 0xDDF88; the 0xddfd8 bnez loop back-edge lands on 0xDDF88 (skips cave - correct, preserves char counter); every other logger path funnels through the cave. Cave rewritten to 25w: empty check now treats +0x08 in {0,-1} as empty (sltiu test; round-4 bnez would have skipped -1 entries), hi16 check dropped (unsigned upper-bound sltu already rejects any vid with hi16 != 0). verify_caves.py now runs a permanent full-text incoming-branch audit for ALL three hooks (log delay branch-free + single known beqz on the j; replay fully branch-free; gate jal-only on entry, delay branch-free) and asserts stock neighbour words. Audit also caught SLTIU encoded as slti (opcode 0x0B not 0x0A). ISO rebuilt EBOOT-only (v5 opening preserved), mtime 2026-09-23T20:52:19, SHA-256 8fa929ded606148ccc216d6eaeddf56b95d313443d45d96bff2cba6121d241e3. Lesson: NEVER trust a hook site until a whole-text incoming-branch audit proves no branch lands on the delay slot (or between hook and ret); prefer keeping the delay slot native stock code when any doubt - a skipped displaced state-mutating instruction corrupts everything downstream.

Voice mapping round 6 (prologue recheck, Ghift globs line): screenshot line (key 126890) played vid53 whose clip = ちゃんと、あの紙きれに書かれてた… ("I did exactly what was on the paper…"). Full bilingual line-by-line alignment of ALL entries (JP CALL214-group first text vs USA attached line, full strings, unattached-line sweep) found: (a) vids 53-57 each attached ONE USA line late - correct keys 126792/126890/126984/126992/127062 (126792 sat UNATT = shift signature; "Ghift! You're all right!" 127098 correctly stays unvoiced under v57's clip); (b) 128/129 same one-late shift (UNATT 132350 "Well then, I shall be assisting you…" = v128 ナラバ、私ハ…; 132426 = v129); (c) 416/417 one-late (UNATT 153440 "priceless goal…working together as a team" = v416; 153514 "Are you…fine with that?" = v417 それでもいいか; 153540 is the unvoiced kids' answer); (d) branch A 151/152 content SWAPPED: JP order [apology, who-am-I] vs USA [topic, apology] - localizer reordered that branch only (other 3 aligned) -> keys swapped; (e) 349 sat on an inserted USA joke ("3,720 to 1") - true line is UNATT 149978 "immediate death" = 死亡シテイタ可能性モ; (f) v122 カッコつけた手前 merged into USA121's line -> dropped, its key 131992 reassigned to v123 ヤレヤレ ("Oh, dear. I was afraid you were headed in that direction."), v124 REINSTATED at 132050 ("Ghift and Folth are trusting me" = ギフトも、フォルス君も, exact); (g) round-4 drops of 30/118 were wrong: 30 -> 124914 ("…helping hand from my favorite Cross" = あいつを呼ぶか), 118 -> 131522 ("master of the backhanded compliment" = ド根性ってヤツさ). Kept after full-string review: loose-but-slot-correct localizations (45, 89-91, 103, 379, 387 - no better target line exists). Confirmed USA natively retains all 68 const CALL214 sites (monster roars 82/88/104/106/112, void-voice 130/135/139/143, etc.) - they play via stock path with clamp NOPed, correctly absent from the table. build_v6fix.py validated every target key+unit as a real USA text call BEFORE writing; 13 moves + 1 drop + 3 adds = 338 entries / 11 chunks; extent byte-verified (13 present + 10 absent packed triples); verify_caves.py ALL PASS; EBOOT-only rebuild (v5 opening preserved). ISO mtime 2026-09-23T21:39:37, SHA-256 0b3bee610fd9707683b36a885b4b9f0fc62f11e1119aa6695f87d00c6ae88d3e. Lessons: an UNATTACHED USA line between attached ones whose content matches an adjacent vid's JP group = the shift signature; watch for localizer-INSERTED lines (must stay unvoiced) and cross-version line-order swaps inside a response pair; round-4's "orphan drop" judgment needs the same full-string standard or valid voices get deleted.

## Post-prologue completeness audit (2026-09-23)

### 1. Captured context (c10=38381 USA / 43032 JP) is provably COMPLETE
Multiset proof (Counter arithmetic, not set membership, so duplicate ids cannot hide):
- JP const 392 = USA retained 68 + table 323 + 1 intentional round-6 drop (vid 122)
- JP f2     15 = USA 0 + table 15
- JP pair  505 = USA 505 (native, untouched)

Only uncovered site is vid122, the deliberate DROP (line merged into USA 121).
This catches the hole in build_v3_table.py's `uc.get(v,0)==0` id-absence filter:
a JP site whose id also occurs elsewhere in USA would have been silently skipped.
Also confirmed: "It was a great war..." narration IS prologue-block content
(USA block contains b'great war'), so that scene is already covered.

### 2. Script block header format (from RAM, both versions identical)
- u32@+0  = 0x10000201   magic
- u32@+4  = 0x10000002   magic
- u32@+8  = total block size (even; = c10*2 + pool bytes)
- u32@+16 = c10         token area = c10*2 bytes from byte 24; string pool after
- tokens start at byte 24 (unit 12); clean landing = last token cursor + 1 == c10

Used as a fast whole-RAM scan prefilter (the magic pair is extremely selective).
NPJH_4 @0xD2D000: size=249596, c10=55506 -> a DIFFERENT story script (ch.1).

### 3. op52 call targets are PER-BLOCK function ids (not global)
Byte-pattern search for 195/214 only works on the prologue. Calibration-free rule:
- text  function = call target with most op50 f1=5 (string-index) pushes
- voice function = call target with most op50 f1=4 (pair-id) pushes

Verified: prologue text=195 voice=214 (2404 f5 / 505 f4);
         ch.1     text=234 voice=253 (3553 f5 / 516 f4).

Also present in every state: non-story system blocks c10=7133 (size 14268) and
c10=8711 (size 17436) - zero text calls, zero CALL214, identical JP vs USA.
Lessons: op52 f1=1 token u16 = 52|(1<<6) = 0x0074 (0x0034 is f1=0); a wrong
pattern silently reports 0 sites. The landing check must compare the unit index
to c10, never to c10*2 (units != bytes) - that bug rejected every valid block.

### 4. THE GAP IS REAL AND QUANTIFIED
Const voice-id space is chapter-partitioned, with ZERO overlap:
- prologue : 392 const sites, ids   15..435   (covered by our table)
- ch.1     : 657 const sites, ids 2000..2664  (NOT covered)

Pair-form ids 36000..36835 are shared across chapters (504 overlap) and USA
retains them natively, so only const/f2 story ids are missing.
USA const-call retention pattern (prologue): non-story (monster roars 82/88/
104/106/112, void 130/135/139/143, ...) kept, story const deleted. The ch.1
const ids 2000..2664 are all story range -> almost certainly deleted in USA too,
but that needs a USA ch.1 RAM capture to confirm and to build the mapping.
=> Current patch = prologue chapter only. Post-prologue chapters are silent.

### 5. Why full static coverage is blocked (negative results)
- 02.DAT (USA 140,421,120 B @ ISO 328826880, 24221 entries, table@70, u32[2]=
  24221*32 -> entry size 32 not 56) and 10.DAT contain NO script text in utf-8 /
  utf-16le / shift_jis, and the exact pool string is absent from the whole USA
  ISO -> script entries are compressed.
- 256x single-byte XOR and +k byte-add scans over 02.DAT: no hits.
- The block-header magic is NEVER materialized in EBOOT code (lui 0x1000 +
  ori $zero,0x201/0x202 scan: 0 hits) -> the 24-byte header is plaintext carried
  inside the compressed blob, so the loader only consumes size/c10.
- SN5 save files (ULUS10656SN5GAME46/47, NPJH50696SN5GAME00-05) are encrypted
  and embed no script block (no magic, no pool strings).
=> Full-game coverage needs either the 02.DAT decompressor (RE) or paired
PPSSPP save states (RAM), the latter being the proven method.

### 6. Extension mechanics (ready)
Table entries are 12-byte (c10, key, vid) triples; the walker already matches
entry[0] against the live context c10, so multi-context support is structural.
Only build_v4.py load_entries() is prologue-specific: it hardcodes c10=38381
and must instead read a per-entry c10 column.
Procedure per chapter: (1) RAM states for USA+JP at the same scene, (2) locate
blocks by magic, (3) classify text/voice funcs by the push-count rule, (4) map
JP const/f2 sites to USA text-call keys (build_v3_table.py logic generalized,
with the round-6 full-bilingual audit standard), (5) append entries with that
chapter's USA c10, (6) rebuild EBOOT-only + verify_caves + xdelta.

## Chapter-1 coverage via paired RAM captures (2026-09-24)

User supplied fresh save-states of the SAME scene in both builds (landlady
scene), overwriting slot 0 (sizes ~7.2-7.3MB, distinct from the old 5.6MB
prologue dumps). Both land on the chapter-1 story block:

| | c10 | size | textfunc | lines | voicefunc | const | pair |
|---|---|---|---|---|---|---|---|
| JP  | 55506 | 249596 | 234 | 3553 | 253 | 657 (2000..2664) | 516 |
| USA | 50098 | 222560 | 234 | 2198 | 253 | 656 (2000..2664) | 516 |

Multiset diff: pair sites identical (516=516); const sites differ by exactly
ONE - vid 2287 is present in JP, deleted in USA. So the chapter-1 block needs
a single new table row, not 657. The whole earlier "657 missing" worry was an
over-extrapolation from the JP-only count; the USA block RETAINS its const
triggers (unlike the heavily-stripped prologue block), and they play natively
once the clamp is NOPed. Only genuinely-deleted triggers need table rows.

Bilingual target for the one deleted site (vids 2286/2288 retained, bracket it):
  JP  unit 42597 vid 2287  line: 「それは、残念でしたね」
  USA unit 38601 sidx 45655 key 191506  "T-That's a shame, I suppose..."
Convention confirmed on retained anchor vid 2288: its preceding JP line
「そろそろ次のところに行きましょ！」 matches USA "Okay, I think we're finished
here for now. We need to go!" (voice fires after its line).
=> new row (c10=50098, key=191506, vid=2287) in work/extra_entries.txt.

### Multi-context table support
The walker already matches each entry's c10 against the live context
(lw 0(t5) vs ctx+0x10, `bne v0,t1,adv`), so per-chapter rows coexist with no
code change. build_v4.py load_entries() now merges a new work/extra_entries.txt
("c10 key vid" lines, UTF-8) with the audited prologue v3_entries.txt
(c10=38381). CHUNK_HOMES hold 343 entries across 11 chunks; 339 used after
this addition, layout still ends at gap+660/664, verify_caves.py ALL PASS.
EBOOT extent re-swapped into the existing ISO (no full rebuild needed since
the JP SV archives + opening were already in place).

Lesson: per-block retention varies wildly - the prologue block lost 324 const
triggers, chapter 1 lost 1. Never extrapolate the strip rate from one block;
diff each block pair.
