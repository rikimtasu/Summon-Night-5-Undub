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
New xdelta after voice audit fix (25 moves + 3 drops, 336 voices). Same big-window settings. Verified by decode, SHA-256 match. Final patch file 465959255 bytes.