# -*- coding: utf-8 -*-
"""Parse the EBOOT as an ELF instead of guessing at its structure.

Everything so far assumed addressing conventions. Several paid off, several
were dead ends (no lui/addiu consumer for the save strings, no raw pointer, no
$gp, no size constant). The file is a plain 3,018,032-byte ELF, so read what it
says about itself:

  * section headers -> names. If .symtab/.strtab survived, function names come
    free and the whole NID-vs-stub problem disappears.
  * .rel.text / .rel.dyn -> R_MIPS_JAL26 relocations mark every call whose
    target is filled in at load, i.e. the import call sites. That gives us the
    call edges directly, no NID naming required.
  * find the import stub section if present, which maps NID -> stub address.

This is read-only reconnaissance: print the section table, symbol counts, and
relocation types present.
"""
import struct
import sys

P = r'D:\Documents\Default Project\EBOOT_USA_decrypted.bin'
d = open(P, 'rb').read()

if d[:4] != b'\x7fELF':
    print('not an ELF:', d[:8].hex())
    sys.exit(1)

(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize,
 e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from(
    '<HHIIIIIHHHHHH', d, 16)
print('ELF: entry=0x%08X phoff=0x%X phnum=%d shoff=0x%X shnum=%d shstrndx=%d'
      % (e_entry, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx))
print('     e_type=%d machine=%d shentsize=%d' % (e_type, e_machine, e_shentsize))

if e_shoff == 0 or e_shnum == 0:
    print('\nNO SECTION HEADERS - stripped. Falling back to program headers.')
    print('  (this is common for retail EBOOTs; .symtab will not be available)')
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from('<IIIIIIII', d, off)
        T = {1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR',
             0x70000000: 'PSPPREVIEW', 0x70000001: 'PSPMODULEINFO'}.get(
            p_type, hex(p_type))
        if p_type in (1, 2) or (p_filesz > 0x100000):
            print('  ph[%d] %-14s off=0x%08X vaddr=0x%08X filesz=0x%X memsz=0x%X flags=%d'
                  % (i, T, p_offset, p_vaddr, p_filesz, p_memsz, p_flags))
    print('DONE')
    sys.exit(0)

# ---- section headers -----------------------------------------------------
shstr_off = e_shoff + e_shstrndx * e_shentsize
(sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info,
 sh_addralign, sh_entsize) = struct.unpack_from('<IIIIIIIIII', d, shstr_off)


def cstr(base, idx):
    e = d.index(b'\x00', base + idx)
    return d[base + idx:e].decode('latin1')


sections = []
print('\n=== section headers ===')
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    (n, t, fl, a, o, s, lk, inf, al, es) = struct.unpack_from('<IIIIIIIIII', d, off)
    name = cstr(shstr_off + sh_offset - sh_offset + sh_offset, 0) if False else None
    try:
        name = d[shstr_off + 0:0]  # placeholder
    except Exception:
        pass
    sections.append((n, t, fl, a, o, s, lk, inf, al, es))

# resolve names properly
shstrtab = d[sh_offset:sh_offset + sh_size]
SHT = {0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
       8: 'NOBITS', 9: 'REL', 11: 'DYNSYM', 0x70000000: 'PSPREL',
       0x70000001: 'PSPMODINFO'}
named = []
for (n, t, fl, a, o, s, lk, inf, al, es) in sections:
    end = shstrtab.find(b'\x00', n)
    nm = shstrtab[n:end].decode('latin1') if end >= 0 else '?'
    named.append((nm, t, a, o, s, es))
    print('  [%2d] %-20s %-10s addr=0x%08X off=0x%08X size=0x%X entsz=%d'
          % (len(named) - 1, nm, SHT.get(t, hex(t)), a, o, s, es))

# ---- symbols -------------------------------------------------------------
sym_sections = [(i, nm, t, o, s, es, link, info)
                for i, (nm, t, fl, a, o, s, lk, inf, al, es) in
                enumerate(named) for _ in [0]]
print('\n=== symbol tables ===')
found_sym = False
for i, (nm, t, fl, a, o, s, lk, inf, al, es) in enumerate(
        [(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9])
         for x in sections]):
    if t in (2, 11):   # SYMTAB / DYNSYM
        found_sym = True
        count = s // 16 if es == 0 else s // es
        print('  section %d type=%s entries=%d' % (i, SHT.get(t, t), count))

if not found_sym:
    print('  none - symbol table stripped (expected for retail)')

# ---- relocations ---------------------------------------------------------
print('\n=== relocation sections ===')
found_rel = False
for i, (n, t, fl, a, o, s, lk, inf, al, es) in enumerate(sections):
    if t in (4, 9, 0x70000000):   # RELA / REL / PSPREL
        found_rel = True
        ent = es or 8
        print('  [%d] type=%s off=0x%X size=0x%X entsz=%d -> %d entries'
              % (i, SHT.get(t, hex(t)), o, s, ent, s // ent if ent else 0))
if not found_rel:
    print('  none - relocations stripped too')
print('DONE')
