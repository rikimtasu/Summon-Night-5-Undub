# -*- coding: utf-8 -*-
"""Save editor GUI for Summon Night 5 (USA), plaintext DATA.BIN.

Editable field (proven end-to-end and playtested):

    DATA.BIN +0x60 = property id 20 = chapter
      0x1A996C(obj,id) = *(obj->array + id*4)
      loader 0x141544   = *(s_pLoadGameData + 0x10 + i*4), 230 words
      0x141CE0          memcpy(s_pLoadGameData, param+0xC680, 0x29890)
      0x14736C get(0x88494, 20) -> table 0x23311C "Ch. N, <title>"
      -> chapter = 0x10 + 20*4 = 0x60

There is no checksum anywhere in the file (verified by a 1-byte edit at
+0x60 surviving a load), and EncryptSave must stay False in ppsspp.ini.

Everything else is displayed read-only: header (+0x00 magic, +0x04 unk,
+0x08 playtime frames at 60/s, +0x0C = filesize - 0x1C) and all 230
property words at 0x10 + id*4, annotated where the RE identified them.

Safety:
  * refuses to write if magic != 0x00021001, size != 0x29890, or
    +0x0C != size - 0x1C (catches SYSTEM saves and foreign files)
  * first edit snapshots the original to DATA.BIN.editbak; Restore puts
    that snapshot back. The backup is never overwritten, so repeated
    edits all roll back to the pre-editor state.

Usage:
    python save_editor.py                # open the window
    python save_editor.py --selftest     # logic test on a temp copy
    python save_editor.py --smoke        # build the window, report, exit
"""
import os
import shutil
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import paths

ROOT = paths.savedata()          # <memstick>\PSP\SAVEDATA

CHAPTER_OFF = 0x60
BAK_NAME = 'DATA.BIN.editbak'
MAGIC_GAME = 0x00021001
MAGIC_SYSTEM = 0x00022001
EXPECTED_SIZE = 0x29890          # 170128 = +0x0C value (0x29874) + 0x1C
PROP_COUNT = 230                 # loader 0x141534: slti $a0, $s5, 0xe6
MAX_CHAPTER = 18

CHAPTERS = {
    0: 'First Dream', 1: 'Border City Savorle', 2: 'What Have You Forgotten?',
    3: 'Another Sunny Day in Savorle', 4: 'Nostalgic Schoolhouse',
    5: 'Connected Hearts, Resonant Souls', 6: 'Bizarre Summon Arts',
    7: 'Doubt and Guidance', 8: 'Academy Defense',
    9: 'The Price of Aspiration', 10: 'Ribbons of Chain',
    11: 'Festering Darkness', 12: 'Shades of Grey',
    13: 'Myriad Black Tentacles', 14: 'Dreaming of Tomorrow Today',
    15: 'Just Once More, Like Before', 16: 'Ending', 17: 'Karma',
    18: 'Clear Data',
}

# property ids whose meaning was decoded from the EBOOT (read-only labels)
PROP_NAMES = {
    20: 'Chapter (editable)',
    50: 'Scenario / scene index',
    52: 'Fixed-point scalar (/10000)',
    55: 'Boolean flag',
    57: 'Character index (GetChr)',
    60: 'Protagonist id (1 = Arca)',
    62: 'Companion id (1 = Dyth, 4 = Priet)',
    64: 'Times Cleared (shown as 0..99)',
    69: 'Bonus flag (==1 -> x1.2)',
    91: 'Bitmask (bits 0x4 / 0x8 tested)',
    160: 'Flag bitmask (0x100 = one-shot)',
    184: 'Set alongside struct+0x14',
}
for _i in range(140, 151):       # ids cleared together at 0xA77A8
    PROP_NAMES[_i] = 'Flag block 140..150'


def u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def prop_off(i):
    return 0x10 + i * 4


def s32(v):
    return v if v < 0x80000000 else v - 0x100000000


def fmt_playtime(frames):
    return '%d:%02d:%02d' % (frames // 216000, (frames // 3600) % 60,
                             (frames // 60) % 60)


def validate(data):
    """Return a list of blocking problems (empty = safe to edit)."""
    issues = []
    if len(data) < 0x3A8:
        issues.append('file too small: %d bytes' % len(data))
        return issues
    magic = u32(data, 0)
    if magic != MAGIC_GAME:
        issues.append('magic +0x00 = 0x%08X, expected 0x%08X '
                      '(0x%08X = SYSTEM save / not a USA game save)'
                      % (magic, MAGIC_GAME, MAGIC_SYSTEM))
    if len(data) != EXPECTED_SIZE:
        issues.append('size = %d (0x%X), expected %d (0x%X)'
                      % (len(data), len(data), EXPECTED_SIZE, EXPECTED_SIZE))
    if u32(data, 0x0C) != len(data) - 0x1C:
        issues.append('+0x0C = %d, expected filesize - 0x1C = %d'
                      % (u32(data, 0x0C), len(data) - 0x1C))
    return issues


def get_chapter(data):
    return u32(data, CHAPTER_OFF)


def apply_chapter(data, chapter):
    if not 0 <= chapter <= MAX_CHAPTER:
        raise ValueError('chapter %r out of 0..%d' % (chapter, MAX_CHAPTER))
    out = bytearray(data)
    struct.pack_into('<I', out, CHAPTER_OFF, chapter)
    return bytes(out)


def discover(root=ROOT):
    """Names of slots under root whose DATA.BIN is a SN5 USA game save."""
    found = []
    if not os.path.isdir(root):
        return found
    for name in sorted(os.listdir(root)):
        path = os.path.join(root, name, 'DATA.BIN')
        try:
            with open(path, 'rb') as fh:
                head = fh.read(4)
        except (IOError, OSError):
            continue
        if len(head) == 4 and struct.unpack('<I', head)[0] == MAGIC_GAME:
            found.append(name)
    return found


def prop_dump_lines(data):
    lines = ['   id  offset   value            meaning']
    for i in range(PROP_COUNT):
        v = u32(data, prop_off(i))
        name = PROP_NAMES.get(i, '')
        lines.append('%4d  +0x%04X   0x%08X (%-7d)  %s'
                     % (i, prop_off(i), v, s32(v), name))
    return lines


def selftest():
    """Exercise load / validate / patch / backup / restore on a temp copy."""
    slots = discover()
    if not slots:
        print('selftest: no SN5 USA game save found under %s' % ROOT)
        return 1
    src = os.path.join(ROOT, slots[0], 'DATA.BIN')
    tmpd = tempfile.mkdtemp(prefix='sn5edit_')
    dst = os.path.join(tmpd, 'DATA.BIN')
    shutil.copyfile(src, dst)
    print('selftest: using copy of %s' % slots[0])

    orig = open(dst, 'rb').read()
    issues = validate(orig)
    assert not issues, issues
    print('selftest: validate OK (size 0x%X, magic 0x%08X)'
          % (len(orig), u32(orig, 0)))

    cur = get_chapter(orig)
    new = MAX_CHAPTER if cur != MAX_CHAPTER else 7
    edited = apply_chapter(orig, new)
    diff = [i for i in range(len(orig)) if orig[i] != edited[i]]
    assert get_chapter(edited) == new
    assert diff and set(diff) <= set(range(CHAPTER_OFF, CHAPTER_OFF + 4)), diff
    print('selftest: chapter %d -> %d, bytes changed: %s'
          % (cur, new, ', '.join('0x%X' % d for d in diff)))

    assert validate(edited) == []
    bad = bytearray(edited)
    struct.pack_into('<I', bad, 0, 0)
    assert validate(bytes(bad)), 'bad magic was not caught'
    print('selftest: bad-magic file correctly rejected')

    editbak = os.path.join(tmpd, BAK_NAME)
    if not os.path.isfile(editbak):
        shutil.copyfile(dst, editbak)      # snapshot pre-edit state
    open(dst, 'wb').write(edited)
    restored = open(editbak, 'rb').read()
    open(dst, 'wb').write(restored)
    assert open(dst, 'rb').read() == orig, 'restore did not round-trip'
    print('selftest: backup + restore round-trip byte-identical')

    shutil.rmtree(tmpd, ignore_errors=True)
    print('selftest: ALL OK')
    return 0


def run_gui(smoke=False):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    class Editor(tk.Tk):
        def __init__(self):
            tk.Tk.__init__(self)
            self.title('Summon Night 5 (USA) save editor')
            self.path = None
            self.loaded_sig = None
            self.data = None
            self._build()

        # ---------------- layout ----------------
        def _build(self):
            pad = {'padx': 6, 'pady': 3}
            top = ttk.Frame(self)
            top.pack(fill='x', **pad)
            ttk.Label(top, text='Save slot:').pack(side='left')
            self.slot_var = tk.StringVar()
            self.slot_box = ttk.Combobox(top, textvariable=self.slot_var,
                                         state='readonly', width=34)
            self.slot_box.pack(side='left', padx=4)
            self.slot_box.bind('<<ComboboxSelected>>', self._on_slot)
            ttk.Button(top, text='Refresh', command=self._refresh
                       ).pack(side='left', padx=2)
            ttk.Button(top, text='Browse DATA.BIN...',
                       command=self._browse).pack(side='left', padx=2)

            self.path_var = tk.StringVar()
            ttk.Label(self, textvariable=self.path_var, foreground='#555'
                      ).pack(fill='x', padx=8)

            info = ttk.Frame(self)
            info.pack(fill='x', **pad)
            self.magic_var = tk.StringVar()
            self.size_var = tk.StringVar()
            self.play_var = tk.StringVar()
            self.chapter_var = tk.StringVar()
            self.bak_var = tk.StringVar()
            for var in (self.magic_var, self.size_var, self.play_var,
                        self.chapter_var, self.bak_var):
                ttk.Label(info, textvariable=var).pack(anchor='w')

            mid = ttk.Frame(self)
            mid.pack(fill='both', expand=True, **pad)
            left = ttk.Frame(mid)
            left.pack(side='left', fill='y')
            ttk.Label(left, text='Chapter (editable):').pack(anchor='w')
            self.ch_list = tk.Listbox(left, width=44, height=21,
                                      exportselection=False,
                                      font=('Consolas', 9))
            for i in range(MAX_CHAPTER + 1):
                self.ch_list.insert('end', '%2d - %s' % (i, CHAPTERS[i]))
            self.ch_list.pack(fill='y', expand=True)
            self.ch_list.bind('<Double-Button-1>', lambda e: self._save())

            btns = ttk.Frame(left)
            btns.pack(fill='x', pady=4)
            self.save_btn = ttk.Button(btns, text='Save chapter',
                                       command=self._save)
            self.save_btn.pack(side='left', padx=2)
            self.restore_btn = ttk.Button(btns, text='Restore backup',
                                          command=self._restore)
            self.restore_btn.pack(side='left', padx=2)

            right = ttk.Frame(mid)
            right.pack(side='left', fill='both', expand=True, padx=6)
            ttk.Label(right, text='All properties (read-only):').pack(anchor='w')
            self.props = tk.Text(right, width=52, state='disabled',
                                 font=('Consolas', 9), wrap='none')
            self.props.tag_configure('chap', background='#d0e8ff')
            sy = ttk.Scrollbar(right, command=self.props.yview)
            self.props.configure(yscrollcommand=sy.set)
            sy.pack(side='right', fill='y')
            self.props.pack(fill='both', expand=True)

            self.status_var = tk.StringVar(
                value='Pick a save slot. Only the chapter field is written.')
            ttk.Label(self, textvariable=self.status_var, relief='sunken',
                      anchor='w').pack(fill='x', side='bottom')

            self._refresh()

        # ---------------- loading ----------------
        def _refresh(self):
            slots = discover()
            self.slot_box['values'] = slots
            if slots and self.slot_var.get() not in slots:
                self.slot_var.set(slots[0])
                self._load(os.path.join(ROOT, slots[0], 'DATA.BIN'))

        def _on_slot(self, _evt=None):
            name = self.slot_var.get()
            if name:
                self._load(os.path.join(ROOT, name, 'DATA.BIN'))

        def _browse(self):
            p = filedialog.askopenfilename(
                initialdir=ROOT, title='Open DATA.BIN',
                filetypes=[('DATA.BIN', 'DATA.BIN'), ('All files', '*.*')])
            if p:
                self.slot_var.set('')
                self._load(p)

        def _load(self, path):
            try:
                data = open(path, 'rb').read()
                st = os.stat(path)
            except (IOError, OSError) as exc:
                self.path = None
                self.status_var.set('cannot read %s: %s' % (path, exc))
                return
            self.path = path
            self.data = data
            self.loaded_sig = (st.st_size, st.st_mtime)
            self.path_var.set(path)

            issues = validate(data)
            if issues:
                self.magic_var.set('INVALID: ' + issues[0])
                self.size_var.set(issues[1] if len(issues) > 1 else '')
                self.play_var.set(issues[2] if len(issues) > 2 else '')
                self.chapter_var.set('')
                self._set_props('')
                self.save_btn.state(['disabled'])
                self.status_var.set('not a USA game save - editing disabled')
            else:
                magic = u32(data, 0)
                self.magic_var.set('magic +0x00 = 0x%08X OK   +0x04 = %d'
                                   % (magic, u32(data, 4)))
                self.size_var.set('size = %d (0x%X), +0x0C field OK'
                                  % (len(data), len(data)))
                frames = u32(data, 8)
                self.play_var.set('playtime +0x08 = %d frames = %s'
                                  % (frames, fmt_playtime(frames)))
                ch = get_chapter(data)
                self.chapter_var.set('chapter +0x60 = %d - %s'
                                     % (ch, CHAPTERS.get(ch, '?')))
                self.save_btn.state(['!disabled'])
                self.status_var.set('loaded OK - select a chapter, then Save')
                self.ch_list.selection_clear(0, 'end')
                self.ch_list.selection_set(ch)
                self.ch_list.see(ch)
                self._set_props('\n'.join(prop_dump_lines(data)), ch)

            editbak = os.path.join(os.path.dirname(path), BAK_NAME)
            has_bak = os.path.isfile(editbak)
            self.bak_var.set('backup %s: %s'
                             % (BAK_NAME, 'present' if has_bak else 'absent'))
            self.restore_btn.state(['!disabled' if has_bak else 'disabled'])

        def _set_props(self, text, chapter=None):
            self.props.configure(state='normal')
            self.props.delete('1.0', 'end')
            if text:
                self.props.insert('1.0', text)
                if chapter is not None:
                    line = chapter + 1               # header line is row 1
                    self.props.tag_add('chap', '%d.0' % line,
                                       '%d.0' % (line + 1))
            self.props.configure(state='disabled')

        # ---------------- writing ----------------
        def _save(self):
            if not self.path or self.data is None:
                return
            sel = self.ch_list.curselection()
            if not sel:
                self.status_var.set('pick a chapter first')
                return
            new = int(sel[0])

            try:
                st = os.stat(self.path)
                fresh = open(self.path, 'rb').read()
            except (IOError, OSError) as exc:
                messagebox.showerror('Save editor', 'cannot re-read: %s' % exc)
                return
            if self.loaded_sig and (st.st_size, st.st_mtime) != self.loaded_sig:
                if not messagebox.askyesno(
                        'File changed on disk',
                        'This save changed since it was loaded (the game may '
                        'have saved). Apply the chapter edit to the new '
                        'contents anyway?'):
                    return

            issues = validate(fresh)
            if issues:
                messagebox.showerror('Save editor',
                                     'refusing to write:\n' + '\n'.join(issues))
                return

            cur = get_chapter(fresh)
            if new == cur:
                self.status_var.set('chapter already %d - nothing written' % new)
                return

            editbak = os.path.join(os.path.dirname(self.path), BAK_NAME)
            made_bak = False
            if not os.path.isfile(editbak):
                open(editbak, 'wb').write(fresh)     # pre-edit snapshot
                made_bak = True

            edited = apply_chapter(fresh, new)
            diff = [i for i in range(len(fresh)) if fresh[i] != edited[i]]
            open(self.path, 'wb').write(edited)

            self._load(self.path)
            msg = ('chapter %d -> %d  (bytes changed: %s)'
                   % (cur, new, ', '.join('0x%X' % d for d in diff)))
            if made_bak:
                msg += '  backup: %s' % BAK_NAME
            self.status_var.set(msg)

        def _restore(self):
            if not self.path:
                return
            editbak = os.path.join(os.path.dirname(self.path), BAK_NAME)
            if not os.path.isfile(editbak):
                self.status_var.set('no backup at %s' % editbak)
                return
            if not messagebox.askyesno(
                    'Restore backup',
                    'Overwrite the current save with %s\n(the state before '
                    'the first edit made by this editor)?' % BAK_NAME):
                return
            shutil.copyfile(editbak, self.path)
            self._load(self.path)
            self.status_var.set('restored from %s' % BAK_NAME)

    app = Editor()
    snapshot = {}
    if smoke:
        # build the window, let it paint, capture state, then exit
        def _cap():
            snapshot['slots'] = list(app.slot_box['values'])
            snapshot['status'] = app.status_var.get()
            snapshot['chapter'] = app.chapter_var.get()
            snapshot['props_lines'] = len(app.props.get('1.0', 'end').splitlines())
            app.destroy()
        app.after(700, _cap)
    app.mainloop()
    if smoke:
        print('smoke: window built OK')
        print('  slots   : %s' % ', '.join(snapshot.get('slots', [])))
        print('  chapter : %s' % snapshot.get('chapter'))
        print('  status  : %s' % snapshot.get('status'))
        print('  proplines: %d' % snapshot.get('props_lines', -1))
    return 0


def main(argv):
    if not paths.PPSSPP_MEMSTICK:
        print('note: SN5_PPSSPP_MEMSTICK is not set, so the save-slot list is '
              'unavailable (use "Browse DATA.BIN..." or set it - see '
              'work/paths.py)')
    if '--selftest' in argv:
        return selftest()
    if '--smoke' in argv:
        return run_gui(smoke=True)
    if '-h' in argv or '--help' in argv:
        print(__doc__)
        return 0
    return run_gui()


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
