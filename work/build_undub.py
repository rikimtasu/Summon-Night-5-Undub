from pycdlib import PyCdlib
import os
usa = r'D:\Documents\Default Project\Summon Night 5 (USA).iso'
out = r'D:\Documents\Default Project\Summon Night 5 (USA) Undub.iso'
svdir = r'D:\Documents\Default Project\work\JPSV\PSP_GAME\USRDIR'
iso = PyCdlib()
print('opening USA...', flush=True)
iso.open(usa)
for i in range(18):
    name = f'SV{i:02d}.DAT'
    src = os.path.join(svdir, name)
    assert os.path.exists(src), src
    iso_path = f'/PSP_GAME/USRDIR/{name}'
    print(f'adding {name}...', flush=True)
    iso.add_fp(open(src,'rb'), os.path.getsize(src), iso_path=iso_path)
print('writing...', flush=True)
iso.write(out)
iso.close()
print('done', flush=True)
