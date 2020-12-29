# build
git reset --hard 51a443ce
gclient sync
git apply diff.patch
tools/dev/gm.py x64.release


