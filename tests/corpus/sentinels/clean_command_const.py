# FP sentinels for PY-WL-108: constant-only command arguments — os.system over a
# literal, and a shlex-quoted constant through subprocess.run. No untrusted value
# reaches either command sink, so the engine must stay silent on both.
import os
import shlex
import subprocess

from wardline.decorators import trusted


@trusted(level="ASSURED")
def const_system(p):  # FP sentinel: literal command string
    os.system("ls -l /tmp")
    return 1


@trusted(level="ASSURED")
def quoted_const_run(p):  # FP sentinel: shlex-quoted constant command
    cmd = shlex.quote("/usr/bin/true")
    subprocess.run(cmd, shell=True)
    return 1
