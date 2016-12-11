#!/usr/bin/env python
# coding=utf-8

import sys
import os
import pbr.version
import shutil
from distutils import sysconfig

try:
    version_info = pbr.version.VersionInfo('nova')
    version_string = version_info.version_string()
except:
    raise Exception("Get Nova version Error!")

if version_string != '13.0.0':
    raise Exception("Nova version error, need version mitaka(13.0.0).")

PYLIB = sysconfig.get_python_lib()
nova_path = os.sep.join([PYLIB, 'nova'])
if not os.path.exists(nova_path):
    raise Exception("Not found nova module path: %s" % nova_path)

TOPDIR = os.path.normpath(os.path.join(
                                       os.path.abspath(sys.argv[0]),
                                       os.pardir))

os.chdir(TOPDIR)
for dirpath, dirnames, filenames in os.walk('nova'):
    py_path = os.sep.join([PYLIB, dirpath])
    if not os.path.exists(py_path):
        print "mkdir " + py_path
        os.mkdir(py_path)
    for py_file in filenames:
        if not py_file.endswith('.py'):
            continue
        src = os.sep.join([dirpath, py_file])
        dest = os.sep.join([PYLIB, dirpath, py_file])
        print "Install: " + src + " -> " + dest
        shutil.copy(src, dest)
