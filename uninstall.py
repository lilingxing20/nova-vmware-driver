#!/usr/bin/env python
# coding=utf-8

import sys
import os
import pbr.version
import shutil
from distutils import sysconfig

PYLIB = sysconfig.get_python_lib()
nova_path = os.sep.join([PYLIB, 'nova'])
if not os.path.exists(nova_path):
    raise Exception("Not found nova module path: %s" % nova_path)

TOPDIR = os.path.normpath(os.path.join(
                                       os.path.abspath(sys.argv[0]),
                                       os.pardir))

os.chdir(TOPDIR)
driver_files = []
driver_dirs = []
for dirpath, dirnames, filenames in os.walk('nova'):
    if not filenames:
        continue
    for py_file in filenames:
        fname, fext = os.path.splitext(py_file)
        if fext != '.py':
            continue
        if fname == '__init__':
            driver_dirs.append(os.sep.join([PYLIB, dirpath]))
        driver_file = os.sep.join([PYLIB, dirpath, py_file])
        driver_files.append(driver_file)

## uninstall nova-vmware-driver pyfile
for py_file in driver_files:
    pyc_file = py_file + 'c'
    pyo_file = py_file + 'o'
    if os.path.exists(py_file):
        os.remove(py_file)
    if os.path.exists(pyc_file):
        os.remove(pyc_file)
    if os.path.exists(pyo_file):
        os.remove(pyo_file)

    print "Uninstall: %s" % py_file

## uninstall nova-vmware-driver dir
for py_dir in driver_dirs:
    if not os.path.exists(py_dir):
        continue
    os.rmdir(py_dir)
    print "rmdir " + py_dir
