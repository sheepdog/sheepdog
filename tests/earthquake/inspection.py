#! /usr/bin/env python

# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version
# 2 as published by the Free Software Foundation.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import os, sys, subprocess
import json, re
import tempfile

cwd = os.getcwd()

inspector_bin = cwd + "/earthquake.git/inspector/c/llvm/ninja_build/bin/eq_c_inspector"

dog_src_dir = cwd + "/../../dog"
sheep_src_dir = cwd + "/../../sheep"
sheepdog_include_dir = cwd + "/../../include"
tgt_src_dir = cwd + "/tgt.git"

# TODO: check there's no changes with git

def exec_inspection(src_path, src_dir, inspection_file_path):
    print "inspecting source file: %s" % (src_path)
    print "source directory: %s" % (src_dir)
    print "a path of inspection rule file: %s" % (inspection_file_path)
    
    subproc_args = []
    subproc_args.append(inspector_bin)
    subproc_args.append("-p")
    subproc_args.append(src_dir)
    subproc_args.append("-inspection-list-path=%s" % (inspection_file_path))
    subproc_args.append(src_path)
    ret = subprocess.call(subproc_args)
    if ret != 0:
        print "inspection failed"
        exit(1)

def do_single_case(path):
    inspection_info_path = cwd + '/' + path + "/inspection.json"
    f = open(inspection_info_path)
    s = f.read()
    inspection_schema = json.loads(s)

    for component in inspection_schema:
        c_name = component["component"]
        src_dir = ""
        if c_name == "dog":
            src_dir = dog_src_dir
        elif c_name == "sheep":
            src_dir = sheep_src_dir
        elif c_name == "tgt":
            src_dir = tgt_src_dir

        src_path = src_dir + '/' + component["file"]
        rule_path = path + '/' + component["rule"]

        # construct compile command json for libtooling
        compile_command = {}
        compile_command["directory"] = src_dir
        compile_command["command"] = "/usr/local/bin/clang -I%s" % (src_dir)
        if c_name == "dog" or c_name == "sheep":
            compile_command["command"] += " -I%s" % (sheepdog_include_dir)
        compile_command["command"] += " -o " + re.sub(r'([a-zA-Z_0-9]+).c', r'\1.o', src_path)
        compile_command["command"] += " -c " + src_dir + '/' + component["file"]
        compile_command["file"] = component["file"]
        compile_command = [compile_command]

        compile_command_file = open(src_dir + '/' + "compile_commands.json", "w+")
        compile_command_file.write(json.JSONEncoder().encode(compile_command))
        compile_command_file.close()

        exec_inspection(src_path, src_dir, rule_path)

if len(sys.argv) != 2:
    print "usage: %s <a number of test case>" % (sys.argv[0])
    exit(1)

try:
    case = int(sys.argv[1])
except:
    print "invalid number of case: %s" % (sys.argv[1])
    exit(1)
    
do_single_case("%03d" % case)

