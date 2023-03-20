#!/usr/bin/env python3

import glob
import json
import sys

if len(sys.argv) != 2:
  print("This program reformats JSON files in-place. You must provide a glob pattern of files to process as its argument.")
else:
  for cfg in glob.glob(sys.argv[1]):
    with open(cfg, "r") as fr:
      j = json.load(fr)
    with open(cfg, "w") as fw:
      json.dump(j, fw, indent="\t")
      fw.write("\n")
