#!/usr/bin/env python3

import glob
import json

for cfg in glob.glob("test/config*/*json"):
    print(cfg)
    with open(cfg, "r") as fr:
      j = json.load(fr)
    with open(cfg, "w") as fw:
      json.dump(j, fw, indent=4)
      fw.write("\n")
