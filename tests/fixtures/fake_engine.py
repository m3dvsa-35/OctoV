"""Stand-in for an analysis engine in tests: behaviour chosen by argv[1].

ok        print {"ok": true}
exit3     print a message to stderr and exit 3
sleep     sleep 60 s
alloc     allocate ~300 MB, then print {"ok": true}
garbage   print text that is not JSON
file      print the contents of the file named in argv[2] (recorded engine output)
pid       print {"pid": <own pid>} then sleep 60 s
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "ok"
    if mode == "ok":
        print(json.dumps({"ok": True}))
    elif mode == "exit3":
        print("engine exploded: bad PE header", file=sys.stderr)
        return 3
    elif mode == "sleep":
        time.sleep(60)
    elif mode == "alloc":
        blob = bytearray(300 * 1024 * 1024)
        blob[-1] = 1
        print(json.dumps({"ok": True}))
    elif mode == "garbage":
        print("this is not json")
    elif mode == "file":
        sys.stdout.write(Path(sys.argv[2]).read_text(encoding="utf-8"))
    elif mode == "pid":
        print(json.dumps({"pid": os.getpid()}), flush=True)
        time.sleep(60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
