#!/usr/bin/env python3
"""Write a slowed-down copy of an asciicast v2 file, for rendering a readable GIF.

The demos finish in about two seconds, too fast to read. This keeps every output event in
order and unchanged and replaces only the timestamps: a pause before each "== " section
heading and each "$ " command, and none before the output that follows, so a command and
its output land in one GIF frame (fewer frames, a smaller file). The input file is
left alone, so the committed .cast stays the real-time recording.

    python3 docs/demo/retime.py IN.cast OUT.cast
"""

import json
import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
HEADING_PAUSE = 2.5
COMMAND_PAUSE = 2.0
OTHER_GAP = 0.0


def gap(text: str) -> float:
    lines = ANSI.sub("", text).replace("\r", "").split("\n")
    if any(line.startswith("== ") for line in lines):
        return HEADING_PAUSE
    if any(line.startswith("$ ") for line in lines):
        return COMMAND_PAUSE
    return OTHER_GAP


def main(source: str, target: str) -> None:
    with open(source, encoding="utf-8") as fh:
        header, *events = [json.loads(line) for line in fh]
    # The recording's idle limit would cap the pauses this script adds.
    header.pop("idle_time_limit", None)
    clock = 0.0
    with open(target, "w", encoding="utf-8") as out:
        out.write(json.dumps(header) + "\n")
        for event in events:
            if event[1] != "o":
                continue
            clock += gap(event[2])
            out.write(json.dumps([round(clock, 3), "o", event[2]]) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
