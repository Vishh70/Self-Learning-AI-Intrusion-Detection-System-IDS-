from __future__ import annotations

import sys

from ids.config import CAPTURE_MODE, INTERFACE, MAX_PACKETS, PCAP_PATH, SAVED_MODEL_PATH
from ids.realtime import start_realtime_detection
from ids.utils import format_realtime_result


def main() -> int:
    try:
        for result in start_realtime_detection(
            mode=CAPTURE_MODE,
            model_path=str(SAVED_MODEL_PATH),
            pcap_path=str(PCAP_PATH),
            interface=INTERFACE,
            max_packets=MAX_PACKETS,
        ):
            print(format_realtime_result(result))
    except (FileNotFoundError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
