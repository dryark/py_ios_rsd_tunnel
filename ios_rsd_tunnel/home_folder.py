# Copyright (c) 2024 Dry Ark LLC
# License GPL 3.0
from pathlib import Path

LOCAL_PAIR_RECORD_PATH = Path.home() / '.iosRsdTunnel'

def get_home_folder() -> Path:
    LOCAL_PAIR_RECORD_PATH.mkdir(
        exist_ok=True,
    )
    return LOCAL_PAIR_RECORD_PATH
