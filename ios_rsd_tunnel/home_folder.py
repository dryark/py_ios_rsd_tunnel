# Copyright (c) 2021-2024 doronz <doron88@gmail.com>
# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License GPL 3.0
from pathlib import Path

LOCAL_PAIR_RECORD_PATH = Path.home() / '.iosRsdTunnel'

def get_home_folder() -> Path:
    LOCAL_PAIR_RECORD_PATH.mkdir(
        exist_ok=True,
    )
    return LOCAL_PAIR_RECORD_PATH
