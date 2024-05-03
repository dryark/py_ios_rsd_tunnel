# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License AGPL
import os
import subprocess

REMOTEDTOOL_PATH = ""

def get_remoted_path() -> str:
    if hasattr( get_remoted_path, "remoted_tool_path" ):
        return get_remoted_path.remoted_tool_path
    
    if 'CFTOOLS' in os.environ:
        get_remoted_path.remoted_tool_path = os.environ['CFTOOLS'] + "/remotedtool"
    else:
        if 'CFRDTOOL' in os.environ:
            get_remoted_path.remoted_tool_path = os.environ['CFRDTOOL']
        else:
            get_remoted_path.remoted_tool_path = "remotedtool"
    return get_remoted_path.remoted_tool_path

def stop_remoted() -> None:
    bin = get_remoted_path()
    subprocess.call( [ bin, "suspend" ] )


def resume_remoted() -> None:
    bin = get_remoted_path()
    subprocess.call( [ bin, "resume" ] )