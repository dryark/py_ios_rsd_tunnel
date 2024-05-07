# Copyright (c) 2024 Dry Ark LLC <license@dryark.com>
# License AGPL
import logging
import os
import shutil
import subprocess

REMOTEDTOOL_PATH = ""

logger = logging.getLogger(__name__)

def validate_helpers() -> bool:
    remotedtool_path = get_remotedtool_path()
    utunuds_path = get_utunuds_path()

    # These errors are printed in get_helper_path()
    if not remotedtool_path or not os.path.exists( remotedtool_path ):
        return False
    if not utunuds_path or not os.path.exists( utunuds_path ):
        return False

    # No suid-bit check if this script was run as root (i.e. via sudo)
    if os.getuid() == 0:
        return True

    for p in (remotedtool_path, utunuds_path):
        file_stat = os.stat(p)
        if not ((file_stat.st_mode & 0o4000) and (file_stat.st_uid == 0)):
            break
    else:
        return True

    remotedtool_path = os.path.abspath( remotedtool_path )
    utunuds_path = os.path.abspath( utunuds_path )

    msg = """
The helper applications "remotedtool" and "utunuds" exist but are not suid root.
root permissions are required in order to suspend/resume the system process 'remoted', and for the
creation of utun network interfaces.

To fix this problem, either run this script with "sudo", or else assign root privileges with the following commands:
    sudo chown root:admin "%s" "%s"
    sudo chmod u+s "%s" "%s"

Before assigning permissions to these files, ensure that they are in the path you expect.
""" % (remotedtool_path, utunuds_path, remotedtool_path, utunuds_path)

    logger.error( msg )
    return False

helpers = {}
def get_helper_path( helper_name, path_env_var, dir_env_var ) -> str:
    if helper_name in helpers:
        return helpers[helper_name]

    p = ""
    if path_env_var in os.environ:
        p = os.environ[path_env_var]
        if not os.path.exists(p):
            logger.error( "File %s=%s does not exists" % (path_env_var, os.environ[path_env_var]) )
    elif dir_env_var in os.environ:
        p = os.path.join( os.environ[dir_env_var], helper_name )
        if not os.path.exists(p):
            logger.error( "%s not found in tools directory %s=%s" % (helper_name, dir_env_var, os.environ[dir_env_var]) )
    else:
        p = shutil.which( helper_name )
        if not p:
            logger.error( "%s not found in your system PATH. Consider setting %s=/path/to/tools/directory" % (helper_name, dir_env_var) )

    helpers[ helper_name ] = p

    return p

def get_remotedtool_path() -> str:
    return get_helper_path( "remotedtool", "CFRDTOOL", "CFTOOLS" )

def get_utunuds_path() -> str:
    return get_helper_path( "utunuds", "CFUTUNUDS", "CFTOOLS" )

def stop_remoted() -> None:
    bin = get_remotedtool_path()
    process = subprocess.Popen( [ bin, "suspend" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True )
    _, stderr = process.communicate()
    logger.debug( "%s", stderr )

def resume_remoted() -> None:
    bin = get_remotedtool_path()
    process = subprocess.Popen( [ bin, "resume" ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True )
    _, stderr = process.communicate()
    logger.debug( "%s", stderr )
