# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: util.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
from screeninfo import get_monitors

def get_aspect_ratio():
    monitor, = get_monitors()
    return monitor.height / monitor.width

def get_user_profile_dir(user_name):
    return os.path.join('/home/', user_name)

def get_user_downloads_dir(user_name):
    return os.path.join(get_user_profile_dir, 'downloads')

def get_safe_filename(filename):
    keepcharacters = (' ', '.', '_', '-')
    return ''.join((c for c in filename if c.isalnum() or c in keepcharacters)).rstrip()