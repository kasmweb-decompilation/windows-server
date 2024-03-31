# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: agents\windows_agent.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import yaml
import requests
import traceback
import logging
import subprocess
import base64
import uuid
import re
import win32con
import win32ts
import win32security
import win32process
import win32event
import win32api
import win32profile
import winreg
from .base import BaseAgent
from windows_eventlog_handler import WindowsEventLogHandler

class WindowsAgent(BaseAgent):

    def __init__(self, config_file, logger):
        handler = WindowsEventLogHandler()
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        super().__init__(config_file, logger)

    def get_user_downloads_dir(self, user_name):
        try:
            sid = win32security.LookupAccountName(None, user_name)[0]
            if sid is None:
                raise Exception('No user %s found' % user_name)
            sid = win32security.ConvertSidToStringSid(sid)
            key = winreg.OpenKey(winreg.HKEY_USERS, '%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders' % sid)
            value, value_type = winreg.QueryValueEx(key, '{374DE290-123F-4565-9164-39C4925E467B}')
            return value
        except Exception as e:
            self.logger.warning(f'Unable to find user profile: {e}')
            return None

    def replace_path_variables(self, path, user_name):
        pattern = re.compile('\\%([a-zA-Z0-9-_]+)\\%')
        newpath = path
        for m in re.finditer(pattern, path):
            env_var_name = m.group(1)
            if user_name and env_var_name == 'HOMEPATH':
                home = self.get_user_profile_dir(user_name)
                newpath = newpath.replace(f'%{env_var_name}%', home)
            elif env_var_name in os.environ:
                newpath = newpath.replace(f'%{env_var_name}%', os.environ[env_var_name])
        return newpath

    def process_file_mapping(self, file_map, user_name):
        if self.api_host:
            local_filename = None
            try:
                url = f"https://{self.api_host}:{self.api_port}/api/admin/get_file_mapping_contents?token={file_map['jwt_token']}"
                local_filename = self.replace_path_variables(file_map['destination'], user_name)
                with requests.get(url, stream=True, verify=False, timeout=self.request_timeout) as r:
                    r.raise_for_status()
                    with open(local_filename, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)
                    self.logger.debug(f'File written to ({local_filename}) for file mapping for user ({user_name}).')
            except Exception as ex:
                self.logger.error(f'Failed to download and write file mapping to file ({local_filename}) for user ({user_name}): {ex}')

    def execute_script(self, file_path, variables):
        if os.path.isfile(file_path):
            filename = os.path.basename(file_path)
            tmp_filename = f'{self.script_path}\\tmp\\{uuid.uuid4().hex}_{filename}'
            try:
                if os.path.isfile(tmp_filename):
                    os.remove(tmp_filename)
                with open(tmp_filename, 'w') as f:
                    for k, v in variables.items():
                        b64_v = base64.b64encode(bytes(str(v), 'utf-8')).decode('utf-8')
                        f.write(f"${k} = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('{b64_v}'))\r\n")
                    with open(file_path, 'r') as f_source:
                        f.writelines(f_source.readlines())
                self.logger.debug(f'Executing script {tmp_filename}')
                p = subprocess.Popen(f'powershell.exe -ExecutionPolicy RemoteSigned -file "{tmp_filename}"', stdout=subprocess.PIPE)
                p_out, p_err = p.communicate()
                output = f'Script {file_path} completed with exit code {p.returncode}\n'
                if p_out:
                    output += 'Script Output: \n'
                    for line in p_out.splitlines():
                        output += f"\t{line.decode('utf-8')}\n"
                if p_err:
                    output += 'Error Output: \n'
                    for line in p_err.splitlines():
                        output += f"\t{line.decode('utf-8')}\n"
                if p.returncode == 0 and output:
                    self.logger.debug(output)
                elif output:
                    self.logger.warning(output)
            except Exception as ex:
                tb = traceback.format_exc()
                self.logger.error(f'Failure during scirpt execution: {tb}')
            finally:
                if os.path.isfile(tmp_filename):
                    os.remove(tmp_filename)
        else:
            self.logger.error(f'The target script ({file_path}) does not exist.')

    def screenshot(self, user_name):
        screenshot_dir = self.get_user_profile_dir(user_name)
        if not os.path.isdir(screenshot_dir):
            return
        screenshot_path = os.path.join(screenshot_dir, 'kasm_screenshot.png')
        try:
            self.logger.debug('Saving screenshot for %s at %s' % (user_name, screenshot_path))
            self.launch_application_as_user(user_name, os.path.join(os.getcwd(), 'screenshot.exe'), '"%s"' % screenshot_path)
        except Exception as e:
            self.logger.warning('%s. Serving last saved screenshot instead.' % str(e))
        if os.path.isfile(screenshot_path):
            return screenshot_path
        return None

    def launch_application_as_user(self, user_name, application_name, application_args=None):
        sessions = win32ts.WTSEnumerateSessions(0, 1, 0)
        session_user_token = None
        for session in sessions:
            if session['State'] == 0:
                try:
                    session_user_name = win32ts.WTSQuerySessionInformation(win32ts.WTS_CURRENT_SERVER_HANDLE, session['SessionId'], win32ts.WTSUserName)
                    if session_user_name == user_name:
                        session_user_token = win32ts.WTSQueryUserToken(session['SessionId'])
                        break
                except Exception as e:
                    tb = traceback.format_exc()
                    self.logger.error(f'Exception occured launching applicaiton {application_name} as user {user_name}: {e}\n{tb}')
                    continue
        if not session_user_token:
            raise Exception("Failed to launch %s. No Windows user session found for '%s'" % (application_name, user_name))
        process_token = win32security.DuplicateTokenEx(session_user_token, win32security.SecurityIdentification, win32con.MAXIMUM_ALLOWED | win32con.TOKEN_QUERY | win32con.TOKEN_DUPLICATE, win32security.TokenPrimary, None)
        startup_info = win32process.STARTUPINFO()
        process_handle, _, pid, _ = win32process.CreateProcessAsUser(process_token, application_name, ' %s' % application_args if application_args else None, None, None, 0, win32process.CREATE_NO_WINDOW, None, None, startup_info)
        win32event.WaitForSingleObject(process_handle, win32event.INFINITE)

    def is_file_hidden(self, path):
        attributes = win32api.GetFileAttributes(path)
        return attributes & (win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)

    def get_user_profile_dir(self, user_name):
        sid = win32security.LookupAccountName(None, user_name)[0]
        if sid is None:
            raise Exception('No user %s found' % user_name)
        sid = win32security.ConvertSidToStringSid(sid)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s' % sid)
        value, value_type = winreg.QueryValueEx(key, 'ProfileImagePath')
        if value_type == winreg.REG_EXPAND_SZ:
            return value