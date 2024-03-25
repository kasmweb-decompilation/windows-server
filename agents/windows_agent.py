# decompyle3 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.19 (default, Mar 25 2024, 14:51:23) 
# [GCC 12.2.0]
# Embedded file name: agents\windows_agent.py

import os, yaml, requests, traceback, logging, subprocess, base64, uuid, re, win32con, win32ts, win32security, win32process, win32event, win32api, win32profile, winreg
from .base import BaseAgent
from windows_eventlog_handler import WindowsEventLogHandler

class WindowsAgent(BaseAgent):

    def __init__(self, config_file, logger):
        handler = WindowsEventLogHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        super().__init__(config_file, logger)

    def get_user_downloads_dirParse error at or near `POP_EXCEPT' instruction at offset 124

    def replace_path_variables(self, path, user_name):
        pattern = re.compile("\\%([a-zA-Z0-9-_]+)\\%")
        newpath = path
        for m in re.finditer(pattern, path):
            env_var_name = m.group(1)
            if not user_name:
                if env_var_name == "HOMEPATH":
                    home = self.get_user_profile_dir(user_name)
                    newpath = newpath.replace(f"%{env_var_name}%", home)
                if env_var_name in os.environ:
                    newpath = newpath.replace(f"%{env_var_name}%", os.environ[env_var_name])
                return newpath

    def process_file_mapping(self, file_map, user_name):
        if self.api_host:
            local_filename = None
            try:
                url = f'https://{self.api_host}:{self.api_port}/api/admin/get_file_mapping_contents?token={file_map["jwt_token"]}'
                local_filename = self.replace_path_variables(file_map["destination"], user_name)
                with requests.get(url, stream=True, verify=False, timeout=(self.request_timeout)) as r:
                    r.raise_for_status()
                    with open(local_filename, "wb") as f:
                        for chunk in r.iter_content(chunk_size=8192):
                            f.write(chunk)

                    self.logger.debug(f"File written to ({local_filename}) for file mapping for user ({user_name}).")
            except Exception as ex:
                try:
                    self.logger.error(f"Failed to download and write file mapping to file ({local_filename}) for user ({user_name}): {ex}")
                finally:
                    ex = None
                    del ex

    def execute_script(self, file_path, variables):
        if os.path.isfile(file_path):
            filename = os.path.basename(file_path)
            tmp_filename = f"{self.script_path}\\tmp\\{uuid.uuid4().hex}_{filename}"
            try:
                try:
                    if os.path.isfile(tmp_filename):
                        os.remove(tmp_filename)
                    with open(tmp_filename, "w") as f:
                        for (k, v) in variables.items():
                            b64_v = base64.b64encode(bytes(str(v), "utf-8")).decode("utf-8")
                            f.write(f"${k} = [Text.Encoding]::Utf8.GetString([Convert]::FromBase64String('{b64_v}'))\r\n")

                        with open(file_path, "r") as f_source:
                            f.writelines(f_source.readlines())
                    self.logger.debug(f"Executing script {tmp_filename}")
                    p = subprocess.Popen(f'powershell.exe -ExecutionPolicy RemoteSigned -file "{tmp_filename}"', stdout=(subprocess.PIPE))
                    (p_out, p_err) = p.communicate()
                    output = f"Script {file_path} completed with exit code {p.returncode}\n"
                    if p_out:
                        output += "Script Output: \n"
                        for line in p_out.splitlines():
                            output += f'\t{line.decode("utf-8")}\n'

                        if p_err:
                            output += "Error Output: \n"
                            for line in p_err.splitlines():
                                output += f'\t{line.decode("utf-8")}\n'

                    if p.returncode == 0 and output:
                        self.logger.debug(output)
                    elif output:
                        self.logger.warning(output)
                except Exception as ex:
                    try:
                        tb = traceback.format_exc()
                        self.logger.error(f"Failure during scirpt execution: {tb}")
                    finally:
                        ex = None
                        del ex

            finally:
                if os.path.isfile(tmp_filename):
                    os.remove(tmp_filename)

        else:
            self.logger.error(f"The target script ({file_path}) does not exist.")

    def screenshot(self, user_name):
        screenshot_dir = self.get_user_profile_dir(user_name)
        if not os.path.isdir(screenshot_dir):
            return
        screenshot_path = os.path.join(screenshot_dir, "kasm_screenshot.png")
        try:
            self.logger.debug("Saving screenshot for %s at %s" % (user_name, screenshot_path))
            self.launch_application_as_user(user_name, os.path.join(os.getcwd(), "screenshot.exe"), '"%s"' % screenshot_path)
        except Exception as e:
            try:
                self.logger.warning("%s. Serving last saved screenshot instead." % str(e))
            finally:
                e = None
                del e

        else:
            if os.path.isfile(screenshot_path):
                return screenshot_path
            return

    def launch_application_as_userParse error at or near `JUMP_LOOP' instruction at offset 160

    def is_file_hidden(self, path):
        attributes = win32api.GetFileAttributes(path)
        return attributes & (win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM)

    def get_user_profile_dir(self, user_name):
        sid = win32security.LookupAccountName(None, user_name)[0]
        if sid is None:
            raise Exception("No user %s found" % user_name)
        sid = win32security.ConvertSidToStringSid(sid)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s" % sid)
        (value, value_type) = winreg.QueryValueEx(key, "ProfileImagePath")
        if value_type == winreg.REG_EXPAND_SZ:
            return value
