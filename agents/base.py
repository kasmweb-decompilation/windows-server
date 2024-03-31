# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: agents\base.py
# Bytecode version: 3.8.0rc1+ (3413)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import os
import yaml
import requests
import traceback
import socket
import json
import threading
from time import sleep
from abc import abstractmethod

class BaseAgent:

    def __init__(self, config_file, logger):
        self.config_file = config_file
        self.logger = logger
        self.request_timeout = 5
        self.load_configuration()

    @property
    def port(self):
        return self.app_config['port'] if 'port' in self.app_config else 4902

    @property
    def ssl(self):
        if 'ssl' in self.app_config:
            return self.app_config['ssl']
        return True

    @property
    def default_upload_dir(self):
        if 'upload_dir' in self.app_config:
            return self.app_config['upload_dir']

    @property
    def default_download_dir(self):
        if 'download_dir' in self.app_config:
            return self.app_config['download_dir']
        return None

    @property
    def is_multi_user(self):
        if 'multi_user' in self.app_config:
            return self.app_config['multi_user']
        return False

    @property
    def is_user_sso(self):
        if 'user_sso' in self.app_config:
            return self.app_config['user_sso']
        return False

    @property
    def server_id(self):
        if 'server_id' in self.app_config:
            return self.app_config['server_id']
        return None

    @property
    def log_file(self):
        if 'log_file' in self.app_config:
            return self.app_config['log_file']

    @property
    def api_host(self):
        if 'api_host' in self.app_config:
            return self.app_config['api_host']

    @property
    def api_port(self):
        if 'api_port' in self.app_config:
            return self.app_config['api_port']
        return 443

    @property
    def registered(self):
        if 'registered' in self.app_config:
            return self.app_config['registered']
        return False

    @property
    def agent_jwt_token(self):
        if 'agent_jwt_token' in self.app_config:
            return self.app_config['agent_jwt_token']
        return None

    @property
    def server_public_key(self):
        if 'server_public_key' in self.app_config:
            return self.app_config['server_public_key']

    @property
    def server_private_key(self):
        if 'server_private_key' in self.app_config:
            return self.app_config['server_private_key']

    @property
    def script_path(self):
        if 'script_path' in self.app_config:
            return self.app_config['script_path']

    @property
    def hostname(self):
        try:
            return socket.getfqdn()
        except Exception as ex:
            self.logger.error(f'Exception getting fqdn of server: {ex}')

    @property
    def debug(self):
        if 'debug' in self.app_config:
            return self.app_config['debug']
        return False

    def save_configuration(self):
        with open(self.config_file, 'w') as f_yaml_config:
            f_yaml_config.write(yaml.dump(self.app_config, default_flow_style=False))
        self.logger.debug('The configuration has been saved.')

    def load_configuration(self):
        with open(self.config_file, 'r') as f_config_file:
            self.app_config = yaml.safe_load(f_config_file)
        if 'jwt_public_key' in self.app_config and self.app_config['jwt_public_key'] and os.path.isfile(self.app_config['jwt_public_key']):
            with open(self.app_config['jwt_public_key'], 'rb') as file:
                self.public_key = file.read()
        else:
            self.logger.warn('The jwt_public_key file is not defined or does not exist.')

    def ready(self):
        sleep(5)
        if self.registered and self.api_host and self.agent_jwt_token and self.server_id:
            url = f'https://{self.api_host}:{self.api_port}/api/admin/register_component?token={self.agent_jwt_token}'
            try:
                r = requests.post(url, json={'type': 'server_agent', 'target_component': {'id': self.server_id, 'type': 'server_agent', 'hostname': f'{self.hostname}', 'service_status': 'running'}}, verify=False, timeout=5)
                if r.ok and r.status_code == 200:
                    registration_response = r.json()
                    if 'error_message' in registration_response:
                        self.logger.error(f"CheckIn failed: {registration_response['error_message']}")
                    elif 'server_agent' in registration_response:
                        self.logger.debug('Service registered as running.')
                    else:
                        self.logger.error('CheckIn Failed: Invalid response from server.')
                else:
                    self.logger.warning(f'Workspaces server responded with status code {r.status_code}')
            except Exception as ex:
                tb = traceback.format_exc()
                self.logger.error(f'CheckIn failed with an exception: {tb}')

    def startup(self):
        if self.registered and self.api_host and self.agent_jwt_token and self.server_id:
            url = f'https://{self.api_host}:{self.api_port}/api/admin/register_component?token={self.agent_jwt_token}'
            try:
                r = requests.post(url, json={'type': 'server_agent', 'target_component': {'id': self.server_id, 'type': 'server_agent', 'hostname': f'{self.hostname}', 'service_status': 'starting'}}, verify=False, timeout=5)
                if r.ok and r.status_code == 200:
                    registration_response = r.json()
                    if 'error_message' in registration_response:
                        self.logger.error(f"CheckIn failed: {registration_response['error_message']}")
                    else:
                        if 'server_agent' in registration_response:
                            server_agent = registration_response['server_agent']
                            self.app_config['agent_jwt_token'] = server_agent['agent_jwt_token']
                            self.save_configuration()
                            self.logger.debug('JWT token has been refreshed.')
                            self.get_server_file_mappings()
                            self.execute_startup_scripts()
                            return True
                        self.logger.error('CheckIn Failed: Invalid response from server.')
                else:
                    self.logger.warning(f'Workspaces server responded with status code {r.status_code}')
            except Exception as ex:
                tb = traceback.format_exc()
                self.logger.error(f'CheckIn failed with an exception: {tb}')

    def session_start(self, session_details):
        variables = {'user_id': session_details['user_id'], 'username': session_details['username'], 'kasm_id': session_details['kasm_id'], 'jwt_token': session_details['jwt'], 'user_groups': session_details['user_groups'] if 'user_groups' in session_details else '', 'api_host': self.api_host, 'api_port': self.api_port}
        if session_details['create_local_account']:
            self.execute_script(f'{self.script_path}\\builtin\\create_local_account.ps1', variables)
        if 'persistent_profile' in session_details and session_details['persistent_profile'] == 's3':
            self.execute_script(f'{self.script_path}\\builtin\\load_persistent_profile.ps1', variables)
        if self.is_user_sso:
            if 'file_mappings' in session_details:
                for k, v in session_details['file_mappings'].items():
                    self.process_file_mapping(v, session_details['username'])
            if 'storage_mappings' in session_details:
                for k, v in session_details['storage_mappings'].items():
                    storage_map_vars = variables.copy()
                    storage_map_vars['storage_mapping'] = json.dumps({k: v})
                    self.execute_script(f'{self.script_path}\\builtin\\map_storage.ps1', storage_map_vars)
        if self.script_path and os.path.isdir(self.script_path):
            for filename in os.listdir(f'{self.script_path}\\session_start'):
                if '_tmp.ps1' not in filename:
                    self.execute_script(f'{self.script_path}\\session_start\\{filename}', variables)
        self.set_session_state(session_details['kasm_id'], 'running', session_details['jwt'])
        threading.Thread(target=self.delayed_screenshot, args=(session_details['username'], 20)).start()

    def session_end(self, session_details):
        variables = {'user_id': session_details['user_id'], 'username': session_details['username'], 'kasm_id': session_details['kasm_id'], 'jwt_token': session_details['jwt'], 'api_host': self.api_host, 'api_port': self.api_port}
        self.execute_script(f'{self.script_path}\\builtin\\logoff_user.ps1', variables)
        if self.is_user_sso:
            if 'file_mappings' in session_details:
                for k, v in session_details['file_mappings'].items():
                    filename = self.replace_path_variables(v['destination'], session_details['username'])
                    homepath = self.get_user_profile_dir(session_details['username'])
                    if not self.is_multi_user or filename.startswith(homepath):
                        self.clean_file_mapping(v, session_details['username'])
                    else:
                        self.logger.debug(f'Skipping deletion of {filename}, from file mapping.')
            if 'storage_mappings' in session_details:
                for k, v in session_details['storage_mappings'].items():
                    storage_map_vars = variables.copy()
                    storage_map_vars['storage_mapping'] = json.dumps({k: v})
                    self.execute_script(f'{self.script_path}\\builtin\\unmap_storage.ps1', storage_map_vars)
        if 'persistent_profile' in session_details and session_details['persistent_profile'] == 's3':
            self.execute_script(f'{self.script_path}\\builtin\\save_persistent_profile.ps1', variables)
        if self.script_path and os.path.isdir(self.script_path):
            for filename in os.listdir(f'{self.script_path}\\session_end'):
                if '_tmp.ps1' not in filename:
                    self.execute_script(f'{self.script_path}\\session_end\\{filename}', variables)
        self.set_session_state(session_details['kasm_id'], 'destroyed', session_details['jwt'])

    def set_session_state(self, kasm_id, state, jwt_token, progress=0, message=None):
        if self.api_host:
            payload = {'kasm_id': kasm_id, 'status': state, 'status_progress': progress}
            if message:
                payload['status_message'] = message
            if state == 'destroyed':
                payload.pop('status')
                payload['destroyed'] = True
            url = f'https://{self.api_host}:{self.api_port}/api/set_kasm_session_status?token={jwt_token}'
            try:
                r = requests.post(url, json=payload, verify=False, timeout=5)
                if r.ok and r.status_code == 200:
                    self.logger.debug(f'Successfully set status of session ({kasm_id})')
                else:
                    self.logger.debug(f'Failed to set status of session ({kasm_id})')
            except Exception as ex:
                tb = traceback.format_exc()
                self.logger.error(f'File mapping failed with an exception: {tb}')

    def execute_startup_scripts(self):
        variables = {'server_id': self.server_id, 'jwt': self.agent_jwt_token, 'api_host': self.api_host, 'api_port': self.api_port}
        if self.script_path and os.path.isdir(self.script_path):
            for filename in os.listdir(f'{self.script_path}\\service_startup'):
                if '_tmp.ps1' not in filename:
                    self.execute_script(f'{self.script_path}\\service_startup\\{filename}', variables)

    @abstractmethod
    def execute_script(self, filename, variables):
        """
        Execute the target script, create the varables in the script prior to execution.
        """
        return

    def get_server_file_mappings(self):
        if self.agent_jwt_token and self.api_host:
            url = f'https://{self.api_host}:{self.api_port}/api/admin/get_server_file_mappings?token={self.agent_jwt_token}'
            try:
                r = requests.get(url, verify=False, timeout=5)
                if r.ok and r.status_code == 200:
                    response = r.json()
                    if 'file_mappings' in response:
                        for k, v in response['file_mappings'].items():
                            file_map = v
                            self.logger.debug(f'Processing file mapping {k}')
                            self.process_file_mapping(file_map, user_name=None)
                    if 'storage_mappings' in response:
                        for k, v in response['file_mappings'].items():
                            self.logger.debug(f'Proccessing storage mapping {k}')
                            variables = {'server_id': self.server_id, 'jwt': self.agent_jwt_token, 'api_host': self.api_host, 'api_port': self.api_port, 'storage_mapping': json.dumps(v)}
                            self.execute_script(f'{self.script_path}\\builtin\\map_storage.ps1', variables)
                else:
                    self.logger.error(f'Retrieval of file mappings failed with status code: {r.status_code}')
            except Exception as ex:
                tb = traceback.format_exc()
                self.logger.error(f'File mapping failed with an exception: {tb}')

    @abstractmethod
    def process_file_mapping(self, file_map):
        """
        Downloads file content for a file_map definition, wrties to file, and changes file permissions and ownership
        """
        return

    @abstractmethod
    def get_user_downloads_dir(self, user_name):
        """
        Return the download path for the specified user on the system
        """
        return

    @abstractmethod
    def screenshot(self, user_name):
        """
        Returns a screenshot of the specified user's session
        """
        return

    @abstractmethod
    def launch_application_as_user(self, user_name, application_name, application_args):
        """
        Launch another application as the specified user
        """
        return

    @abstractmethod
    def replace_path_variables(self, path):
        """
        Replace variables in a path, such as HOMEPATH in windows or HOME in Linux
        """
        return

    def delayed_screenshot(self, user_name, delay_seconds):
        sleep(delay_seconds)
        self.screenshot(user_name)

    def clean_file_mapping(self, file_map, user_name):
        local_filename = self.replace_path_variables(file_map['destination'], user_name)
        if os.path.isfile(local_filename):
            os.remove(local_filename)
            self.logger.debug(f'File removed: {local_filename}')

    def register(self, token, server_id, host, port=443, auto_configure=True):
        url = f'https://{host}:{port}/api/admin/register_component'
        try:
            r = requests.post(url, json={'type': 'server_agent', 'registration_token': token, 'target_component': {'id': server_id, 'type': 'server_agent', 'auto_configure': auto_configure, 'hostname': f'{self.hostname}', 'service_status': 'registering'}}, verify=False, timeout=5)
            if r.ok and r.status_code == 200:
                registration_response = r.json()
                if 'error_message' in registration_response:
                    self.logger.error(f"Registration failed: {registration_response['error_message']}")
                else:
                    if 'server_agent' in registration_response:
                        server_agent = registration_response['server_agent']
                        self.app_config['server_id'] = server_id
                        self.app_config['api_host'] = host
                        self.app_config['api_port'] = port
                        self.app_config['registered'] = True
                        self.app_config['agent_jwt_token'] = server_agent['agent_jwt_token']
                        if 'multi_user' in server_agent:
                            self.app_config['multi_user'] = server_agent['multi_user']
                        if 'user_sso' in server_agent:
                            self.app_config['user_sso'] = server_agent['user_sso']
                        if 'server_cert' in server_agent and 'server_key' in server_agent:
                            with open(self.app_config['server_public_key'], 'w') as f_server_cert:
                                f_server_cert.write(server_agent['server_cert'])
                            with open(self.app_config['server_private_key'], 'w') as f_server_key:
                                f_server_key.write(server_agent['server_key'])
                        if 'public_jwt_cert' in server_agent:
                            with open(self.app_config['jwt_public_key'], 'w') as f_jwt_key:
                                f_jwt_key.write(server_agent['public_jwt_cert'])
                        self.save_configuration()
                        self.load_configuration()
                        return True
                    self.logger.error('Registration Failed: Invalid response from server.')
            else:
                self.logger.warning(f'Workspaces server responded with status code {r.status_code}')
        except Exception as ex:
            tb = traceback.format_exc()
            self.logger.error(f'Registration failed with an exception: {tb}')