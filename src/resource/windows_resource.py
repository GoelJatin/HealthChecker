# -*- coding: utf-8 -*-

"""
@author: Jatin Goel

File for performing operations on a resource.

This file consists of a class: **Resource**, which can connect to the remote
Windows Machine, using PowerShell Remoting.

The instance of this class can be used to perform various operations on a machine, like,

    #.  Check if a Directory Exists or not
    #.  Create a new Directory
    #.  Rename a File / Folder
    #.  Remove an existing Directory
    #.  Get the Size of a File / Folder
    #.  Check if a Registry exists or not
    #.  Add / Update a Registry Key / Value
    #.  Get the Value of a Registry Key
    #.  Delete a Registry Key / Value
    #.  Compare the contents of 2 Files / Folders


WindowsResource
===============

    __init__()              --  initializes an instance of the Resource class

    _login()                --  creates a connection to the remote client

    _get_client_ip()        --  gets the ip address of the machine

    execute()               --  execute an operation on the client

    execute_command()       --  executes a command on the machine

    get_storage_details()   --  returns the storage details of this machine

    reboot_client()         --  reboots the machine

    kill_process()          --  terminates a running process on the client machine
    either with the given process name or the process id

    disconnect()            --  disconnects the session with the machine

Attributes
----------

    **os_info**     --  returns the OS details of the client

    **os_sep**      --  returns the path separator based on the OS of the Machine

    **ip_address**  --  returns IP address of the machine


Usage
-----

    -   For creating an object of any resource, i.e., Windows / UNIX, the user should only
        initialize an object of the Resource class, which internally takes care of detecting the OS
        of the machine, and initializes the appropriate object.

    -   Resource class object can be initialized in 2 ways:

        -   If the resource is a Remote Machine:

            >>> resource = Resource(hostname, username, password)

        -   If the resource is the Local Machine:

            >>> resource = Resource(local_machine_hostname)

                        OR

            >>> resource = Resource()


"""

import os
import sys
import subprocess

import paramiko

from .resource import Resource
from .script_generator import ScriptGenerator
from .output_formatter import WindowsOutput


from .scripts import (
    CREDENTIALS,
    EXECUTE_COMMAND
)


class WindowsResource(Resource):
    """Class for performing operations on a remote client."""

    def __init__(self, hostname=None, username=None, password=None):
        """Initializes instance of the Resource class.

        Args:
            hostname        (str)       --  name / ip address of the client to connect to

                if hostname is not provided, then the Resource object for the local machine
                will be created

                default:    None

            username            (str)       --  username for the client to connect to

                default:    None

            password            (str)       --  password for the above specified user

                default:    None

        """
        super().__init__(hostname, username, password)

        if self.is_local_machine:
            process = subprocess.run(
                'powershell.exe Get-ExecutionPolicy',
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE
            )
            self._execution_policy = process.stdout.decode()

            # Ensure the PowerShell execution policy is set to Remote Signed
            __ = subprocess.run(
                'powershell.exe Set-ExecutionPolicy RemoteSigned -Force',
                stdin=subprocess.PIPE
            )

        self._script_generator = ScriptGenerator(self.hostname, self.credentials_file)

        # check if the credentials given are correct or not
        output = self.execute_command('Get-PSDrive')
        exception = output.exception.lower().replace('\r\n', '')
        del output

        if 'access is denied' in exception:
            # if the operation raised exception, call disconnect, and raise
            # Exception
            self.disconnect()
            raise Exception('Authentication Failed. Invalid credentials provided.')
        elif 'client cannot connect to the destination' in exception:
            # if the operation raised exception, call disconnect, and raise
            # Exception
            self.disconnect()
            raise Exception(
                'Failed to connect to the Machine. Please ensure the services are running'
            )
        else:
            del exception

        self._os_info = "WINDOWS"

    def __repr__(self):
        return (
            f'Resource class instance of Host: [{self.hostname}], '
            f'for User: [{self.username}]'
        )

    def _login(self):
        """Generates the Credentials File for the machine,
            to use for performing operations on the remote client.

            Raises:
                Exception:
                    if an error was returned on the error stream

        """
        # if the controller machine is Linux, try connection to Windows Machine
        # using SSH
        if 'linux' in sys.platform.lower():
            self._ssh = paramiko.SSHClient()
            self._ssh.load_system_host_keys()
            self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                self._ssh.connect(self.hostname, username=self.username, password=self.password)
            except paramiko.AuthenticationException:
                raise Exception('Authentication Failed. Invalid credentials provided.')

        # otherwise use PowerShell for all communications
        else:
            # Replace any white space ( ) in the PowerShell file path with ' '
            # e.g.; Original Script path:
            # "C:\\Program Files\\HealthChecker\\src\\resource\\Scripts\\Windows\\Creds.ps1"

            # Corrected Path:
            # "C:\\Program' 'Files\\HealthChecker\\src\\resource\\Scripts\\Windows\\Creds.ps1"
            process = subprocess.Popen(
                [
                    'powershell',
                    CREDENTIALS.replace(" ", "' '"),
                    self.hostname,
                    self.username,
                    self.password
                ],
                # HACK:the code gets hung at the process.communicate() call, if stdin is not included
                # this issue is yet to be looked into on why this happens
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )

            output, error = process.communicate()

            if error.decode():
                raise Exception(f'Failed to create credentials object.\nError: "{error.decode()}"')

            self.credentials_file = os.path.abspath(output.strip().decode())

    def _get_client_ip(self):
        """Gets the ip_address of the resource"""
        cmd = f"Test-Connection -ComputerName {self.hostname} -Count 1 | Select-Object IPV4Address"
        cmd_output = self.execute_command(cmd)
        self._ip_address = str(cmd_output.formatted_output[0][0])

    @property
    def os_sep(self):
        """Returns the path separator based on the OS of the resource."""
        return "\\"

    # Execution
    def execute(self, script, script_arguments=None):
        """Execute the script remotely on a client using the credentials provided.

            Args:
                script              (str)   --  path of the script file to execute on the
                remote client

                script_arguments    (str)   --  arguments to be passed to the script.

                    default: None

            Returns:
                object  -   instance of WindowsOutput class

        """
        if 'linux' in sys.platform.lower():
            sftp = self._ssh.open_sftp()
            file = script.rsplit('/')[-1]
            destination = 'c:/temp/'
            if'temp' not in sftp.listdir('c:'):
                sftp.mkdir(destination)
            destination = destination + file
            sftp.put(script, destination)
            command = 'powershell -File {0}'.format(destination)
            _, stdout, stderr = self._ssh.exec_command(command)
            output = stdout.read()
            error = stderr.read()
            if stderr.channel.status_event._flag:
                exit_code = 0
            else:
                exit_code = 1
            if file in sftp.listdir('c:/temp/'):
                sftp.remove(destination)
            return WindowsOutput(exit_code, output.decode(), error.decode())

        else:
            # Replace any white space ( ) in the PowerShell file path with ' '
            # e.g.; Original Script path:
            # "C:\\Program Files\\HealthChecker\\src\\resource\\Scripts\\Windows\\Creds.ps1"

            # Corrected Path:
            # "C:\\Program' 'Files\\HealthChecker\\src\\resource\\Scripts\\Windows\\Creds.ps1"
            process = subprocess.Popen(
                [
                    'powershell',
                    script.replace(" ", "' '")
                ],
                # HACK:the code gets hung at the process.communicate() call, if stdin is not included
                # this issue is yet to be looked into on why this happens
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            output, error = process.communicate()
            return WindowsOutput(process.returncode, output.decode(), error.decode())

    def execute_command(self, command):
        """Executes a PowerShell command on the resource.

            An instance of the **WindowsOutput** class is returned.

            Output / Exception messages received from command execution are
            available as the attributes of the class instance.

                output_instance.output              --  raw output returned from the command

                output_instance.formatted_output    --  o/p received after parsing the raw output

                output_instance.exception           --  raw exception message

                output_instance.exception_message   --  parsed exception message from the raw o/p


        Args:
            command     (str)   --  PowerShell command to be executed on the machine

        Returns:
            object  -   instance of WindowsOutput class

        """
        self._script_generator.script = EXECUTE_COMMAND
        data = {
            'command': command
        }
        execute_command_script = self._script_generator.run(data)

        output = self.execute(execute_command_script)
        os.unlink(execute_command_script)

        return output

    def get_storage_details(self):
        """Gets the details of the Storage on the Client.

        Returns:
            dict    -   dictionary consisting the details of the storage on the client (in MB)

            {
                'total': size_in_MB,

                'available': size_in_MB,

                'drive': {

                    'total': size_in_MB,

                    'available': size_in_MB,
                }
            }

        Raises:
            Exception(Exception_Code, Exception_Message):
                if failed to get the storage details for the machine

        """
        output = self.execute_command('Get-PSDrive')

        if output.exception_message:
            raise Exception(output.exception_code, output.exception_message)
        elif output.exception:
            raise Exception(output.exception_code, output.exception)

        storage_dict = {
            'total': 0,
            'available': 0
        }

        for value in output.formatted_output:
            try:
                drive_name = value[0]
                used_space = round(float(value[1]) * 1024.0, 2)
                free_space = round(float(value[2]) * 1024.0, 2)
                total_space = round(free_space + used_space, 2)

                storage_dict[drive_name] = {
                    'total': total_space,
                    'available': free_space
                }

                storage_dict['total'] += total_space
                storage_dict['available'] += free_space
            except ValueError:
                continue

        return storage_dict

    def reboot_client(self):
        """Reboots the Resource.

            Please NOTE that the connectivity will go down in this scenario, and the Resource
            class may not be able to re-establish the connection to the Machine.

            In such cases, the user will have to initialize the Resource class instance again.

            Args:
                None

            Returns:
                object  -   instance of the WindowsOutput class

            Raises:
                Exception:
                    if failed to reboot the client

        """
        output = self.execute_command('Restart-Computer -Force')

        if output.exception_message:
            raise Exception(output.exception_code, output.exception_message)
        elif output.exception:
            raise Exception(output.exception_code, output.exception)

        return output

    def kill_process(self, process_name=None, process_id=None):
        """Terminates a running process on the client machine either with the given
            process name or the process id.

            Args:
                process_name    (str)   --  name of the process to be terminate

                process_id      (str)   --  ID of the process ID to be terminated

            Returns:
                object  -   instance of the WindowsOutput class

            Raises:
                Exception:
                    if neither the process name nor the process id is given

                    if failed to kill the process

        """
        if process_name:
            command = f"Stop-Process -Name {process_name} -Force"
        elif process_id:
            command = f"Stop-Process -Id {process_id} -Force"
        else:
            raise Exception('Please provide either the process Name or the process ID')

        output = self.execute_command(command)

        if output.exception_message:
            raise Exception(output.exception_code, output.exception_message)
        elif output.exception:
            raise Exception(output.exception_code, output.exception)

        return output

    def disconnect(self):
        if self.is_local_machine:
            __ = subprocess.run(
                f'powershell.exe Set-ExecutionPolicy {self._execution_policy} -Force',
                stdin=subprocess.PIPE
            )

        super().disconnect()
