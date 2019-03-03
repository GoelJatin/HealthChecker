# -*- coding: utf-8 -*-

"""
@author: Jatin Goel

File for performing operations on a resource.

This file consists of a class: **UnixResource**, which can connect to the remote
UNIX Machine, using SSH via Paramiko.

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


UnixResource
============

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
import time
import subprocess

import paramiko

from .resource import Resource
from .script_generator import ScriptGenerator
from .output_formatter import UnixOutput


class UnixResource(Resource):
    """Class for performing operations on a UNIX client."""

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

        self._script_generator = ScriptGenerator()
        self._os_info = "UNIX"
        self._os_flavour = self.get_uname_output()

    def _login(self):
        """Establish connection with the remote Client."""
        self._client = paramiko.SSHClient()

        self._client.load_system_host_keys()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self._client.connect(self.hostname, username=self.username, password=self.password)
        except paramiko.AuthenticationException:
            raise Exception('Authentication Failed. Invalid credentials provided.')

    def _get_client_ip(self):
        """Gets the ip_address of the resource"""
        cmd = "hostname -I"
        cmd_output = self.execute_command(cmd)
        ip_addresses = cmd_output.output.split(" ")
        self._ip_address = ip_addresses[0]

    @property
    def os_sep(self):
        """Returns the path separator based on the OS of the resource."""
        return "/"

    # Execution
    def execute(self, script, script_arguments=None):
        """Execute the script remotely on a client using the credentials provided.

        Args:
            script              (str)   --  path of the script file to execute on the
            remote client

            script_arguments    (str)   --  arguments to be passed to the script.

                default: None

        Returns:
            object  -   instance of Output class

        """
        script_arguments = '' if script_arguments is None else script_arguments

        if self.is_local_machine:
            if os.path.isfile(script):
                script = f'bash {script} {script_arguments}'.strip()
            else:
                script = '{0} {1}'.format(script, script_arguments).strip()

            process = subprocess.run(
                script,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            return UnixOutput(process.returncode, process.stdout.decode(), process.stderr.decode())
        else:
            remove_temp_file = False

            if os.path.isfile(script):
                script_base_name = "{0}{1}".format(
                    str(id(self)), os.path.basename(script))
                sftp = self._client.open_sftp()
                sftp.put(
                    os.path.abspath(script),
                    '/tmp/{0}.temp'.format(script_base_name)
                )
                sftp.close()
                time.sleep(0.25)
                self._client.exec_command(
                    "tr -d '\r' < /tmp/{0}.temp > /tmp/{0}; rm -rf /tmp/{0}.temp".format(
                        script_base_name)
                )
                time.sleep(0.25)
                script = f'bash /tmp/{script_base_name} {script_arguments}'
                remove_temp_file = True
            else:
                script = '%s %s' % (script, script_arguments)

            __, stdout, stderr = self._client.exec_command(script)

            output = stdout.read()
            error = stderr.read()

            while True:
                while stdout.channel.recv_ready():
                    output = '%s%s' % (output, stdout.read())

                while stderr.channel.recv_ready():
                    error = '%s%s' % (error, stderr.read())

                if stdout.channel.exit_status_ready():
                    break

            exit_code = stdout.channel.recv_exit_status()

            if remove_temp_file is True:
                self._client.exec_command(
                    'rm -rf /tmp/{0}'.format(script_base_name))

            return UnixOutput(exit_code, output.decode(), error.decode())

    def execute_command(self, command):
        """Executes a command on the resource.

            An instance of the **UnixOutput** class is returned.

            Output / Exception messages received from command execution are
            available as the attributes of the class instance.

                output_instance.output              --  raw output returned from the command

                output_instance.formatted_output    --  o/p received after parsing the raw output

                output_instance.exception           --  raw exception message

                output_instance.exception_message   --  parsed exception message from the raw o/p


        Args:
            command     (str)   --  command to be executed on the resource

        Returns:
            object  -   instance of UnixOutput class

        """
        return self.execute(command)

    def get_uname_output(self, options="-s"):
        """Gets the uname output from the machine

            Args:
                options     (str)   --  options to uname command

                    default: "-s"

            Returns:
                str    -   uname output

            Raises:
                Exception:
                    if any error occurred while getting the uname output.

        """
        uname_cmd = r'uname  {0}'.format(options)
        output = self.execute(uname_cmd)

        if output.exit_code != 0:
            raise Exception(
                "Error occurred while getting uname output. "
                + output.output
                + output.exception
            )
        else:
            return output.formatted_output

    def get_storage_details(self, root=False):
        """Gets the details of the Storage on the Client.
            Returns the details of all paths, if root is set to the default value False.
            If root is set to True, it returns the details of only `/`

            Args:
                root    (bool)  --  boolean flag to specify whether to return details of all paths,
                                        or the details of the path mounted on root(/)

            Returns:
                dict - dictionary consisting the details of the storage on the client (in MB)

                {
                    'total': size_in_MB,

                    'available': size_in_MB,

                    'drive': {
                        'total': size_in_MB,

                        'available': size_in_MB,

                    }

                }

        """
        command = 'df -Pk'

        if root is True:
            command += ' .'

        output = self.execute(command)

        storage_dict = {
            'total': 0,
            'available': 0,
            'mountpoint': "/"
        }

        for value in output.formatted_output:
            try:
                drive_name = value[0]
                total_space = round(float(value[1]) / 1024.0, 2)
                free_space = round(float(value[3]) / 1024.0, 2)
                mount_point = str(value[5])

                storage_dict[drive_name] = {
                    'total': total_space,
                    'available': free_space,
                    'mountpoint': mount_point
                }

                storage_dict['total'] += total_space
                storage_dict['available'] += free_space
                storage_dict['mountpoint'] += mount_point
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
                object  -   instance of the Output class

            Raises:
                Exception:
                    if failed to reboot the client

        """
        output = self.execute_command('reboot')

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
                object  -   instance of the Output class

            Raises:
                Exception:
                    if neither the process name nor the process id is given

                    if failed to kill the process

        """
        if process_name:
            command = f'pkill -f {process_name}'
        elif process_id:
            command = f'kill -9 {process_id}'
        else:
            raise Exception('Please provide either the process Name or the process ID')

        output = self.execute_command(command)

        if output.exception_message:
            raise Exception(output.exception_code, output.exception_message)
        elif output.exception:
            raise Exception(output.exception_code, output.exception)

        return output

    def is_healthy(self):
        """Checks if the resource is healthy or not.

            A resource health check can be done using various parameters.

            Here, we'll be doing a very basic check using the below parameters:

                - Network Check:    check if the machine has internet connectivity

                - Disk space check: check whether the resource has at least
                **1 GB** free space in /root

            Args:
                None

            Returns:
                bool:   boolean value specifying whether the resource is healthy or not

        """
        try:
            # check network if the resource is local
            if self.is_local_machine:
                output = self.execute_command("ping 0.0.0.0 -c 4")

                if output.exception:
                    return False

            # otherwise, for remote machines, network check is done as part of getting the storage details
            output = self.get_storage_details(True)

            return output.get('available', 0) >= 1024

        # get storage details raises exception if the machine is not reachable
        except Exception:
            return False

    def disconnect(self):
        """Disconnects the current session with the resource.

            Deletes the object's attributes.

            Removes the Credentials File as well, if it was created.

        """
        if self._client:
            self._client.close()

        super().disconnect()
