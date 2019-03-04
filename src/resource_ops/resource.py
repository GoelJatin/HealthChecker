# -*- coding: utf-8 -*-

"""
@author: Jatin Goel

File for performing operations on a resource.

This file consists of a class: **Resource**, which can connect to the remote machine,
using PowerShell for Windows, and SSH for UNIX.

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


Resource
========

    __new__()               --  pings the resource, to get the OS details, whether
    Windows / UNIX, and initialize the class instance accordingly

    __init__()              --  initializes an instance of the Resource class

    _login()                --  creates a connection to the remote client

    _convert_size()         --  converts the given float size to appropriate size in
    B / KB / MB / GB, etc.

    _get_client_ip()        --  gets the ip address of the machine

    execute()               --  execute an operation on the client

    execute_command()       --  executes a command on the machine

    execute_script()        --  executes a script on the machine

    get_storage_details()   --  returns the storage details of this machine

    join_path()             --  joins the path using the separator based on the OS of the
    Machine

    reboot_client()         --  reboots the machine

    kill_process()          --  terminates a running process on the client machine
    either with the given process name or the process id

    disconnect()            --  disconnects the session with the machine

Attributes
----------

    **os_info**     --  returns the OS details of the client (Windows / UNIX)

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

import getpass
import math
import os
import re
import socket

from .pyping import ping


class Resource:
    """Class for performing operations on a remote client."""

    def __new__(cls, hostname=None, *args, **kwargs):
        """Returns the instance of one of the Subclasses WindowsResource / UnixResource,
            based on the OS details of the remote client.

            Pings the client, and decides the OS based on the TTL value.

            TTL Value: 64 (Linux) / 128 (Windows) / 255 (UNIX)

        """
        if hostname is None:
            hostname = socket.gethostname()

        try:
            response = ping(hostname)
        except ValueError as error:
            if 'too many values to unpack' in str(error).lower():
                raise Exception('Please run the program as Administrator')
            else:
                raise

        # Extract TTL value form the response.output string.
        try:
            ttl = int(
                re.match(r"(.*)ttl=(\d*) .*", response.output[2]).group(2)
            )
        except AttributeError:
            raise Exception(
                'Failed to connect to the resource.\nError: "{0}"'.format(response.output)
            )

        if ttl <= 64:
            from .unix_resource import UnixResource
            return object.__new__(UnixResource)
        elif ttl <= 128:
            from .windows_resource import WindowsResource
            return object.__new__(WindowsResource)
        elif ttl <= 255:
            from .unix_resource import UnixResource
            return object.__new__(UnixResource)
        else:
            raise Exception(
                'Got unexpected TTL value.\nTTL value: "{0}"'.format(ttl)
            )
            # https://social.technet.microsoft.com/Forums/windowsserver/en-US/86e490e2-72be-4e2f-bb45-85fa2f52c876/os-check-for-unix-or-linux?forum=winserverpowershell

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
        self.hostname = hostname
        self.username = username
        self.password = password
        self.credentials_file = None
        self.is_local_machine = False

        self._os_info = None
        self._ip_address = None
        self._os_flavour = None
        self._client = None
        self._script_generator = None
        self._is_connected = None
        temp = []
        self._ssh = None

        if not self.hostname:
            self.hostname = hostname = socket.gethostname()

        for value in socket.gethostbyname_ex(socket.gethostname()):
            if isinstance(value, str):
                # value will have the FQDN of the controller
                # hostname should either match the FQDN, or just the hostname
                # MachineName.Domain.com        //      HostName
                temp.append(
                    hostname.lower() == value.lower() or
                    f'{hostname}.'.lower() in value.lower()
                )
            else:
                temp.append(hostname.lower() in value)

        self.is_local_machine = any(temp)

        del temp

        if self.is_local_machine:
            pass

        elif self.username is not None:
            if self.password is None:
                prompt = 'Please provide the password of the Machine: "{0}", for User: "{1}": '
                self.password = getpass.getpass(
                    prompt.format(self.hostname, self.username)
                )

            self._login()

        else:
            exception = (
                'Client: "{0}" is not a Local Machine. '
                "Please provide the client's username and password"
            ).format(hostname)

            raise Exception(exception)

        self._is_connected = True

        del self.password

    def __repr__(self):
        return (
            f'Resource class instance of Host: [{self.hostname}], '
            f'for User: [{self.username}]'
        )

    def __str__(self):
        return (
            f'Resource class instance of Host: [{self.hostname}], '
            f'for User: [{self.username}]'
        )

    def __enter__(self):
        """Returns the current instance.

        Returns:
            object - the initialized instance referred by self

        """
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        """Disconnects the current session with the resource."""
        self.disconnect()

    def _login(self):
        """Establish connection with the remote Client."""
        raise NotImplementedError('Method Not Implemented by the Child Class')

    @staticmethod
    def _convert_size(input_size):
        """Converts the given float size to appropriate size in B / KB / MB / GB, etc.

        Args:
            size    (float)     --  float value to convert

        Returns:
            str     -   size converted to the specific type (B, KB, MB, GB, etc.)

        """
        if input_size == 0:
            return '0B'

        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(input_size, 1024)))
        power = math.pow(1024, i)
        size = round(input_size / power, 2)
        return '%s %s' % (size, size_name[i])

    def _get_client_ip(self):
        """Gets the ip_address of the resource"""
        raise NotImplementedError('Method Not Implemented by the Child Class')

    @property
    def os_info(self):
        """Returns the OS Info of this resource."""
        return self._os_info

    @property
    def os_flavour(self):
        """Returns the OS flavour of this resource."""
        return self._os_flavour

    @property
    def os_sep(self):
        """Returns the path separator based on the OS of the resource."""
        raise NotImplementedError('Property Not Implemented by the Child Class')

    @property
    def ip_address(self):
        """Returns the IP address of the Resource."""
        if self._ip_address is None:
            self._get_client_ip()

        return self._ip_address

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
        raise NotImplementedError('Method Not Implemented by the Child Class')

    def execute_command(self, command):
        """Executes a command on the resource.

            An instance of the **Output** class is returned.

            Output / Exception messages received from command execution are
            available as the attributes of the class instance.

                output_instance.output              --  raw output returned from the command

                output_instance.formatted_output    --  o/p received after parsing the raw output

                output_instance.exception           --  raw exception message

                output_instance.exception_message   --  parsed exception message from the raw o/p


        Args:
            command     (str)   --  command to be executed on the resource

        Returns:
            object  -   instance of Output class

        """
        raise NotImplementedError('Method Not Implemented by the Child Class')

    def execute_script(self, script_path, data=None):
        """Executes the script at the given script path on the resource.

            Args:
                script_path     (str)   --  PowerShell / UNIX shell/bash script to be
                executed on the resource

                    script should be of same format as other
                    PowerShell / UNIXShell scripts present in:

                        -   PowerShell          -   ..\\\\Scripts\\\\Windows\\\\

                        -   UNIX shell / bash   -   ..\\\\Scripts\\\\UNIX\\\\

                data            (dict)  --  dictionary consisting of the variables and its values,
                to be substituted in the script

            Returns:
                object  -   instance of Output class corresponding to WindowsOutput for
                WindowsResource and UnixOutput for UnixResource

        """
        if data is None:
            data = {}

        self._script_generator.script = script_path
        execute_script = self._script_generator.run(data)

        output = self.execute(execute_script)
        os.unlink(execute_script)

        return output

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
        raise NotImplementedError('Method Not Implemented by the Child Class')

    def join_path(self, path, *args):
        """Joins the paths given in the args list with the given path using the os separator based
            on the OS / Type of the Resource

        Args:
            path    (str)       --  root path to join the rest of the elements to

            *args   (tuple)     --  list of the elements of path to join to the root path

        Returns:
            str     -   full path generated after joining all the elements using the OS sep

        """
        return self.os_sep.join(
            [path.rstrip(self.os_sep)]
            + [arg.rstrip(self.os_sep) for arg in args]
        )

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
        raise NotImplementedError('Method Not Implemented by the Child Class')

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
        raise NotImplementedError('Method Not Implemented by the Child Class')

    def is_healthy(self):
        """Checks if the resource is healthy or not.

            A resource health check can be done using various parameters.

            Here, we'll be doing a very basic check using the below parameters:

                - Network Check:    check if the machine has internet connectivity

                - Disk space check: check whether the resource has at least 1 GB free space
                in C:\\ (for Windows) or /root (for UNIX)

            Args:
                None

            Returns:
                bool:   boolean value specifying whether the resource is healthy or not

        """
        raise NotImplementedError('Method Not Implemented by the Child Class')

    def disconnect(self):
        """Disconnects the current session with the resource.

            Deletes the object's attributes.

            Removes the Credentials File as well, if it was created.

        """
        self._is_connected = False

        try:
            os.unlink(self.credentials_file)
        except (OSError, TypeError):
            # Continue silently, as the file might already have been removed
            pass

        try:
            del self.username
            del self.credentials_file
            del self._client
            del self._script_generator
        except AttributeError:
            pass
