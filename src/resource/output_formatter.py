# -*- coding: utf-8 -*-
# pylint: disable=W0105
# pylint: disable=R0912

"""
File for handling the output received from executing the PowerShell / Shell Script.

An object of **Output** will be returned for each response received.

Instance of the **Output** class has the following attributes:

    **output**              --  raw output received from the script

    **formatted_output**    --  list of the formatted output

        same as output, if the output received is one-line, or not in a tabular format

    **columns**             --  list of columns, if the output returned was of table type

    **exit_code**           --  exit code received from the script execution

    **exception**           --  raw exception message, if an exception was raised by the script

    **exception_code**      --  exception error code for the exception raised by the script

    **exception_message**   --  exception error message for the exception raised by the script


The Output class currently supports 2 types of outputs that it can format, and generate simplified
output object for:

    #.  **Tabular** output

        The output from the script which is in the form of a table.

        e.g.:

            COLUMN1     COLUMN2     COLUMN3     COLUMN4

            -------     -------     -------     -------

            value01     value02     value03     value04

            value11     value12     value13     value14

    #.  **String** output

        The output from the script which has both the column and values in the type of a string.

        e.g.:

            @{COLUMN1=value1;COLUMN2=value2;COLUMN3=value3;COLUMN4=value4}


This file has 3 classes: Output, UnixOutput, and WindowsOutput.

Output:         Base class for both UNIX and Windows Output result.

UnixOutput:     Derived class from Output,
which handles output received from executing Shell scripts / commands.

WindowsOutput:  Derived class from Output,
which handles output received from executing PowerShell scripts / commands.


Output:

    __init__()              --      initializes the attributes and properties of the Output class

    _extract_output()       --      extracts the output from the raw output received

    _extract_exception()    --      extracts the exception from the raw error received


WindowsOutput:

    get_rows()              --      returns the list of rows that match the given filter

    get_column()            --      returns the list of values for the given column

    get_columns()           --      returns the list of all values for the given columns

"""

import re

GET_COLUMNS_FROM_TABLE_REGEX = r'(.*?)--'
"""str:     Module level regular expression to get the column names from a PowerShell table.

This regular expression is used to get the column names from a PowerShell table

    COLUMN1     COLUMN2     COLUMN3     COLUMN4

    -------     -------     -------     -------

    value01     value02     value03     value04

    value11     value12     value13     value14

"""

GET_VALUES_FROM_TABLE_REGEX = r'--([-\\\.:\"\#\%\_\(\)\s\w\$\=,]*)'
"""str:     Module level regular expression to get all the values from a PowerShell table.

This regular expression is used to get the values from a PowerShell table

    Column1     Column2     Column3     Column4

    -------     -------     -------     -------

    VALUE01     VALUE02     VALUE03     VALUE04

    VALUE11     VALUE12     VALUE13     VALUE14

"""

GET_COLUMNS_FROM_STRING_REGEX = r'@{(.*?)}'
"""str:     Module level regular expression to column names from a string.

This regular expression is used to get the column names from a PowerShell string of type

    @{COLUMN1=value1;COLUMN2=value2;COLUMN3=value3;COLUMN4=value4}

"""

GET_VALUES_FROM_STRING_REGEX = r'=([\w\d\.\s\(\)-\:\\@]*)'
"""str:     Module level regular expression to get the values in a string.

This regular expression is used to get the values from a PowerShell string of type

    @{column1=VALUE1;column2=VALUE2;column3=VALUE3;column4=VALUE4}

"""

GET_ERROR_CODE_REGEX = r'(\d\w[\d\w]*) '
"""str:     Module level regular expression to get the error code.

This regular expression is used to get the error code from the exception raised
from executing a PowerShell script.

"""


class Output(object):
    """Base class for the handling the output received from executing the script."""

    def __init__(self, exit_code, output, error):
        """Initializes an instance of the Output class, for the output value given.

            Args:
                exit_code   (str)   --  exit code received from the script

                output      (str)   --  raw output received from the script

                error       (str)   --  raw error string received from the script
        """
        self._output = output
        self._formatted_output = []
        self._exit_code = int(exit_code)
        self._exception = error
        self._exception_message = None
        self._exception_code = None
        self._columns = ''
        self._root_keys = ['id', 'name', 'path', 'processname']
        self._extract_output()
        self._extract_exception()

    def _extract_output(self):
        """Parses the output received from the script,
            and updates the value of the class attributes.
        """
        raise NotImplementedError('Method not implemented')

    def _extract_exception(self):
        """Parses the error received from the script,
            and updates the value of the class attributes.
        """
        raise NotImplementedError('Method not implemented')

    @property
    def output(self):
        """Returns the raw output received from the script."""
        return self._output

    @property
    def columns(self):
        """Returns the columns received from the script."""
        return self._columns

    @property
    def exit_code(self):
        """Returns the exit code received from the script"""
        return self._exit_code

    @property
    def formatted_output(self):
        """Returns the output formatted into a list of lists received from the script."""
        return self._formatted_output

    @property
    def exception(self):
        """Returns the raw exception message received from the script."""
        return self._exception

    @property
    def exception_message(self):
        """Returns the exception message received from the script."""
        return self._exception_message

    @property
    def exception_code(self):
        """Returns the exception error code received from the script."""
        return self._exception_code


class UnixOutput(Output):
    """Class for the handling the output received from executing
        the Shell script for UNIX machines."""

    def __repr__(self):
        """Returns the string representation for instance of this class."""
        return "Output class instance for Shell script output"

    def _extract_output(self):
        """Parses the output received from the script,
            and updates the value of the class attributes.
        """
        output = self._output.strip().split('\n')

        if len(output) == 1:
            self._formatted_output = output[0].strip()
        else:
            for value in output:
                self._formatted_output.append(value.strip().split())

    def _extract_exception(self):
        """Parses the error received from the script,
            and updates the value of the class attributes.
        """
        if ': ' in self.exception:
            self._exception_message = self.exception[
                self.exception.rfind(': ') + len(': '):
            ].strip()
        else:
            self._exception_message = self.exception


class WindowsOutput(Output):
    """Class for the handling the output received from executing
        the PowerShell script for Windows machines."""

    def __repr__(self):
        """Returns the string representation for instance of this class."""
        return "Output class instance for PowerShell script output"

    def _extract_output(self):
        """Parses the output received from the script,
            and updates the value of the class attributes.
        """
        output = self._output.strip()
        columns = output.find('--')

        if columns != -1:
            values = re.search(GET_VALUES_FROM_TABLE_REGEX, output)
            columns = output[: columns].strip().split('\n')[-1].split()
            values = values.group(1).strip().split('\n')[1:]
            self._columns = columns

            for value in values:
                value = value.strip().split()

                if len(columns) > len(value):
                    value += [''] * (len(columns) - len(value))

                self._formatted_output.append(value)
        else:
            columns = re.search(GET_COLUMNS_FROM_STRING_REGEX, output)

            if columns and columns.group(1):
                self._columns = re.findall(r'(\w*)=', columns.group(1))
                values = output[:].strip().split('\n')

                if len(values) < 2:
                    values = output[:].strip().split(' @')

                for value in values:
                    value = value.strip()
                    temp = re.findall(GET_VALUES_FROM_STRING_REGEX, value)

                    if temp:
                        self._formatted_output.append(temp)
                    else:
                        self._formatted_output.append(value)
            else:
                self._formatted_output = output.strip()

    def _extract_exception(self):
        """Parses the error received from the script,
            and updates the value of the class attributes.
        """
        if self.exception:
            exception_string = 'HRESULT: '
            exception_message = ''

            if exception_string in self.exception:
                exception_message += self.exception[
                    self.exception.find(exception_string) + len(exception_string):
                    self.exception.find('\n', self.exception.find(exception_string) + 15)
                ]
            elif ': ' in self.exception:
                exception_message = self.exception[: self.exception.find('\r\n')]
                if ': ' in exception_message:
                    exception_message += self.exception[
                        exception_message.find(': ') + len(': '): exception_message.find('. ')
                    ]

            exception_message = exception_message.replace('\n', '').replace('\r', '').strip()

            error_code = re.search(GET_ERROR_CODE_REGEX, exception_message)

            if error_code and error_code.group(1):
                self._exception_code = error_code.group(1)

            self._exception_message = exception_message

    def get_rows(self, keys, match_all_values=False):
        """Filters the output based on the keys and their given values.

            Args:
                keys    (dict)  --  dictionary consisting of the keys as the column name
                                        and the value as the value of the column

                match_all_values    (bool)  --  boolean to specify whether to return the row
                                                    that matches all the values
                                                    or the rows where any of the value matches
                        default: False
                    e.g.:
                        True    -   return the row where all key and values match

                        False   -   return the rows where any of the key or value match

            Returns:
                None    -   if the type of formatted output attribute is not list

                list    -   list consisting of dicts which matched the filter

            Raises:
                Exception   -   if type of keys is not dict
        """
        if not isinstance(self.formatted_output, list):
            return None

        if not isinstance(keys, dict):
            raise Exception('Keys should be a dict')

        output = []

        for key, value in keys.items():
            if key in self.columns:
                for val in self.formatted_output:
                    if val[self.columns.index(key)] == value:
                        temp_dict = {}

                        for column in self.columns:
                            temp_dict[column] = val[self.columns.index(column)]

                        if temp_dict not in output:
                            output.append(temp_dict)

        return_list = []

        if match_all_values is True:
            for out in output:
                for key, value in keys.items():
                    if out[key] != value:
                        break
                else:
                    if out not in return_list:
                        return_list.append(out)

            return return_list

        return output

    def get_column(self, column):
        """Returns the list of value for the column given.

            Args:
                column      (str)   --      column name to get the values of

            Returns:
                None    -   if the type of formatted output attribute is not list

                list    -   list consisting of values for the given column
        """
        if not isinstance(self.formatted_output, list):
            return None

        output = []

        if column in self.columns:
            column_index = self.columns.index(column)
            for value in self.formatted_output:
                output.append(value[column_index])

        return output

    def get_columns(self, columns):
        """Returns the list of values for the columns in the input columns list.

            Args:
                columns     (list)  --  list of columns whose values should be returned

            Returns:
                None    -   if the type of formatted output attribute is not list

                list    -   list consisting of all lists which matched the filter

            Raises:
                Exception   -   if type of columns is not list
        """
        if not isinstance(self.formatted_output, list):
            return None

        if not isinstance(columns, list):
            raise Exception('Columns should be a list')

        output = []

        if columns:
            if len(columns) == 1:
                return self.get_column(columns[0])

            for val in self.formatted_output:
                temp_list = []

                for column in columns:
                    if column in self.columns:
                        column_index = self.columns.index(column)
                        temp_list.append(val[column_index])

                if temp_list:
                    output.append(tuple(temp_list))

        return output
