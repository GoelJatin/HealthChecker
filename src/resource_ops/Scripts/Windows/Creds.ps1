# Read arguments from Command Line, and create a credentials object
# Required Arguments:
#   ComputerName    --  name of the computer / machine to connect to
#   Username        --  username to use to login to the computer
#   Password        --  password for the above user

param (
    [string] $ComputerName = $null,
    [string] $Username = $null,
    $Password = $null
)

Try {
    # Convert the plain-text password to secure string
    $Password = ConvertTo-SecureString -String $Password -AsPlainText -Force

    # Create credentials object using the Username, and Password provided
    $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password

    # Export the Credentials object to a XML file
    $Credentials | Export-Clixml ($ComputerName.ToString() + '.xml')
} Catch {
    return $_.ToString()
}

return ($ComputerName.ToString() + '.xml')
