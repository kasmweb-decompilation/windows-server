Add-Type -AssemblyName System.Web.Extensions

add-type @" 
			using System.Net; 
			using System.Security.Cryptography.X509Certificates; 

			public class NoSSLCheckPolicy : ICertificatePolicy { 
				public NoSSLCheckPolicy() {} 
				public bool CheckValidationResult( 
					ServicePoint sPoint, X509Certificate cert, 
					WebRequest wRequest, int certProb) { 
					return true; 
				} 
			}
"@ 
[System.Net.ServicePointManager]::CertificatePolicy = new-object NoSSLCheckPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Update-SessionStatus{
	param(
	[Parameter(Mandatory=$true)] [Int]$PercentComplete,
	[Parameter(Mandatory=$true)] [String]$Message,
	[Parameter(Mandatory=$false)] [String]$Status="starting",
	[Parameter(Mandatory=$false)] [bool]$Destroy=$false
	)
	
	try {
		$params = @{"status"=$Status;
			"status_message"=$Message;
			"status_progress"=$PercentComplete;
		}
		$url = "https://$api_host`:$api_port/api/set_kasm_session_status?token=$jwt_token"
		
		Invoke-WebRequest -Uri $url -Method POST -TimeoutSec 15 -UseBasicParsing -ContentType "application/json" -Body ($params|ConvertTo-Json)
	}
	catch {
		$e = $_.Exception
		"An error occured attempting to set the session status: $e.Message" | Write-Warning
		Exit 1
	}
}

Update-SessionStatus -PercentComplete 1 -Message "Creating session on Server." -Status "starting"

try {
    $url = "https://$api_host`:$api_port/api/set_kasm_session_credential?token=$jwt_token"
    Write-Host "Sending request for credentials to https://$api_host`:$api_port/api/set_kasm_session_credential"
    $connection_password=(Invoke-WebRequest -Uri $url -Method GET -TimeoutSec 15 -UseBasicParsing).Content
}
catch {
    $e = $_.Exception
    "An error occured attempting to retrieve user credentials: $e.Message" | Write-Warning
    Exit 1
}

# Create Local User
$pass = ConvertTo-SecureString -String $connection_password -AsPlainText -Force
try {
    Write-Host "Searching for $username in LocalUser DataBase"
    $ObjLocalUser = Get-LocalUser $username
}
catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
    "User $username was not found, creating user" | Write-Warning
}
catch {
    "An unspecifed error occured" | Write-Error
    Exit 1 # Stop Powershell! 
}

if ($ObjLocalUser) {
    Set-LocalUser -Name $username -Password $pass
    Write-Host "Credentials updated for $username"
} else {
    New-LocalUser -Name $username -Description 'Programatically generated Kasm user account' -Password $pass -PasswordNeverExpires -AccountNeverExpires | Add-LocalGroupMember -Group "Remote Desktop Users"
    Write-Host "User account created for $username"
}

# The following block is an example where users in the built-in Kasm Administrator group are added to the Local Admin group in windows.
# $user_groups variable contains an array of Group IDs
#Write-Host "User Groups $user_groups"
#if ($user_groups.Contains("e3ce6d01-4732-4ff7-8dcd-2db5538c8519")) {
#	Get-LocalUser $username | Add-LocalGroupMember -Group administrators
#	Write-Host "Added $username to Administrators Groups."
#}

# Existing user, can exit at this point
if ($ObjLocalUser) {
	Exit 0
}

# Create User Profile if new user
$methodName = 'UserEnvCP'
$script:nativeMethods = @();

function Register-NativeMethod
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [string]$dll,
 
        # Param2 help description
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [string]
        $methodSignature
    )
 
    $script:nativeMethods += [PSCustomObject]@{ Dll = $dll; Signature = $methodSignature; }
}

function Add-NativeMethods
{
    [CmdletBinding()]
    [Alias()]
    [OutputType([int])]
    Param($typeName = 'NativeMethods')
 
    $nativeMethodsCode = $script:nativeMethods | ForEach-Object { "
        [DllImport(`"$($_.Dll)`")]
        public static extern $($_.Signature);
    " }
 
    Add-Type @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices;
        public static class $typeName {
            $nativeMethodsCode
        }
"@
}

Register-NativeMethod "userenv.dll" "int CreateProfile([MarshalAs(UnmanagedType.LPWStr)] string pszUserSid,`
  [MarshalAs(UnmanagedType.LPWStr)] string pszUserName,`
  [Out][MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszProfilePath, uint cchProfilePath)";

Add-NativeMethods -typeName $MethodName;

$localUser = New-Object System.Security.Principal.NTAccount("$username");
$userSID = $localUser.Translate([System.Security.Principal.SecurityIdentifier]);
$sb = new-object System.Text.StringBuilder(260);
$pathLen = $sb.Capacity;

Write-Host "Creating user profile for $username";
try
{
    [UserEnvCP]::CreateProfile($userSID.Value, $username, $sb, $pathLen) | Out-Null;
}
catch
{
    Write-Error $_.Exception.Message;
    break;
}