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

try {
    Write-Host "Logging off user $username"
    Update-SessionStatus -PercentComplete 1 -Message "Logging user off server." -Status "deleting"
    $sessions = quser
    #$sessionIds = ($sessions -split ' +')[2]
    $sessionDeletedID = $null

    $sessions | ForEach-Object {
        if ($_ -match '^ ?(?<Name>\S+) +(\S+ +)?(?<SessionId>\d+)') {
            
            if ($Matches.Name -eq $username) { 
                $sessionID = $Matches.SessionID
                Write-Host "Logging off user $username, session ID $sessionID"
                logoff $sessionID
            }
        }
    }
} catch {
    if ($_.Exception.Message -match 'No user exists') {
             Write-Host "The user is not logged in."
     } else {
         $e = $_.Exception
         "An error occured attempting to logout user $username`: $e.Message" | Write-Warning
         Exit 1
     }
}

if (!$sessionID) {
    Write-Host "Session for user $username not found."
}