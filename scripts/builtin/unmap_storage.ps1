#requires -version 2
<#
.SYNOPSIS
Ingests a pid file to clean up running rclone processes in this session

.NOTES
  Version: 1.0
  Author: Kasm Technologies
#>

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$profile_dir = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' ProfilesDirectory
$user_home = "$profile_dir\$username"
$user_kasm_dir = "$user_home\.kasm_tmp"
$pid_file = "$user_kasm_dir\.map_storage_pids"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Loop through pid file and kill them
ForEach ($rclone_pid in Get-Content $pid_file) {
  Stop-Process -Force -Id $rclone_pid
}

# Remove pid file
Remove-Item -Path $pid_file -Force
