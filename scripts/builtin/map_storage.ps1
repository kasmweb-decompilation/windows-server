#requires -version 3
<#
.SYNOPSIS
Ingests a storage mapping configuration from Kasm Workspaces, writes out an rclone configuration if needed, and mounts the desired mapping if required.

.NOTES
  Version: 1.0
  Author: Kasm Technologies
#>


#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Write-Log {
  param($message)
  $DateFormat = "%m/%d/%Y %H:%M:%S"
  Write-Host ("[{0}] {1}" -F (Get-Date -UFormat $DateFormat), $message)
}

Function Run-Mounts {
  param($mapping)
  # Run mounts defined in storage mapping
  foreach ($key in ($mapping | Get-Member -MemberType NoteProperty).name) {
    if ( $mapping.$key.volume_config.driver_opts.type -eq "s3") {
      $arguments = @(
        "mount",
        (":s3:" + $mapping.$key.volume_config.driver_opts.path),
        ($user_home + "\Desktop\" + $key.Trim('/')),
        "--s3-provider", $mapping.$key.volume_config.driver_opts."s3-provider",
        "--s3-access-key-id", $mapping.$key.volume_config.driver_opts."s3-access-key-id",
        "--s3-secret-access-key", $mapping.$key.volume_config.driver_opts."s3-secret-access-key",
        "--s3-region", $mapping.$key.volume_config.driver_opts."s3-region",
        "-o", "UserName=`"${username}`"",
        "--file-perms", "0600",
        "--dir-perms", "0700",
        "-o", "FileSecurity=`"D:P(A;;FA;;;OW)`"",
        "--cache-dir", "`"${cache_dir}`"",
        "--vfs-cache-mode", "writes"
      )
      if ( $mapping.$key.mount_config.read_only ) { $arguments += "--read-only" }
      $s3_process = Start-Process -PassThru -WindowStyle hidden -FilePath $rclone_bin -ArgumentList $arguments
      Add-Content -Path $pid_file -Value $s3_process.Id
    }
    if ( $mapping.$key.volume_config.driver_opts.type -eq "dropbox") {
      $token = $mapping.$key.volume_config.driver_opts."dropbox-token" | ConvertTo-JSON
      $arguments = @(
        "mount",
        (":dropbox:"),
        ($user_home + "\Desktop\" + $key.Trim('/')),
        "--dropbox-client-id", $mapping.$key.volume_config.driver_opts."dropbox-client-id",
        "--dropbox-client-secret", $mapping.$key.volume_config.driver_opts."dropbox-client-secret",
        "--dropbox-token", $token,
        "-o", "UserName=`"${username}`"",
        "--file-perms", "0600",
        "--dir-perms", "0700",
        "-o", "FileSecurity=`"D:P(A;;FA;;;OW)`"",
        "--cache-dir", "`"${cache_dir}`"",
        "--vfs-cache-mode", "writes"
      )
      if ( $mapping.$key.mount_config.read_only ) { $arguments += "--read-only" }
      $dropbox_process = Start-Process -PassThru -WindowStyle hidden -FilePath $rclone_bin -ArgumentList $arguments
      Add-Content -Path $pid_file -Value $dropbox_process.Id
    }
    if ( $mapping.$key.volume_config.driver_opts.type -eq "onedrive") {
      $token = $mapping.$key.volume_config.driver_opts."onedrive-token" | ConvertTo-JSON
      $arguments = @(
        "mount",
        (":onedrive:"),
        ($user_home + "\Desktop\" + $key.Trim('/')),
        "--onedrive-client-id", $mapping.$key.volume_config.driver_opts."onedrive-client-id",
        "--onedrive-client-secret", $mapping.$key.volume_config.driver_opts."onedrive-client-secret",
        "--onedrive-drive-id", $mapping.$key.volume_config.driver_opts."onedrive-drive-id",
        "--onedrive-drive-type", $mapping.$key.volume_config.driver_opts."onedrive-drive-type",
        "--onedrive-token", $token,
        "-o", "UserName=`"${username}`"",
        "--file-perms", "0600",
        "--dir-perms", "0700",
        "-o", "FileSecurity=`"D:P(A;;FA;;;OW)`"",
        "--cache-dir", "`"${cache_dir}`"",
        "--vfs-cache-mode", "writes"
      )
      if ( $mapping.$key.mount_config.read_only ) { $arguments += "--read-only" }
      $onedrive_process = Start-Process -PassThru -WindowStyle hidden -FilePath $rclone_bin -ArgumentList $arguments
      Add-Content -Path $pid_file -Value $onedrive_process.Id
    }
    if ( $mapping.$key.volume_config.driver_opts.type -eq "webdav") {
      $arguments = @(
        "mount",
        (":webdav:"),
        ($user_home + "\Desktop\" + $key.Trim('/')),
        "--webdav-url", $mapping.$key.volume_config.driver_opts."webdav-url",
        "--webdav-vendor", $mapping.$key.volume_config.driver_opts."webdav-vendor",
        "--webdav-user", $mapping.$key.volume_config.driver_opts."webdav-user",
        "--webdav-pass", $mapping.$key.volume_config.driver_opts."webdav-pass",
        "-o", "UserName=`"${username}`"",
        "--file-perms", "0600",
        "--dir-perms", "0700",
        "-o", "FileSecurity=`"D:P(A;;FA;;;OW)`"",
        "--cache-dir", "`"${cache_dir}`"",
        "--vfs-cache-mode", "writes"
      )
      if ( $mapping.$key.mount_config.read_only ) { $arguments += "--read-only" }
      $webdav_process = Start-Process -PassThru -WindowStyle hidden -FilePath $rclone_bin -ArgumentList $arguments
      Add-Content -Path $pid_file -Value $webdav_process.Id
    }
    if ( $mapping.$key.volume_config.driver_opts.type -eq "drive") {
      $token = $mapping.$key.volume_config.driver_opts."drive-token" | ConvertTo-JSON
      $arguments = @(
        "mount",
        (":drive:"),
        ($user_home + "\Desktop\" + $key.Trim('/')),
        "--drive-client-id", $mapping.$key.volume_config.driver_opts."drive-client-id",
        "--drive-client-secret", $mapping.$key.volume_config.driver_opts."drive-client-secret",
        "--drive-token", $token,
        "-o", "UserName=`"${username}`"",
        "--file-perms", "0600",
        "--dir-perms", "0700",
        "-o", "FileSecurity=`"D:P(A;;FA;;;OW)`"",
        "--cache-dir", "`"${cache_dir}`"",
        "--vfs-cache-mode", "writes"
      )
      if ( $mapping.$key.mount_config.read_only ) { $arguments += "--read-only" }
      $drive_process = Start-Process -PassThru -WindowStyle hidden -FilePath $rclone_bin -ArgumentList $arguments
      Add-Content -Path $pid_file -Value $drive_process.Id
    }
  }
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$profile_dir = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' ProfilesDirectory
$user_home = "$profile_dir\$username"
$user_kasm_dir = "$user_home\.kasm_tmp"
$cache_dir = "$user_kasm_dir\cache"
$ProgressPreference = 'SilentlyContinue'
$storage_dict = $storage_mapping | convertfrom-json
$rclone_bin = "C:\Program Files\Kasm\bin\rclone.exe"
$pid_file = "$user_kasm_dir\.map_storage_pids"

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Create user kasm dir
if (-Not (Test-Path $user_kasm_dir)) {
	Write-Host "Creating kasm user directory: $user_kasm_dir"
	$KasmTempDir = New-Item -ItemType Directory -Path "$user_kasm_dir"
	$KasmTempDir.attributes='Hidden'
}

# Create Cache dir
if (-Not (Test-Path $cache_dir)) {
	Write-Host "Creating cache directory: $cache_dir"
	$KasmTempDir = New-Item -ItemType Directory -Path "$cache_dir"
}

# Run mount commands for remotes
Run-Mounts($storage_dict)
