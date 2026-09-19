param(
  [Parameter(Mandatory=$true)][string]$User,
  [Parameter(Mandatory=$true)][string]$Domain,
  [Parameter(Mandatory=$true)][string]$Password,
  [int]$WaitSeconds = 12
)
$source = @'
using System;
using System.Runtime.InteropServices;
public static class AutoUpdateToken {
  [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool ImpersonateLoggedOnUser(IntPtr token);
  [DllImport("advapi32.dll", SetLastError=true)] public static extern bool RevertToSelf();
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
}
'@
Add-Type $source
$token=[IntPtr]::Zero
try {
  if(-not [AutoUpdateToken]::LogonUser($User,$Domain,$Password,2,0,[ref]$token)){throw "LogonUser=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"}
  if(-not [AutoUpdateToken]::ImpersonateLoggedOnUser($token)){throw "Impersonate=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"}
  "identity=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) level=$([Security.Principal.WindowsIdentity]::GetCurrent().ImpersonationLevel)"
  $auto=New-Object -ComObject Microsoft.Update.AutoUpdate
  'autoupdate=created'
  "serviceEnabled=$($auto.ServiceEnabled)"
  $auto.DetectNow()
  'detectNow=returned'
  Start-Sleep -Seconds $WaitSeconds
  'observation_wait=complete'
} finally {
  [void][AutoUpdateToken]::RevertToSelf()
  if($token -ne [IntPtr]::Zero){[void][AutoUpdateToken]::CloseHandle($token)}
}
