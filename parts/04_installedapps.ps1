function Get-InstalledApplications {
[cmdletbinding()]
param(
  [Parameter(DontShow)]
  $keys = @('','\Wow6432Node')
)
  foreach($key in $keys) {
      try {
        $apps = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall").GetSubKeyNames()
      }
      catch { 
        Continue 
      }
    foreach($app in $apps) {
        $program = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine',$env:COMPUTERNAME).OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall\$app")
        $name = $program.GetValue('DisplayName')
      if($name) {
        New-Object -TypeName PSObject -Property ([Ordered]@{       
              Computername = $env:COMPUTERNAME
              Software = $name 
              Version = $program.GetValue("DisplayVersion")
              Publisher = $program.GetValue("Publisher")
              InstallDate = $program.GetValue("InstallDate")
              UninstallString = $program.GetValue("UninstallString")
              Architecture = $(if($key -eq '\wow6432node') {'x86'}else{'x64'})
              Path = $program.Name
        })
      }
    }
  }
}
