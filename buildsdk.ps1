#
# my-devices SDK build script
# 
# Usage:
# ------
# buildwin.ps1 [-poco_base    dir]
#              [-tool         msbuild]
#              [-vs_version   150 | 140 | 120 | 110 | 100 | 90]
#              [-action       build | rebuild | clean]
#              [-linkmode     shared | static_mt | static_md | all]
#              [-config       release | debug | both]
#              [-platform     Win32 | x64 | WinCE | WEC2013]

[CmdletBinding()]
Param
(
  [Parameter()]
  [string] $poco_base,
  
  [Parameter()]
  [ValidateSet('msbuild')]
  [string] $tool = 'msbuild',

  [Parameter()]
  [ValidateSet(90, 100, 110, 120, 140, 150)]
  [int] $vs_version,

  [Parameter()]
  [ValidateSet('build', 'rebuild', 'clean')]
  [string] $action = 'build',

  [Parameter()]
  [ValidateSet('shared', 'static_mt', 'static_md', 'all')]
  [string] $linkmode = 'shared',

  [Parameter()]
  [ValidateSet('release', 'debug', 'both')]
  [string] $config = 'release',

  [Parameter()]
  [ValidateSet('Win32', 'x64', 'WinCE', 'WEC2013')]
  [string] $platform = 'x64',

  [switch] $help
)


function Add-Env-Var([string] $lib, [string] $var)
{
  if ((${Env:$var} -eq $null) -or (-not ${Env:$var}.Contains(${Env:$lib_$var"})))
  {
    $libvar = "$lib" + "_" + "$var"
    $envvar = [Environment]::GetEnvironmentVariable($libvar, "Process")
    [Environment]::SetEnvironmentVariable($var, $envvar, "Process")
  }
  
}


function Set-Environment
{
  $loc = Get-Location
  if ($poco_base -eq '') { $script:poco_base = "$loc\poco" }

  if ($vs_version -eq 0)
  {
    if     ($Env:VS150COMNTOOLS -ne '') { $script:vs_version = 150 }
    elseif ($Env:VS140COMNTOOLS -ne '') { $script:vs_version = 140 }
    elseif ($Env:VS120COMNTOOLS -ne '') { $script:vs_version = 120 }
    elseif ($Env:VS110COMNTOOLS -ne '') { $script:vs_version = 110 }
    elseif ($Env:VS100COMNTOOLS -ne '') { $script:vs_version = 100 }
    elseif ($Env:VS90COMNTOOLS  -ne '') { $script:vs_version = 90 }
    else
    {
      Write-Host 'Visual Studio not found, exiting.'
      Exit
    }
  }

  if (-Not $Env:PATH.Contains("$script:poco_base\bin64;$script:poco_base\bin;")) 
  { $Env:PATH = "$script:poco_base\bin64;$script:poco_base\bin;$Env:PATH" }

  $vsct = "VS$($vs_version)COMNTOOLS"
  $vsdir = (Get-Item Env:$vsct).Value
  $Command = ''
  $CommandArg = ''
  if ($platform -eq 'x64')
  {
    $CommandArg = "amd64"
  }
  else
  {
    $CommandArg = "x86"
  }
  if ($vs_version -ge 150)
  {
    $Command = "$($vsdir)..\..\VC\Auxiliary\Build\vcvarsall.bat"
  }
  else
  {
    $Command = "$($vsdir)..\..\VC\vcvarsall.bat"
  }
  $tempFile = [IO.Path]::GetTempFileName()
  cmd /c " `"$Command`" $CommandArg && set > `"$tempFile`" "
  Get-Content $tempFile | Foreach-Object {
    if($_ -match "^(.*?)=(.*)$")
    {
      Set-Content "Env:$($matches[1])" $matches[2]
    }
  }
  Remove-Item $tempFile
}


function Process-Input
{
  if ($help -eq $true)
  {
    Write-Host 'Usage:'
    Write-Host '------'
    Write-Host 'buildwin.ps1 [-poco_base    dir]'
    Write-Host '             [-tool         msbuild | devenv]'
    Write-Host '             [-vs_version   150 | 140 | 120 | 110 | 100 | 90]'
    Write-Host '             [-action       build | rebuild | clean]'
    Write-Host '             [-linkmode     shared | static_mt | static_md | all]'
    Write-Host '             [-config       release | debug | both]'
    Write-Host '             [-platform     Win32 | x64 | WinCE | WEC2013]'

    Exit
  }
  else
  { 
    Set-Environment

    Write-Host "my-devices SDK build configuration:"
    Write-Host "--------------------"
    Write-Host "Poco Base:     $poco_base"
    Write-Host "Version:       $vs_version"
    Write-Host "Action:        $action"
    Write-Host "Link Mode:     $linkmode"
    Write-Host "Configuration: $config"
    Write-Host "Platform:      $platform"

    # NB: this won't work in PowerShell ISE
    Write-Host "Press Ctrl-C to exit or any other key to continue ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp")
  }
}


function Build-MSBuild([string] $vsProject)
{
  Write-Host "Build-MSBuild ==> $vsProject"
  if ($linkmode -eq 'all')
  {
    $linkModeArr = 'shared', 'static_mt', 'static_md'

    foreach ($mode in $linkModeArr)
    {
      if ($config -eq 'both')
      {
        $configArr = 'release', 'debug'
        foreach ($cfg in $configArr)
        {
          $projectConfig = "$cfg"
          $projectConfig += "_$mode"
          Invoke-Expression "msbuild $vsProject /t:$action /p:Configuration=$projectConfig /p:Platform=$platform /p:useenv=true"
        }
      }
      else #config
      {
        $projectConfig = "$config"
        $projectConfig += "_$mode"
        Invoke-Expression "msbuild $vsProject /t:$action /p:Configuration=$projectConfig /p:Platform=$platform /p:useenv=true"
      }
    }
  }
  else #linkmode
  {
    if ($config -eq 'both')
    {
      $configArr = 'release', 'debug'
      foreach ($cfg in $configArr)
      {
        $projectConfig = "$cfg"
        $projectConfig += "_$linkmode"
        Invoke-Expression "msbuild $vsProject /t:$action /p:Configuration=$projectConfig /p:Platform=$platform /p:useenv=true"
      }
    }
    else #config
    {
      $projectConfig = "$config"
      $projectConfig += "_$linkmode"
      Invoke-Expression "msbuild $vsProject /t:$action /p:Configuration=$projectConfig /p:Platform=$platform /p:useenv=true"
    }
  }
}


function Build-POCO
{
  $omit = @"
"
          CppUnit/WinTestRunner;NetSSL_Win;Data;Data/SQLite;Data/ODBC;Data/MySQL;Zip;
          PageCompiler;PageCompiler/File2Page;PDF;CppParser;MongoDB;Redis;PocoDoc;ProGen;
"
"@

  $cmd = "&$poco_base\buildwin.ps1 -poco_base $poco_base -tool $tool -vs_version $vs_version -action $action -linkmode $linkmode -config $config -platform $platform -omit $omit"
  Write-Host $cmd
  Invoke-Expression -Command "$cmd"
  if ($LastExitCode -ne 0) { Exit $LastExitCode }
  #Invoke-Expression -Command "$poco_base\buildwin.ps1 -poco_base $poco_base -tool $tool -vs_version $vs_version -action $action -config $config -platform $platform -omit $omit"
}


function Build
{
  Process-Input
  Build-POCO

  if ($vs_version -lt 100) { $extension = 'vcproj'  }
  else                     { $extension = 'vcxproj' }

  $platformName = ''
  if ($platform -eq 'x64')       { $platformName = '_x64' }
  elseif ($platform -eq 'WinCE') { $platformName = '_CE' }

  $loc = Get-Location
  Get-Content "$loc\components" | Foreach-Object {

    $component = $_
    $componentDir = $_.Replace("/", "\")
    $componentArr = $_.split('/')
    $componentName = $componentArr[$componentArr.Length - 1]
    $suffix = "_vs$vs_version"

    $vsProject = "$componentDir\$componentName$($platformName)$($suffix).$($extension)"

    if (!(Test-Path -Path $vsProject)) # when VS project name is not same as directory name
    {
      $vsProject = "$componentDir$($platformName)$($suffix).$($extension)"
      if (!(Test-Path -Path $vsProject)) # not found
      {
        Write-Host "+------------------------------------------------------------------"
        Write-Host "| VS project $vsProject not found, skipping."
        Write-Host "+------------------------------------------------------------------"
        Return # since Foreach-Object is a function, this is actually loop "continue"
      }
    }
    
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Write-Host "| Building $vsProject"
    Write-Host "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"

    if ($tool -eq "msbuild") { Build-MSBuild $vsProject }
#   else                     { Build-Devenv $vsProject}
  }
}

Build
