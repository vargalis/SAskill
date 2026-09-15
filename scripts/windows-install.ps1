param([switch]$Resume)
$ErrorActionPreference = 'Stop'
$pluginSource = Split-Path -Parent $PSScriptRoot
$workspaceRoot = Split-Path -Parent (Split-Path -Parent $pluginSource)
$candidates = @((Join-Path $env:USERPROFILE 'plugins/.runtimes/agent-for-secureaccess/Scripts/python.exe'), (Join-Path $workspaceRoot 'work/secureaccess-venv/Scripts/python.exe'))
$runtime = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($runtime) {
    & $runtime (Join-Path $PSScriptRoot 'install_local.py')
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) { & $pythonCommand.Source (Join-Path $PSScriptRoot 'install_local.py') } else {
        & py -3 (Join-Path $PSScriptRoot 'install_local.py')
    }
}
if ($LASTEXITCODE -ne 0) { throw 'Portable plugin installation failed' }
