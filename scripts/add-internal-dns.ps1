# Run this on any domain-joined Windows machine or DC
$securePass = ConvertTo-SecureString "Hermes1234!@#$" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("_Hermes", $securePass)

Invoke-Command -ComputerName dc1.witschger.home -Credential $cred -ScriptBlock {
    Add-DnsServerResourceRecordA -Name "ddns" -ZoneName "witschger.home" -IPv4Address "192.168.10.234"
    Write-Host "DNS record ddns.witschger.home -> 192.168.10.234 added successfully" -ForegroundColor Green
}