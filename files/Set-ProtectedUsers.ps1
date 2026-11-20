[CmdletBinding(SupportsShouldProcess)]
param([string]$Server, [string]$DomainSid, [string[]]$ApprovedUsers)

$Ansible.Changed = $false
$domain = Get-ADDomain -Server $Server
if ([int]$domain.DomainMode -lt 6) {
    throw 'Protected Users requires Windows Server 2012 R2 domain functional level or newer.'
}
$group = Get-ADGroup -Identity "$DomainSid-525" -Server $Server
$caller = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$administrators = foreach ($sid in "$DomainSid-519", "$DomainSid-512", "$DomainSid-518",
                                   'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-551') {
    Get-ADGroupMember -Identity $sid -Server $Server -Recursive |
        Where-Object { $_.objectClass -eq 'user' } | ForEach-Object { $_.SID.Value }
}
$updates = foreach ($identity in ($ApprovedUsers | Sort-Object -Unique)) {
    $user = Get-ADUser -Identity $identity -Server $Server -Properties MemberOf
    if ($user.SID.Value -in @($caller, "$DomainSid-500") -or $user.SID.Value -notin $administrators) {
        throw "Identity $identity is outside the approved scope for Protected Users."
    }
    if ($group.DistinguishedName -notin $user.MemberOf) {
        $user
    }
}
$Ansible.Result = @{ accounts = @($updates | ForEach-Object { $_.SamAccountName }) }
foreach ($user in $updates) {
    $Ansible.Changed = $true
    if (-not $Ansible.CheckMode) {
        Add-ADGroupMember -Identity $group -Members $user -Server $Server
    }
}
