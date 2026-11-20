[CmdletBinding(SupportsShouldProcess)]
param([string]$Server, [string]$DomainSid, [string[]]$AdditionalGroups)

$Ansible.Changed = $false
$groups = @("$DomainSid-512", "$DomainSid-518", "$DomainSid-519", "$DomainSid-520",
            'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550',
            'S-1-5-32-551', 'S-1-5-32-557') + $AdditionalGroups
$users = foreach ($identity in $groups) {
    $group = Get-ADGroup -Identity $identity -Server $Server
    Get-ADGroupMember -Identity $group -Server $Server -Recursive |
        Where-Object { $_.objectClass -eq 'user' } | ForEach-Object { $_.DistinguishedName }
    if ($group.SID.AccountDomainSid -and $group.SID.AccountDomainSid.Value -eq $DomainSid) {
        $rid = [int]($group.SID.Value.Split('-')[-1])
        Get-ADUser -Filter { PrimaryGroupID -eq $rid } -Server $Server |
            ForEach-Object { $_.DistinguishedName }
    }
}
$updates = foreach ($dn in ($users | Sort-Object -Unique)) {
    Get-ADUser -Identity $dn -Server $Server -Properties AccountNotDelegated |
        Where-Object { -not $_.AccountNotDelegated }
}
$Ansible.Result = @{ accounts = @($updates | ForEach-Object { $_.SamAccountName }) }
foreach ($user in $updates) {
    $Ansible.Changed = $true
    if (-not $Ansible.CheckMode) {
        Set-ADAccountControl -Identity $user -Server $Server -AccountNotDelegated $true
    }
}
