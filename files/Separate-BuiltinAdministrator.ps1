[CmdletBinding(SupportsShouldProcess)]
param([string]$Server, [string]$DomainSid, [bool]$RemovePolicyCreatorMembership)

$Ansible.Changed = $false
$user = Get-ADUser -Identity "$DomainSid-500" -Server $Server -Properties MemberOf, PrimaryGroupID
$domainAdmins = Get-ADGroup -Identity "$DomainSid-512" -Server $Server
if (($user.PrimaryGroupID -ne 512) -and ($domainAdmins.DistinguishedName -notin $user.MemberOf)) {
    throw 'The built-in Administrator is not a direct Domain Admin. Review recovery access before tier separation.'
}
$groupRids = @(519, 518)
if ($RemovePolicyCreatorMembership) {
    $groupRids += 520
}
$remove = foreach ($rid in $groupRids) {
    $group = Get-ADGroup -Identity "$DomainSid-$rid" -Server $Server
    if ($group.DistinguishedName -in $user.MemberOf) {
        $group
    }
}
$Ansible.Result = @{ remove_from = @($remove | ForEach-Object { $_.Name }) }
foreach ($group in $remove) {
    $Ansible.Changed = $true
    if (-not $Ansible.CheckMode) {
        Remove-ADGroupMember -Identity $group -Members $user -Server $Server -Confirm:$false
    }
}
