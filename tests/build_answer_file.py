#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Generate the ADDomain V3R8 answers from procedures and optional reviewed evidence."""

import argparse
import base64
from datetime import date
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'files' / 'answer_files'
BENCHMARK = ROOT / 'files' / 'U_Active_Directory_Domain_V3R8_STIG.zip'
XCCDF = ('U_Active_Directory_Domain_V3R8_Manual_STIG/'
         'U_Active_Directory_Domain_STIG_V3R8_Manual-xccdf.xml')
NA_ALLOWED = {'V-243473', 'V-243495', 'V-243498', 'V-243499', 'V-243500'}
HOST_CHECK = """\
$ErrorActionPreference = 'Stop'
if ($env:COMPUTERNAME -ine '{hostname}') {{ return $false }}
$domain = Get-ADDomain -Server localhost
if ($domain.DomainSID.Value -ne '{domain_sid}') {{ return $false }}
"""
SMART_CARD_CHECK = """\
if ($domain.DomainMode -notin @('Windows2016Domain', 'Windows2025Domain') -or
    -not $domain.PublicKeyRequiredPasswordRolling) { return $false }
$users = @(Get-ADUser -Server localhost -Filter {SmartcardLogonRequired -eq $true} -ResultSetSize 1)
return $users.Count -eq 0
"""
DC_DISCOVERY = "$controllers = @(Get-ADDomainController -Filter * -Server localhost)\n"
SINGLE_DC_CHECK = DC_DISCOVERY + """
return ($controllers.Count -eq 1 -and $controllers[0].HostName -eq $domain.PDCEmulator -and
        $controllers[0].Name -eq $env:COMPUTERNAME)
"""
DSRM_CHECK = DC_DISCOVERY + """
if ($controllers.Count -ne 1 -or $controllers[0].Name -ne $env:COMPUTERNAME) { return $false }
$events = @(Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4794
    StartTime = (Get-Date).AddYears(-1)
    Keywords = [long][System.Diagnostics.Eventing.Reader.StandardEventKeywords]::AuditSuccess
} -MaxEvents 1 -ErrorAction SilentlyContinue)
if ($events.Count -ne 1) { return $false }
return @{Valid = $true; Results = "A successful DSRM password reset was recorded at $($events[0].TimeCreated.ToUniversalTime().ToString('o'))."}
"""
AUDIT_CHECK = """\
$output = & auditpol.exe /get /category:* /r
if ($LASTEXITCODE -ne 0) { return $false }
$rows = $output | ConvertFrom-Csv
foreach ($name in 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations') {
    $match = @($rows | Where-Object Subcategory -eq $name)
    if ($match.Count -ne 1 -or $match[0].'Inclusion Setting' -ne 'Success and Failure') {
        return $false
    }
}
return $true
""".strip()


LIVE_CHECKS = {
    'V-243476': (SMART_CARD_CHECK, 'NF', 'Rolling is enabled and no smart-card-required user accounts were found.'),
    'V-243479': (DSRM_CHECK, 'NF', 'Security event 4794 records a successful reset within one year on the sole DC.'),
    'V-243495': (SINGLE_DC_CHECK, 'NA', 'The assessed domain has exactly one DC and therefore no multi-enclave DC placement.'),
    'V-243498': (SINGLE_DC_CHECK, 'NA', 'The assessed domain has exactly one DC and therefore no multi-enclave DC placement.'),
}


def approved_evidence(control, entry):
    allowed = {'NF', 'O', 'NA'} if control in NA_ALLOWED else {'NF', 'O'}
    if entry.get('status') not in allowed:
        raise ValueError(f'{control}: invalid status for this control')
    for field in ('reviewer', 'reference', 'decision'):
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            raise ValueError(f'{control}: missing {field}')
    reviewed = date.fromisoformat(entry['reviewed'])
    expires = date.fromisoformat(entry['expires'])
    if reviewed > date.today() or expires <= reviewed:
        raise ValueError(f'{control}: invalid review interval')
    payload = json.dumps({field: entry[field] for field in
                          ('reviewer', 'reference', 'decision', 'reviewed', 'expires')}, ensure_ascii=False).encode()
    if len(payload) > 2000:
        raise ValueError(f'{control}: reference detailed evidence separately')
    encoded = base64.b64encode(payload).decode()
    return f"""\
$record = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')) | ConvertFrom-Json
if ([datetime]::UtcNow.Date -gt [datetime]::ParseExact($record.expires, 'yyyy-MM-dd', $null)) {{
    return $false
}}
return @{{
    Valid = $true
    Results = "Reviewed by $($record.reviewer) on $($record.reviewed). Evidence $($record.reference). $($record.decision)"
}}
"""


def add_answer(root, rule_id, hostname, native, script, true_status, true_comment, false_status, false_comment):
    vuln = ET.SubElement(root, 'Vuln', ID=rule_id)
    key = ET.SubElement(vuln, 'AnswerKey', Name='DEFAULT')
    answer = ET.SubElement(key, 'Answer', Index='1', ExpectedStatus=native, Hostname=hostname)
    for name, value in (
        ('ValidationCode', script), ('ValidTrueStatus', true_status),
        ('ValidTrueComment', true_comment), ('ValidFalseStatus', false_status),
        ('ValidFalseComment', false_comment),
    ):
        ET.SubElement(answer, name).text = value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--computer-name', required=True, help='Windows computer name of the development PDC')
    parser.add_argument('--domain-sid', required=True, help='Domain SID of the development forest')
    parser.add_argument('--benchmark', type=Path, default=BENCHMARK, help='DISA ADDomain V3R8 ZIP')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?', args.computer_name):
        parser.error('--computer-name must be a 1–15 character Windows computer name')
    if not re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+', args.domain_sid):
        parser.error('--domain-sid must be an AD domain SID')
    hostname = args.computer_name.upper()
    host_check = HOST_CHECK.format(hostname=hostname, domain_sid=args.domain_sid)
    evidence = json.loads(args.evidence.read_text()) if args.evidence else {}

    try:
        with ZipFile(args.benchmark) as archive:
            benchmark = ET.fromstring(archive.read(XCCDF))
    except (FileNotFoundError, KeyError):
        parser.error(f'Provide the DISA ADDomain V3R8 ZIP with --benchmark. Checked {args.benchmark}')
    rules = {group.attrib['id']: group.find('{*}Rule').attrib['id'] for group in benchmark.findall('{*}Group')}
    sections = re.split(r'^## (V-\d+)\s*\n', (DIRECTORY / 'SecurityPlanProcedures.md').read_text(), flags=re.M)
    procedures = dict(zip(sections[1::2], sections[2::2], strict=True))
    audit = procedures.pop('V-269097').strip()
    if set(evidence) - procedures.keys():
        parser.error('Evidence contains a control without a manual review entry')

    root = ET.Element('STIGComments', Name='ADDomain')
    for control, text in procedures.items():
        entry = evidence.get(control)
        procedure = text.strip()
        true_status = 'NR'
        review_procedure = procedure
        script = 'return $false'
        if entry is not None:
            script = host_check + approved_evidence(control, entry)
            true_status = entry['status']
        elif control in LIVE_CHECKS:
            script, true_status, result = LIVE_CHECKS[control]
            script = host_check + script
            procedure = result + ' ' + procedure
        add_answer(
            root, rules[control], hostname, 'NR', script, true_status, procedure,
            'NR', 'Current approved evidence is required. ' + review_procedure,
        )
    add_answer(root, rules['V-269097'], hostname, 'NF', host_check + AUDIT_CHECK, 'NF', audit,
               'O', 'The independent auditpol query did not confirm both required settings.')
    ET.indent(root, space='  ')
    args.output.write_text(ET.tostring(root, encoding='unicode', xml_declaration=True) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
