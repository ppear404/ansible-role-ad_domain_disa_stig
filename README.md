# Active Directory Domain DISA STIG Ansible role

An Ansible role for selected controls in the DISA Active Directory Domain STIG V3R8. It targets the writable PDC emulator in an isolated, single-domain development forest with one domain controller. Preflight verifies the controller hostname, DNS domain, domain SID, and forest topology before remediation.

| Control | Role behavior |
| --- | --- |
| V-243466, V-243467 | Keeps the RID-500 account in Domain Admins and removes its direct Enterprise Admins and Schema Admins memberships. Both tags select the same task, which also removes direct Group Policy Creator Owners membership unless V-243487 is excepted. Review indirect membership and document account assignments. |
| V-243470 | Marks privileged user accounts as sensitive and non-delegable. Use `ad_domain_stig_additional_privileged_groups` for site-specific groups. |
| V-243476 | Enables smart-card password rolling at the Windows Server 2016 and 2025 domain functional levels. Verify the 60-day rotation requirement using resultant policies and rotation records. |
| V-243477 | Adds explicitly approved personnel accounts to Protected Users. Enrollment defaults to an empty list. Test administrative access with Kerberos and retain the RID-500 recovery account before enrolling users. |
| V-243478 | Clears unconstrained delegation on non-DC computer accounts. |
| V-269097 | Enables Success and Failure auditing for Kerberos Authentication Service and Kerberos Service Ticket Operations. If a GPO governs these settings, configure both flags in the authorized DC GPO and verify after computer policy refresh. |

The [control map](tests/control-map.md) lists benchmark Rule IDs and assessment coverage. The [security-plan procedures](files/answer_files/SecurityPlanProcedures.md) describe the evidence to collect for manual review.

## Set up a lab

Use Ansible Core 2.16 or newer, the Windows ActiveDirectory PowerShell module, and an elevated Windows session on the lab controller. The sample inventory uses PowerShell Remoting with Kerberos over HTTPS. Install the controller dependencies for your chosen transport, configure its authentication and certificate trust, and keep credentials in your local vault or credential store. [Ansible Windows connection documentation](https://docs.ansible.com/projects/ansible/latest/os_guide/windows_winrm.html)

```bash
ansible-galaxy collection install -r requirements.yml
cp inventory.example.yml inventory.yml
```

In the private `inventory.yml`, set `ansible_host` to the lab controller and set `ad_domain_stig_dev_domain` and `ad_domain_stig_dev_domain_sid` to the DNS domain and domain SID. The example plays select `pdc`. For a differently named controller, update the inventory alias, both play host patterns, and `ad_domain_stig_dev_host` to its short Windows computer name.

Set `ad_domain_stig_protected_users` only for approved personnel accounts. Use `ad_domain_stig_exceptions` for documented control exceptions. Either V-243466 or V-243467 skips the shared membership task. Retest access affected by membership changes in a fresh logon session.

## Develop, test, deploy, validate

Install Evaluate-STIG 1.2610.1 on the lab controller before running assessments. The assessment play expects `C:\Tools\Evaluate-STIG\Evaluate-STIG.ps1` by default. Set `ad_domain_eval_script` with `-e` if the installation path differs. The play prints control IDs and statuses and saves the full checklist under `.local/evidence/pdc/`. Keep that evidence private.

```bash
ansible-playbook -i inventory.yml tests/test.yml --syntax-check
ansible-playbook -i inventory.yml tests/test.yml --limit pdc --list-hosts
ansible-playbook -i inventory.yml tests/evaluate.yml --limit pdc
ansible-playbook -i inventory.yml tests/test.yml --limit pdc --check --diff
ansible-playbook -i inventory.yml tests/test.yml --limit pdc
ansible-playbook -i inventory.yml tests/test.yml --limit pdc  # Verify changed=0
ansible-playbook -i inventory.yml tests/evaluate.yml --limit pdc
```

For a targeted assessment, pass `-e '{"ad_domain_eval_controls":["V-269097"]}'` to the assessment play. After deployment, refresh computer policy and verify that both Kerberos audit subcategories still report Success and Failure.

## Generate a private answer file

Use Python 3.10 or newer and the official Active Directory Domain V3R8 STIG ZIP. Supply the actual short computer name and domain SID from your private inventory. The values below are examples. [DoD Cyber Exchange STIG library](https://www.cyber.mil/stigs/compilations/)

```bash
mkdir -p .local
python3 tests/build_answer_file.py \
  --benchmark /path/to/U_Active_Directory_Domain_V3R8_STIG.zip \
  --computer-name PDC --domain-sid S-1-5-21-100-200-300 \
  --output .local/ADDomain_AnswerFile.xml
ansible-playbook -i inventory.yml tests/evaluate.yml --limit pdc \
  -e ad_domain_eval_use_answers=true
```

For manual controls, add `--evidence /path/to/reviewed-evidence.json` when generating the XML. The file is a JSON object keyed by Vulnerability ID. Each entry has `status` (`NF`, `O`, or `NA` where allowed), `reviewer`, `reference`, `decision`, `reviewed`, and `expires`. Use ISO dates for the review and expiry. Each reviewed answer applies only to a native Not Reviewed result on the specified computer and domain, through its expiry date. Keep both the evidence JSON and generated XML private.

## License

The role and its documentation are distributed under [MIT No Attribution](LICENSE).
