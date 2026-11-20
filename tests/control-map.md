# Active Directory Domain V3R8 control map

The table maps all 36 controls in benchmark version 3, release 8, dated 30 September 2026. Use the official DISA Check and Fix text alongside the procedures for your lab. [DoD Cyber Exchange STIG library](https://www.cyber.mil/stigs/compilations/)

- DISA source archive member `U_Active_Directory_Domain_V3R8_Manual_STIG/U_Active_Directory_Domain_STIG_V3R8_Manual-xccdf.xml`.
- Evaluate-STIG 1.2610.1 sources `Src/Evaluate-STIG/Modules/Scan-ActiveDirectoryDomain_Checks/Scan-ActiveDirectoryDomain_Checks.psm1` and `Src/Evaluate-STIG/xml/STIGList.xml`. The evaluator product short name is `ADDomain`.

| Control | Rule | Native check | Role or review |
| --- | --- | --- | --- |
| V-243466 | `SV-243466r1266527_rule` | `Get-V243466` | Enterprise Admins roster limited to dedicated forest identities. Remove the built-in RID-500 tier overlap and redundant Group Policy Creator Owners membership. [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243466). |
| V-243467 | `SV-243467r959010_rule` | `Get-V243467` | Domain Admins roster limited to dedicated domain identities. Retain the RID-500 domain recovery assignment while removing redundant elevated memberships. [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243467). |
| V-243468 | `SV-243468r959010_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243468). |
| V-243469 | `SV-243469r959010_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243469). |
| V-243470 | `SV-243470r959010_rule` | Manual | No privileged user delegates credentials. Enforce for built-in and configured groups, review individually delegated identities. [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243470). |
| V-243471 | `SV-243471r1186315_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243471). |
| V-243472 | `SV-243472r959010_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243472). |
| V-243473 | `SV-243473r959010_rule` | `Get-V243473` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243473). |
| V-243475 | `SV-243475r959010_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243475). |
| V-243476 | `SV-243476r1266530_rule` | `Get-V243476` | Rotate smart-card hashes within 60 days. Enable rolling, then verify resultant policy and rotation evidence. [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243476). |
| V-243477 | `SV-243477r1153405_rule` | `Get-V243477` | Protected Users covers personnel administrators with documented recovery and service exceptions. Enrollment is inventory-driven. [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243477). |
| V-243478 | `SV-243478r959010_rule` | `Get-V243478` | No unconstrained delegation on non-DC computer accounts. Enforced in the role. |
| V-243479 | `SV-243479r1153403_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243479). |
| V-243480 | `SV-243480r959010_rule` | `Get-V243480` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243481 | `SV-243481r959010_rule` | `Get-V243481` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243482 | `SV-243482r1266533_rule` | `Get-V243482` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243483 | `SV-243483r1266535_rule` | `Get-V243483` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243484 | `SV-243484r958482_rule` | `Get-V243484` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243485 | `SV-243485r1117265_rule` | `Get-V243485` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243486 | `SV-243486r958504_rule` | `Get-V243486` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243487 | `SV-243487r959010_rule` | `Get-V243487` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243487). |
| V-243488 | `SV-243488r959010_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243488). |
| V-243489 | `SV-243489r959010_rule` | `Get-V243489` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243490 | `SV-243490r959010_rule` | `Get-V243490` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243490). |
| V-243491 | `SV-243491r959010_rule` | `Get-V243491` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243491). |
| V-243492 | `SV-243492r959010_rule` | `Get-V243492` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243492). |
| V-243493 | `SV-243493r959010_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243493). |
| V-243494 | `SV-243494r959010_rule` | `Get-V243494` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243495 | `SV-243495r1266538_rule` | `Get-V243495` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243495). |
| V-243496 | `SV-243496r959010_rule` | `Get-V243496` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243497 | `SV-243497r959010_rule` | `Get-V243497` | Run the evaluator and review applicability after topology or configuration changes. |
| V-243498 | `SV-243498r958406_rule` | `Get-V243498` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243498). |
| V-243499 | `SV-243499r959010_rule` | Manual | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243499). |
| V-243500 | `SV-243500r959010_rule` | `Get-V243500` | [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-243500). |
| V-243501 | `SV-243501r1016334_rule` | `Get-V243501` | Run the evaluator and review applicability after topology or configuration changes. |
| V-269097 | `SV-269097r1026170_rule` | `Get-V269097` | Success and Failure for both Kerberos audit subcategories. Verify effective policy after policy refresh. [Procedure](../files/answer_files/SecurityPlanProcedures.md#v-269097). |

## Assessment notes

- The V-243476 evaluator checks rolling on Windows2016Domain. On Windows2025Domain, the answer file independently checks whether rolling is enabled and whether any smart-card-required accounts exist. When such accounts exist, review actual rotation evidence.
- V-243477 requires personnel, recovery, and service account classifications before assessing Protected Users membership.
- The V-269097 evaluator can pass when a queried audit row is absent. When the native status is Not a Finding, the answer file independently requires both audit rows to report Success and Failure.
