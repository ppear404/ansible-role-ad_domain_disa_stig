# Active Directory Domain V3R8 security-plan procedures

Review during STIG reassessment and after changes affecting a control. Record the reviewer, decision, evidence reference, and next review date in the assessment record.

## V-243466

Export direct and nested Enterprise Admins membership. Have the IAO approve each member and confirm that each account is dedicated to forest administration and holds no conflicting privileged, server, or workstation role. Remove time-bound forest elevation when the work ends and verify final membership.

## V-243467

Export direct, nested, and primary Domain Admins membership. Have the IAO approve the dedicated domain and DC administration accounts. Compare the roster to forest, schema, member-server, and workstation administrative assignments. Verify recovery access and record each account's purpose.

## V-243468

Designate a domain group and issue unique accounts for member-server administration. Have the IAO approve the roster. Compare group membership and local administrator mappings with forest, domain, and workstation assignments. Correct any overlap.

## V-243469

Designate a domain group and issue unique accounts for workstation administration. Have the IAO approve the roster. Compare group membership and local administrator mappings with forest, domain, and member-server assignments. Correct any overlap.

## V-243470

Inventory privileged users through built-in, nested and site-defined groups and individually delegated rights. Verify that every identified account is sensitive and cannot be delegated. Include site-defined privileged groups in the role inventory and separately review individually delegated users.

## V-243471

Inventory deployed domain systems and all local administrator accounts. Verify unique per-system credentials using LAPS coverage metadata or the AO-approved equivalent, including accounts outside LAPS. Record coverage without exporting passwords.

## V-243472

Compare the EA and DA account-to-card assignments with the PKI issuance records for other accounts. EA and DA may share a card. Verify their cards carry no other accounts.

## V-243473

Use the approved asset and exposure inventory to determine applicability. Inspect local Administrators membership on each public-facing server. Verify a dedicated public-server group and separate accounts, with no administrators from the internal server tier or Domain Admins.

## V-243475

Review boundary, proxy and host egress controls with the network administrator. Test that DC internet egress is blocked over IPv4 and IPv6. Record rule references, outcomes, and organizational approvals for critical-function exceptions.

## V-243476

Inventory smart-card-required accounts. Review password timestamps, the domain rolling setting, resultant password policies and rotation records to verify a rotation interval of 60 days or less. On functional levels without rolling support, verify the approved periodic rotation process and its results.

## V-243477

Identify personnel in the six benchmark groups, including nested memberships. Test Kerberos administration before enrollment. Review Protected Users membership, one documented recovery exception at most, and the owner-confirmed service-account exclusions. Record the authentication test and membership comparison.

## V-243479

Schedule and verify an annual DSRM password rotation for every DC using a successful event 4794 or a controlled reset record. Store unique recovery credentials in the approved vault and retain the date and evidence reference.

## V-243487

Export direct and nested Group Policy Creator Owners and Incoming Forest Trust Builders membership. Have the ISSO confirm and document each business need. Remove memberships lacking a justified need and record the final roster.

## V-243488

Compare the IAM-approved AD object ownership and update-delegation roster with built-in administrative memberships. Remove duplicate authority and retain the delegated-user roster. Obtain explicit IAM acknowledgment and justification when more than ten users are delegated.

## V-243490

Verify monitoring of Security events 4740, 4728, 4732, 4756, 4624, 4625 and 4648 for privileged-account activity and membership additions. Exercise alert or review coverage and retain monitoring and response records.

## V-243491

Verify monitoring of Security events 4624 and 4625 for logon type 3, NTLM, and local accounts excluding ANONYMOUS LOGON. Test with representative records and retain the query and its results.

## V-243492

Verify monitoring of Security event 4624 for logon type 10 and Negotiate. Test with an authorized RDP login and retain the query and alert evidence.

## V-243493

Record the approved Availability categorization. Verify AD System State backup histories for all DCs at least weekly for Low or daily for Moderate or High. Test the approved restore procedure and resolve gaps.

## V-243495

Review network and inventory diagrams for DCs and AD traffic across enclave or DMZ boundaries. Record a single-enclave determination if supported. Otherwise verify VPN protection for replication, logon, and query traffic, and record an ADAM migration plan where applicable.

## V-243498

Confirm whether the AD implementation spans enclaves and uses a VPN. Where both apply, verify IDS visibility into directory traffic across the VPN and retain the diagram and inspection evidence.

## V-243499

Record the approved Availability categorization. For Moderate or High, verify the contingency plan includes the current forest, tree and domain hierarchy. Update after topology changes.

## V-243500

Record the approved Availability categorization. For Moderate or High, verify at least two DCs support the domain through directory inventory and replication health. Document the applicability decision.

## V-269097

Verify Success and Failure for both Kerberos audit subcategories on the domain controller. Review the winning computer GPO with gpresult. If GPO governs either subcategory, configure both flags in the authorized DC GPO. Rerun Evaluate-STIG after normal computer policy refresh and confirm both flags persist.
