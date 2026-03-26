# Stryker/Intune Detection Pack

Detection-as-code pack targeting Microsoft Intune MDM abuse, inspired by the March 2026 Stryker Corporation attack where threat actor Handala used compromised Intune access to wipe 200,000 devices and exfiltrate 50TB of data.

## Attack Summary

| Field | Detail |
|-------|--------|
| Target | Stryker Corporation (Fortune 500 medical devices) |
| Threat Actor | Handala (pro-Iran hacktivist) |
| Date | March 11, 2026 |
| Impact | 200K devices wiped, 50TB exfiltrated |
| Method | Microsoft Intune MDM abused to push mass device wipe policies |
| Type | Destructive (no ransomware/extortion) |
| Response | CISA issued endpoint management hardening guidance (March 18) |

## Detection Rules

All rules use [Sigma](https://github.com/SigmaHQ/sigma) format (vendor-agnostic YAML) and map to MITRE ATT&CK.

| Rule | MITRE Technique | Data Source |
|------|----------------|-------------|
| [intune_mass_device_wipe](rules/intune_mass_device_wipe.yml) | T1485 (Data Destruction) | Microsoft Graph API audit logs |
| [intune_policy_change_anomaly](rules/intune_policy_change_anomaly.yml) | T1484.002 (Domain/Tenant Policy Modification) | Intune audit logs |
| [entra_admin_impossible_travel](rules/entra_admin_impossible_travel.yml) | T1078.004 (Cloud Accounts) | Entra ID sign-in logs |
| [bulk_compliance_drift](rules/bulk_compliance_drift.yml) | T1485 (Data Destruction) | Intune compliance state events |
| [volumetric_data_egress](rules/volumetric_data_egress.yml) | T1048 (Exfiltration Over Alternative Protocol) | Firewall/proxy/NetFlow |
| [intune_admin_privilege_escalation](rules/intune_admin_privilege_escalation.yml) | T1098 (Account Manipulation) | Entra ID audit logs |

## Reproducible Verification

Every claim in this project is tested. Run `pytest tests/test_rules.py -v` to reproduce.

| What the test proves | How |
|---|---|
| 6 Sigma rules with required fields (title, logsource, detection, level, tags) | Parses each YAML and asserts required keys |
| 3 documented benign false-positive scenarios per rule (18 total) | Each benign case is run through the enriched detector — must be suppressed |
| 3 malicious attack scenarios per rule (18 total) | Each malicious case is run through the enriched detector — must alert |
| 100% false-positive reduction on mass-wipe simulation | 100 synthetic events (80 benign, 20 malicious) scored by naive rule vs enriched rule using `admin_baseline.csv` lookups. Naive rule alerts on all 100. Enriched rule suppresses all 80 benign, catches all 20 malicious |
| 5+ unique MITRE ATT&CK techniques covered | Extracts tags from all rules and counts distinct `attack.tXXXX` entries |

**43 tests, 0 failures.**

The enrichment logic simulates KV store lookups (admin baselines, change tickets, VPN status, destination reputation) — the same approach used in production Splunk environments to reduce alert fatigue without losing coverage.

## Enrichment

KV store definitions for Splunk-based enrichment lookups:

- [asset_info.csv](enrichment/asset_info.csv) - Asset ownership, department, criticality
- [admin_baseline.csv](enrichment/admin_baseline.csv) - Admin account normal behavior baselines
- [enrichment_guide.md](enrichment/enrichment_guide.md) - KV store setup instructions

## Response

- [intune_abuse_response.md](response/intune_abuse_response.md) - Incident response playbook for Intune MDM abuse

## Kill Chain Mapping

1. **Recon** - Identified target's use of Intune for device management
2. **Weaponization** - Developed Intune policy abuse tooling
3. **Delivery** - Initial access via compromised Entra ID admin credentials
4. **Exploitation** - Gained Intune Administrator or Global Administrator role
5. **Installation** - Pushed malicious MDM wipe policies to 200K managed devices
6. **C2** - Used Intune itself as the command channel (legitimate management tool)
7. **Actions on Objectives** - Mass device destruction + 50TB data exfiltration

## References

- [CISA: Endpoint Management System Hardening (March 18, 2026)](https://www.cisa.gov/news-events/alerts/2026/03/18/cisa-urges-endpoint-management-system-hardening-after-cyberattack-against-us-organization)
- [Stryker Customer Update (March 2026)](https://www.stryker.com/us/en/about/news/2026/a-message-to-our-customers-03-2026.html)
- [CNN: Pro-Iran hackers claim Stryker attack](https://www.cnn.com/2026/03/11/politics/pro-iran-hackers-cyberattack-medical-device-maker)
