# Incident Response Playbook: Intune MDM Abuse

## Trigger
Any of the following detection rules fire at HIGH or CRITICAL level:
- `intune_mass_device_wipe` (CRITICAL)
- `intune_policy_change_anomaly` (HIGH)
- `entra_admin_impossible_travel` (HIGH)
- `bulk_compliance_drift` (CRITICAL)
- `intune_admin_privilege_escalation` (CRITICAL)

## Severity Classification

| Signal | Severity | Response Time |
|--------|----------|--------------|
| Single admin policy change outside hours | P2 | 4 hours |
| Admin impossible travel + Intune action | P1 | 30 minutes |
| Mass device wipe threshold exceeded | P0 | Immediate |
| Bulk compliance drift > 100 devices | P0 | Immediate |
| Admin role assigned to non-admin account | P1 | 1 hour |

## Immediate Actions (First 15 Minutes)

### P0: Mass Wipe or Bulk Compliance Drift

1. **Disable the admin account** in Entra ID immediately. Do not wait for confirmation.
   ```
   # Azure CLI
   az ad user update --id <UserPrincipalName> --account-enabled false
   ```

2. **Revoke all active sessions** for the compromised admin.
   ```
   # Microsoft Graph API
   POST /users/{id}/revokeSignInSessions
   ```

3. **Pause Intune device sync** to prevent further wipe commands from propagating.
   - Intune Admin Center > Devices > All devices > Bulk device actions > Pause sync
   - If available via API: suspend the Intune connector service.

4. **Notify incident commander** and open a bridge call.

5. **Preserve evidence**: Export Intune audit logs and Entra ID sign-in logs for the last 72 hours before any remediation changes overwrite them.

### P1: Impossible Travel or Privilege Escalation

1. **Force MFA re-registration** for the affected admin account.
2. **Review recent Intune actions** by the account (last 24 hours).
3. **Check for new device configuration profiles** or compliance policy changes.
4. **Verify** the role assignment was authorized via change management / HR onboarding.

## Investigation Checklist

- [ ] Identify the compromised admin account(s)
- [ ] Determine initial access vector (phished credentials, token theft, session hijacking)
- [ ] Map all Intune actions taken by the compromised account in the last 72 hours
- [ ] Identify all affected devices (wipe commands issued, policies pushed)
- [ ] Check for persistence: new admin accounts created, new app registrations, new service principals
- [ ] Check for data exfiltration: volumetric egress anomalies, new SharePoint/OneDrive sharing rules
- [ ] Review Conditional Access policy changes (attacker may have weakened access controls)
- [ ] Check for lateral movement: did the attacker pivot from Intune admin to other Azure/M365 services?

## Containment

1. **Rotate credentials** for all Intune/Entra admin accounts (not just the compromised one).
2. **Review and revoke** any Conditional Access policy changes made in the attack window.
3. **Audit all Intune configuration profiles** created or modified in the last 7 days.
4. **Block the source IPs** identified in the impossible travel or anomalous login events.
5. **Enable Privileged Identity Management (PIM)** if not already active for Intune admin roles.

## Recovery

1. **Re-image affected devices** from known-good backups or baseline images.
2. **Re-enroll devices** in Intune with fresh compliance baselines.
3. **Verify compliance state** returns to normal across the fleet.
4. **Monitor for re-compromise**: increased logging on admin accounts for 30 days.

## Post-Incident

- [ ] Document timeline and root cause in incident report
- [ ] Update KV store baselines to reflect any legitimate changes
- [ ] Review Conditional Access policies for Intune admin access (require compliant device, phishing-resistant MFA, named locations)
- [ ] Evaluate whether break-glass account procedures need updating
- [ ] Share detection pack improvements with team (new rules, tuned thresholds)

## MITRE ATT&CK Mapping

| Phase | Technique | Detection Rule |
|-------|-----------|---------------|
| Initial Access | T1078.004 Cloud Accounts | entra_admin_impossible_travel |
| Persistence | T1098 Account Manipulation | intune_admin_privilege_escalation |
| Defense Evasion | T1484.002 Tenant Policy Modification | intune_policy_change_anomaly |
| Impact | T1485 Data Destruction | intune_mass_device_wipe, bulk_compliance_drift |
| Exfiltration | T1048 Exfiltration Over Alternative Protocol | volumetric_data_egress |
