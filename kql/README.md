# Microsoft Sentinel KQL (correlated queries)

These queries mirror the Sigma rules in `rules/` and are meant to run in **Microsoft Sentinel** against `AuditLogs` (and typical Intune-relevant categories). Field names match common Entra audit exports; validate against your tenant because OperationName strings differ by workload version.

| File | Intent |
|------|--------|
| [intune_mass_wipe_retire_burst.kql](intune_mass_wipe_retire_burst.kql) | High-volume wipe, retire, delete, or remote lock in a 1h bin per actor |
| [intune_policy_change_velocity.kql](intune_policy_change_velocity.kql) | Policy and compliance configuration change burst per actor per hour |
| [entra_privileged_intune_window.kql](entra_privileged_intune_window.kql) | Role management event for a user followed by Intune device operations within 4h |

Tuning: adjust `lookback`, `window`, `min_ops`, `min_changes`, and `gap` at the top of each file.
