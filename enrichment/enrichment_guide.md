# KV Store Enrichment Setup Guide

## Overview

This detection pack uses KV store lookups to enrich alerts with contextual data that would otherwise require tribal knowledge. Instead of asking "who owns this device?" in Slack, the enrichment happens automatically at alert time.

## Collections

### asset_info
Maps device IDs to ownership, department, and criticality. Feeds into: mass wipe detection, compliance drift detection.

```
# Create collection
curl -k -u admin:password \
  https://splunk:8089/servicesNS/nobody/stryker_detections/storage/collections/config \
  -d name=asset_info

# Define schema
curl -k -u admin:password \
  https://splunk:8089/servicesNS/nobody/stryker_detections/storage/collections/config/asset_info \
  -d 'field.DeviceId=string' \
  -d 'field.hostname=string' \
  -d 'field.owner=string' \
  -d 'field.department=string' \
  -d 'field.criticality=string' \
  -d 'accelerated_fields.device={"DeviceId": 1}'

# Bulk load from CSV
curl -k -u admin:password \
  https://splunk:8089/servicesNS/nobody/stryker_detections/storage/collections/data/asset_info/batch_save \
  -H 'Content-Type: application/json' \
  -d @asset_info.json
```

### admin_baseline
Stores normal behavior baselines for admin accounts. Feeds into: impossible travel, policy change anomaly, mass wipe threshold.

```
# Create collection
curl -k -u admin:password \
  https://splunk:8089/servicesNS/nobody/stryker_detections/storage/collections/config \
  -d name=admin_baseline

# Define schema
curl -k -u admin:password \
  https://splunk:8089/servicesNS/nobody/stryker_detections/storage/collections/config/admin_baseline \
  -d 'field.UserPrincipalName=string' \
  -d 'field.normal_daily_actions=number' \
  -d 'field.normal_hours=string' \
  -d 'field.typical_locations=string' \
  -d 'accelerated_fields.user={"UserPrincipalName": 1}'
```

## SPL Lookup Configuration

Add to `transforms.conf`:

```ini
[asset_info_lookup]
external_type = kvstore
collection = asset_info
fields_list = DeviceId, hostname, owner, department, criticality, device_type, os, location

[admin_baseline_lookup]
external_type = kvstore
collection = admin_baseline
fields_list = UserPrincipalName, normal_daily_actions, typical_policies_modified, normal_hours, typical_locations, on_call_status
```

## Usage in SPL

```spl
# Enrich Intune wipe events with asset context
index=azure sourcetype="azure:intune:audit" Activity="wipeManagedDevice"
| lookup asset_info_lookup DeviceId as TargetDeviceId
  OUTPUT owner, department, criticality
| where criticality="critical"
| table _time, InitiatedByUser, TargetDeviceId, owner, department, criticality

# Enrich admin logins with baseline behavior
index=azure sourcetype="azure:entra:signin" ResultType=0
| lookup admin_baseline_lookup UserPrincipalName
  OUTPUT normal_hours, typical_locations, on_call_status
| eval is_off_hours = if(match(_time, normal_hours), "no", "yes")
| where is_off_hours="yes"
```

## Maintenance

- **asset_info**: Update when devices are provisioned/decommissioned. Integrate with CMDB sync job.
- **admin_baseline**: Recalculate monthly from actual usage patterns. Automate via scheduled search that writes back to KV store.
- **egress_baseline**: Rolling 30-day average, calculated nightly via scheduled search.
