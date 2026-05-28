# GCP CIS-oriented security audit

**Tools invoked:** get_iam_policy, get_logging_monitoring_config, get_network_config, get_compute_info, get_storage_metadata, get_cloud_sql_inventory, get_bigquery_inventory, get_dataproc_inventory

**CIS section hints:** 1, 2, 3, 4, 5, 6, 7, 8

---

## Summary
The provided JSON inventory and CIS benchmark excerpts are used to assess the compliance of a GCP project with various security controls. The inventory is compacted due to request limits, and there are no tool-level permission errors recorded.

## Non-Compliant findings
* CIS 1.14: **Non-Compliant** - The inventory does not provide sufficient information to determine if API keys are restricted to only the APIs that the application needs access to.
* CIS 1.7: **Non-Compliant** - The inventory does not provide sufficient information to determine if user-managed/external keys for service accounts are rotated every 90 days or fewer.
* CIS 2.5: **Non-Compliant** - The inventory does not provide sufficient information to determine if the log metric filter and alerts exist for audit configuration changes.
* CIS 2.7: **Non-Compliant** - The inventory does not provide sufficient information to determine if the log metric filter and alerts exist for VPC network firewall rule changes.
* CIS 3.6: **Non-Compliant** - The inventory does not provide sufficient information to determine if SSH access is restricted from the internet.
* CIS 3.7: **Non-Compliant** - The inventory does not provide sufficient information to determine if RDP access is restricted from the internet.
* CIS 4.6: **Non-Compliant** - The inventory does not provide sufficient information to determine if IP forwarding is not enabled on instances.

## Other observations
The inventory provides some information about the project's configuration, such as the presence of service accounts, service account keys, and networks. However, the information is not sufficient to determine compliance with the CIS benchmarks.

## Data gaps
* The inventory does not provide detailed information about API keys and their restrictions.
* The inventory does not provide detailed information about service account keys and their rotation.
* The inventory does not provide detailed information about log metrics and alerts.
* The inventory does not provide detailed information about firewall rules and their configurations.
* The inventory does not provide detailed information about instances and their configurations.
* The inventory is compacted due to request limits, which may have omitted relevant information.