# AVD-Blueprint

Cloud Shell PowerShell tool that documents an Azure Virtual Desktop environment and generates a customer-ready HTML report.

![AVD-Blueprint report preview](docs/avd-blueprint-dryrun-viewport.svg)

## What it captures

- AVD host pools, workspaces, application groups, session hosts, and scaling plans
- IAM role assignments visible in the selected scope
- VNets, subnets, NSGs, routes, NAT Gateways, VPN Gateways, ExpressRoute, DNS, private DNS, private endpoints, and NICs
- FSLogix/profile storage candidates
- Log Analytics workspaces and diagnostic settings
- Architecture summary, section findings, and collapsible inventory tables

## Quick start

Open Azure Cloud Shell in **PowerShell** mode:

```powershell
git clone https://github.com/marsillig/AVD-Blueprint.git
cd AVD-Blueprint
./AVD-Blueprint.ps1 -UseExistingConnection -OutputPath ~/clouddrive/AVD-Blueprint-Report.html
```

The output filename is timestamped automatically, for example:

```text
AVD-Blueprint-Report-20260520-143000.html
```

Download the HTML report from Cloud Shell and open it locally.

## Common commands

```powershell
# Current subscription
./AVD-Blueprint.ps1 -UseExistingConnection -OutputPath ~/clouddrive/AVD-Blueprint-Report.html

# Specific subscription
./AVD-Blueprint.ps1 -UseExistingConnection -SubscriptionId "<subscription-id>" -OutputPath ~/clouddrive/AVD-Blueprint-Report.html

# Specific resource group
./AVD-Blueprint.ps1 -UseExistingConnection -ResourceGroupName "rg-avd-prod" -OutputPath ~/clouddrive/AVD-Blueprint-Report.html

# Specific host pool
./AVD-Blueprint.ps1 -UseExistingConnection -ResourceGroupName "rg-avd-prod" -HostPoolName "hp-prod-pooled-01" -OutputPath ~/clouddrive/AVD-Blueprint-Report.html
```

## Parameters

| Parameter | Description |
|---|---|
| `-UseExistingConnection` | Use the current Az PowerShell context. Recommended in Cloud Shell. |
| `-SubscriptionId` | Optional subscription ID. Defaults to current context. |
| `-TenantId` | Optional tenant ID. Defaults to current context. |
| `-ResourceGroupName` | Optional resource group scope. |
| `-HostPoolName` | Optional host pool scope. Requires `-ResourceGroupName`. |
| `-OutputPath` | Output file or directory. Timestamp is added automatically. |
| `-OpenReport` | Open the report locally after generation. |

## Permissions

Minimum: `Reader` on the subscription or resource group.

For complete output, include read access to IAM, monitoring, and any network/storage resource groups used by the AVD environment.

## Notes

- The script is read-only.
- It does not collect passwords, tokens, storage keys, VM guest data, or user profile contents.
- Generated reports may contain customer architecture and IAM metadata; do not commit them.

## License

MIT
