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
curl -o ./AVD-Blueprint.ps1 https://raw.githubusercontent.com/marsillig/AVD-Blueprint/main/AVD-Blueprint.ps1
./AVD-Blueprint.ps1 -UseExistingConnection
```

The output filename is timestamped automatically, for example:

```text
AVD-Blueprint-Report-20260520-143000.html
```

Download the generated HTML report and open it locally.

If you prefer an explicit output name:

```powershell
./AVD-Blueprint.ps1 -UseExistingConnection -OutputPath ./AVD-Blueprint-Report.html
```

### Try it out (Dry Run)

You can test AVD-Blueprint immediately without an active Azure connection or subscription using the dry-run mode. This generates a high-fidelity simulated report using mock data so you can preview the design:

```powershell
./AVD-Blueprint.ps1 -DryRun
```

## Common commands

```powershell
# Current subscription
./AVD-Blueprint.ps1 -UseExistingConnection

# Specific subscription
./AVD-Blueprint.ps1 -UseExistingConnection -SubscriptionId "<subscription-id>"

# Multiple subscriptions
./AVD-Blueprint.ps1 -UseExistingConnection -SubscriptionId "<sub-a>","<sub-b>"

# All visible subscriptions in the tenant
./AVD-Blueprint.ps1 -UseExistingConnection -AllTenantSubscriptions

# Specific resource group
./AVD-Blueprint.ps1 -UseExistingConnection -ResourceGroupName "rg-avd-prod"

# Specific host pool
./AVD-Blueprint.ps1 -UseExistingConnection -ResourceGroupName "rg-avd-prod" -HostPoolName "hp-prod-pooled-01"
```

## Parameters

| Parameter | Description |
|---|---|
| `-UseExistingConnection` | Use the current Az PowerShell context. Recommended in Cloud Shell. |
| `-SubscriptionId` | Optional subscription ID or comma-separated list. Defaults to current context. |
| `-AllTenantSubscriptions` | Scan all enabled subscriptions visible in the current tenant. |
| `-TenantId` | Optional tenant ID. Defaults to current context. |
| `-ResourceGroupName` | Optional resource group scope. |
| `-HostPoolName` | Optional host pool scope. Requires `-ResourceGroupName`. |
| `-OutputPath` | Output file or directory. Timestamp is added automatically. |
| `-OpenReport` | Open the report locally after generation. |
| `-DryRun` | Bypass Azure connection and generate report using simulated mock data. |
| `-CustomerName` | Optional custom customer name or branding header to override default domain extraction. |

## Permissions

Minimum: `Reader` on each subscription or resource group being scanned.

For complete output, include read access to IAM, monitoring, and any network/storage resource groups used by the AVD environment.

## Notes

- The script is read-only.
- It does not collect passwords, tokens, storage keys, VM guest data, or user profile contents.
- Generated reports may contain customer architecture and IAM metadata; do not commit them.

## License

MIT
