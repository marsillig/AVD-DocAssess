# AVD-DocAssess

**AVD-DocAssess** is a Cloud Shell–friendly, read-only PowerShell documentation assessor for Azure Virtual Desktop deployments. It inventories the core components of an AVD environment and generates a self-contained HTML documentation report.

It is designed for consultants and operators who need a structured AVD deployment document without collecting secrets or making changes to Azure.

## What it documents

- Azure Virtual Desktop host pools, workspaces, application groups, session hosts, and scaling plans
- IAM role assignments at the selected subscription or resource group scope
- VNets, subnets, NSGs, route tables, NAT Gateways, VPN Gateways, ExpressRoute circuits, DNS settings, session host NICs, and private endpoints
- Likely FSLogix/profile storage accounts based on names and tags
- Log Analytics workspaces, diagnostic settings, and activity log alerts
- High-level architecture/dependency map, including outbound network components where visible
- Documentation gaps and collection notes

## Security model

AVD-DocAssess is read-only. It does not collect:

- Passwords
- Access tokens
- Storage account keys
- VM guest data
- User profile contents
- FSLogix container contents

Generated reports can still contain sensitive architecture and IAM metadata. Do **not** commit client reports to GitHub.

## Least-privilege permissions

Baseline:

- `Reader` on the subscription or target resource group

Optional enrichment:

- `Microsoft.Authorization/roleAssignments/read` for IAM visibility
- Monitoring Reader-style visibility for diagnostic settings and alerts
- Reader access to hub/spoke networking resource groups if AVD network resources live outside the AVD resource group

## Azure Cloud Shell quick start

Open [Azure Cloud Shell](https://shell.azure.com) in **PowerShell** mode.

```powershell
# Clone the private repo after it has been created
 git clone https://github.com/marsillig/AVD-DocAssess.git
 cd AVD-DocAssess

# Run with the existing Cloud Shell Azure context
./AVD-DocAssess.ps1 -UseExistingConnection -OutputPath ./AVD-DocAssess-Report.html
```

Download the generated `AVD-DocAssess-Report.html` from Cloud Shell and open it locally.

## Parameters

| Parameter | Description | Example |
|---|---|---|
| `-SubscriptionId` | Subscription to document. Defaults to current Az context. | `00000000-0000-0000-0000-000000000000` |
| `-TenantId` | Tenant to authenticate against. Defaults to current context. | `11111111-1111-1111-1111-111111111111` |
| `-ResourceGroupName` | Optional resource group scope. | `rg-avd-prod` |
| `-HostPoolName` | Optional host pool scope. Requires `-ResourceGroupName`. | `hp-prod-pooled-01` |
| `-UseExistingConnection` | Use the current Az context; recommended in Cloud Shell. | switch |
| `-OutputPath` | HTML report path. | `./AVD-DocAssess-Report.html` |
| `-OpenReport` | Open the generated report locally. Ignored in Cloud Shell. | switch |

## Examples

```powershell
# Full current subscription
./AVD-DocAssess.ps1 -UseExistingConnection

# Specific subscription
./AVD-DocAssess.ps1 -UseExistingConnection -SubscriptionId "00000000-0000-0000-0000-000000000000"

# Specific AVD resource group
./AVD-DocAssess.ps1 -UseExistingConnection -ResourceGroupName "rg-avd-prod"

# Specific host pool
./AVD-DocAssess.ps1 -UseExistingConnection -ResourceGroupName "rg-avd-prod" -HostPoolName "hp-prod-pooled-01"
```

## Repository hygiene

The `.gitignore` excludes generated reports, JSON exports, logs, local credentials, and Azure profile material. Keep all client-specific outputs outside source control.

## Relationship to AVD-Assess

AVD-DocAssess complements AVD-Assess. AVD-Assess focuses on health/best-practice scoring. AVD-DocAssess focuses on deployment documentation and inventory.

## License

MIT
