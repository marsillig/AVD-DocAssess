# AVD-DocAssess architecture

AVD-DocAssess is a read-only Azure inventory/documentation generator for Azure Virtual Desktop environments.

```mermaid
flowchart LR
  Operator["Operator in Azure Cloud Shell"] --> Script["AVD-DocAssess.ps1"]
  Script --> ARM["Azure Resource Manager read APIs"]
  ARM --> AVD["AVD resources"]
  ARM --> Network["VNets / subnets / NSGs / routes / private endpoints"]
  ARM --> IAM["Role assignments"]
  ARM --> Monitor["Diagnostics / Log Analytics / alerts"]
  ARM --> Storage["FSLogix storage candidates"]
  Script --> Report["Self-contained HTML report"]
```

The tool does not collect secrets and does not write client reports into source control.
