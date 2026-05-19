<#
.SYNOPSIS
    AVD-DocAssess - Azure Virtual Desktop deployment documentation assessor.

.DESCRIPTION
    Runs read-only Azure PowerShell queries against an Azure Virtual Desktop
    deployment and generates a self-contained HTML documentation report covering
    AVD resources, IAM, networking, FSLogix/profile storage candidates,
    diagnostics, monitoring, and dependency diagrams.

.PARAMETER SubscriptionId
    Azure subscription ID to document. Falls back to the current Az context.

.PARAMETER TenantId
    Azure tenant ID to authenticate against. Falls back to the current context.

.PARAMETER ResourceGroupName
    Optional resource group scope.

.PARAMETER HostPoolName
    Optional host pool scope. Must be used with -ResourceGroupName.

.PARAMETER UseExistingConnection
    Skip Connect-AzAccount and use the current Az PowerShell context. Recommended
    for Azure Cloud Shell.

.PARAMETER OutputPath
    HTML output path. Defaults to AVD-DocAssess-Report-yyyyMMdd-HHmmss.html.

.PARAMETER OpenReport
    Open the generated HTML report in the default browser. Ignored in Cloud Shell.

.EXAMPLE
    ./AVD-DocAssess.ps1 -UseExistingConnection -OutputPath ./AVD-DocAssess-Report.html

.NOTES
    This tool is read-only. It does not collect secrets, keys, tokens, or VM guest
    data. Generated reports can contain sensitive architecture and IAM metadata;
    do not commit client reports to source control.
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$ResourceGroupName,
    [string]$HostPoolName,
    [switch]$UseExistingConnection,
    [string]$OutputPath,
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'
$script:ToolVersion = '0.1.0'
$script:RequiredModules = @(
    'Az.Accounts',
    'Az.DesktopVirtualization',
    'Az.Resources',
    'Az.Network',
    'Az.Compute',
    'Az.Storage',
    'Az.Monitor',
    'Az.OperationalInsights'
)
$script:Warnings = [System.Collections.Generic.List[string]]::new()

function Add-WarningMessage {
    param([string]$Message)
    if (-not [string]::IsNullOrWhiteSpace($Message)) {
        $script:Warnings.Add($Message) | Out-Null
        Write-Warning $Message
    }
}

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-ShortId {
    param([AllowNull()][string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return '' }
    $parts = $ResourceId -split '/'
    if ($parts.Count -ge 2) { return $parts[-1] }
    return $ResourceId
}

function Get-RgFromArmId {
    param([AllowNull()][string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return $null }
    $match = [regex]::Match($ResourceId, '/resourceGroups/([^/]+)', 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value }
    return $null
}

function Get-NameFromSessionHost {
    param([object]$SessionHost)
    if ($SessionHost.Name -match '/') { return ($SessionHost.Name -split '/')[-1] }
    return $SessionHost.Name
}

function Invoke-ReadOnly {
    param(
        [Parameter(Mandatory)][string]$OperationName,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [switch]$Optional
    )
    try {
        return & $ScriptBlock
    } catch {
        $message = "$OperationName failed: $($_.Exception.Message)"
        if ($Optional) {
            Add-WarningMessage $message
            return @()
        }
        throw $message
    }
}

function Assert-RequiredModules {
    $missing = @()
    foreach ($module in $script:RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) { $missing += $module }
    }
    if ($missing.Count -gt 0) {
        throw "Missing Az PowerShell modules: $($missing -join ', '). In Cloud Shell, install with: Install-Module $($missing -join ', ') -Scope CurrentUser -Force"
    }
}

function Connect-DocAssessAzure {
    Assert-RequiredModules

    if ($HostPoolName -and -not $ResourceGroupName) {
        throw '-HostPoolName requires -ResourceGroupName.'
    }

    if (-not $UseExistingConnection) {
        $connectParams = @{}
        if ($TenantId) { $connectParams.Tenant = $TenantId }
        Connect-AzAccount @connectParams | Out-Null
    }

    $context = Get-AzContext
    if (-not $context) { throw 'No Azure context available. Run Connect-AzAccount or use Azure Cloud Shell with -UseExistingConnection.' }

    if ($SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        $context = Get-AzContext
    }

    return $context
}

function Get-DiagnosticSettingsSafe {
    param([string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return @() }
    return @(Invoke-ReadOnly -OperationName "Get-AzDiagnosticSetting ($ResourceId)" -Optional -ScriptBlock {
        Get-AzDiagnosticSetting -ResourceId $ResourceId -ErrorAction Stop -WarningAction SilentlyContinue
    })
}


function Get-AvdDocumentationData {
    param([object]$Context)

    Write-Host 'Collecting AVD resources...' -ForegroundColor Cyan

    $hostPools = @()
    if ($HostPoolName) {
        $hostPools = @(Invoke-ReadOnly -OperationName 'Get-AzWvdHostPool' -ScriptBlock {
            Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolName -ErrorAction Stop
        })
    } elseif ($ResourceGroupName) {
        $hostPools = @(Invoke-ReadOnly -OperationName 'Get-AzWvdHostPool' -ScriptBlock {
            Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -ErrorAction Stop
        })
    } else {
        $hostPools = @(Invoke-ReadOnly -OperationName 'Get-AzWvdHostPool' -ScriptBlock {
            Get-AzWvdHostPool -ErrorAction Stop
        })
    }

    $workspaces = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzWvdWorkspace' -Optional -ScriptBlock { Get-AzWvdWorkspace -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzWvdWorkspace' -Optional -ScriptBlock { Get-AzWvdWorkspace -ErrorAction Stop })
    }

    $applicationGroups = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzWvdApplicationGroup' -Optional -ScriptBlock { Get-AzWvdApplicationGroup -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzWvdApplicationGroup' -Optional -ScriptBlock { Get-AzWvdApplicationGroup -ErrorAction Stop })
    }

    $scalingPlans = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzWvdScalingPlan' -Optional -ScriptBlock { Get-AzWvdScalingPlan -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzWvdScalingPlan' -Optional -ScriptBlock { Get-AzWvdScalingPlan -ErrorAction Stop })
    }

    $sessionHosts = [System.Collections.Generic.List[object]]::new()
    $sessionHostVms = [System.Collections.Generic.List[object]]::new()
    $nics = [System.Collections.Generic.List[object]]::new()
    $hostPoolDiagnostics = [System.Collections.Generic.List[object]]::new()
    $vmDiagnostics = [System.Collections.Generic.List[object]]::new()

    foreach ($hp in $hostPools) {
        $hpRg = Get-RgFromArmId $hp.Id
        $hpName = $hp.Name
        $hpDiag = Get-DiagnosticSettingsSafe -ResourceId $hp.Id
        foreach ($diag in $hpDiag) {
            $hostPoolDiagnostics.Add([pscustomobject]@{ ResourceName = $hpName; ResourceType = 'HostPool'; DiagnosticName = $diag.Name; WorkspaceId = $diag.WorkspaceId; StorageAccountId = $diag.StorageAccountId; EventHubAuthorizationRuleId = $diag.EventHubAuthorizationRuleId }) | Out-Null
        }

        $hosts = @(Invoke-ReadOnly -OperationName "Get-AzWvdSessionHost ($hpName)" -Optional -ScriptBlock {
            Get-AzWvdSessionHost -ResourceGroupName $hpRg -HostPoolName $hpName -ErrorAction Stop
        })

        foreach ($sessionHost in $hosts) {
            $hostShortName = Get-NameFromSessionHost -SessionHost $sessionHost
            $sessionHosts.Add([pscustomobject]@{
                HostPool = $hpName
                Name = $hostShortName
                ResourceGroup = $hpRg
                Status = $sessionHost.Status
                AllowNewSession = $sessionHost.AllowNewSession
                Sessions = $sessionHost.Session
                AgentVersion = $sessionHost.AgentVersion
                UpdateState = $sessionHost.UpdateState
                VmResourceId = $sessionHost.ResourceId
            }) | Out-Null

            if (-not [string]::IsNullOrWhiteSpace($sessionHost.ResourceId)) {
                $vmName = ConvertTo-ShortId $sessionHost.ResourceId
                $vmRg = Get-RgFromArmId $sessionHost.ResourceId
                $vm = Invoke-ReadOnly -OperationName "Get-AzVM ($vmName)" -Optional -ScriptBlock {
                    Get-AzVM -ResourceGroupName $vmRg -Name $vmName -ErrorAction Stop
                }
                if ($vm) {
                    $sessionHostVms.Add($vm) | Out-Null
                    $diag = Get-DiagnosticSettingsSafe -ResourceId $vm.Id
                    foreach ($d in $diag) {
                        $vmDiagnostics.Add([pscustomobject]@{ ResourceName = $vm.Name; ResourceType = 'VirtualMachine'; DiagnosticName = $d.Name; WorkspaceId = $d.WorkspaceId; StorageAccountId = $d.StorageAccountId; EventHubAuthorizationRuleId = $d.EventHubAuthorizationRuleId }) | Out-Null
                    }
                    foreach ($nicRef in @($vm.NetworkProfile.NetworkInterfaces)) {
                        if ($nicRef.Id) {
                            $nic = Invoke-ReadOnly -OperationName "Get-AzNetworkInterface ($($vm.Name))" -Optional -ScriptBlock {
                                Get-AzNetworkInterface -ResourceId $nicRef.Id -ErrorAction Stop
                            }
                            if ($nic) { $nics.Add($nic) | Out-Null }
                        }
                    }
                }
            }
        }
    }

    Write-Host 'Collecting networking, IAM, storage, and monitoring resources...' -ForegroundColor Cyan

    $scope = if ($ResourceGroupName) { "/subscriptions/$($Context.Subscription.Id)/resourceGroups/$ResourceGroupName" } else { "/subscriptions/$($Context.Subscription.Id)" }

    $roleAssignments = @(Invoke-ReadOnly -OperationName 'Get-AzRoleAssignment' -Optional -ScriptBlock {
        Get-AzRoleAssignment -Scope $scope -ErrorAction Stop
    })

    $vnets = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzVirtualNetwork' -Optional -ScriptBlock { Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzVirtualNetwork' -Optional -ScriptBlock { Get-AzVirtualNetwork -ErrorAction Stop })
    }

    $nsgs = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzNetworkSecurityGroup' -Optional -ScriptBlock { Get-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzNetworkSecurityGroup' -Optional -ScriptBlock { Get-AzNetworkSecurityGroup -ErrorAction Stop })
    }

    $routeTables = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzRouteTable' -Optional -ScriptBlock { Get-AzRouteTable -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzRouteTable' -Optional -ScriptBlock { Get-AzRouteTable -ErrorAction Stop })
    }

    $privateEndpoints = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzPrivateEndpoint' -Optional -ScriptBlock { Get-AzPrivateEndpoint -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzPrivateEndpoint' -Optional -ScriptBlock { Get-AzPrivateEndpoint -ErrorAction Stop })
    }

    $storageAccounts = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzStorageAccount' -Optional -ScriptBlock { Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzStorageAccount' -Optional -ScriptBlock { Get-AzStorageAccount -ErrorAction Stop })
    }

    $workspacesLa = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzOperationalInsightsWorkspace' -Optional -ScriptBlock { Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzOperationalInsightsWorkspace' -Optional -ScriptBlock { Get-AzOperationalInsightsWorkspace -ErrorAction Stop })
    }

    $alerts = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzActivityLogAlert' -Optional -ScriptBlock { Get-AzActivityLogAlert -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzActivityLogAlert' -Optional -ScriptBlock { Get-AzActivityLogAlert -ErrorAction Stop })
    }

    $profileStorageCandidates = @($storageAccounts | Where-Object {
        $_.StorageAccountName -match 'fslogix|profile|avd' -or
        ($_.Tags.Keys -contains 'FSLogixStorageAccount') -or
        ($_.Tags.Keys -contains 'Purpose' -and $_.Tags['Purpose'] -match 'fslogix|profile|avd')
    })

    return [pscustomobject]@{
        Context = $Context
        Scope = $scope
        HostPools = $hostPools
        Workspaces = $workspaces
        ApplicationGroups = $applicationGroups
        ScalingPlans = $scalingPlans
        SessionHosts = @($sessionHosts)
        SessionHostVms = @($sessionHostVms)
        NetworkInterfaces = @($nics | Sort-Object Id -Unique)
        VirtualNetworks = $vnets
        NetworkSecurityGroups = $nsgs
        RouteTables = $routeTables
        PrivateEndpoints = $privateEndpoints
        StorageAccounts = $storageAccounts
        ProfileStorageCandidates = $profileStorageCandidates
        RoleAssignments = $roleAssignments
        LogAnalyticsWorkspaces = $workspacesLa
        ActivityLogAlerts = $alerts
        Diagnostics = @($hostPoolDiagnostics + $vmDiagnostics)
        GeneratedAt = (Get-Date).ToUniversalTime()
        Warnings = @($script:Warnings)
    }
}

function New-TableHtml {
    param(
        [Parameter(Mandatory)][string[]]$Headers,
        [AllowNull()][object[]]$Rows,
        [string]$EmptyMessage = 'No records found.'
    )
    $safeRows = @($Rows)
    if (-not $safeRows -or $safeRows.Count -eq 0) {
        return "<p class='empty'>$(ConvertTo-HtmlSafe $EmptyMessage)</p>"
    }
    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append('<div class="table-wrap"><table><thead><tr>')
    foreach ($header in $Headers) { [void]$html.Append("<th>$(ConvertTo-HtmlSafe $header)</th>") }
    [void]$html.Append('</tr></thead><tbody>')
    foreach ($row in $safeRows) {
        [void]$html.Append('<tr>')
        foreach ($header in $Headers) {
            $value = $row.$header
            if ($value -is [array]) { $value = $value -join ', ' }
            [void]$html.Append("<td>$(ConvertTo-HtmlSafe $value)</td>")
        }
        [void]$html.Append('</tr>')
    }
    [void]$html.Append('</tbody></table></div>')
    return $html.ToString()
}

function New-TagSummary {
    param([AllowNull()][hashtable]$Tags)
    if (-not $Tags -or $Tags.Count -eq 0) { return '' }
    return (($Tags.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
}


function New-ArchitectureMapHtml {
    param([object]$Data)

    function New-MapItemsHtml {
        param(
            [object[]]$Items,
            [scriptblock]$Label,
            [string]$EmptyText = 'None found',
            [int]$MaxItems = 8
        )
        if (-not $Items -or $Items.Count -eq 0) {
            return "<li class='muted'>$(ConvertTo-HtmlSafe $EmptyText)</li>"
        }
        $html = [System.Text.StringBuilder]::new()
        foreach ($item in @($Items | Select-Object -First $MaxItems)) {
            [void]$html.Append("<li>$(ConvertTo-HtmlSafe (& $Label $item))</li>")
        }
        if ($Items.Count -gt $MaxItems) {
            [void]$html.Append("<li class='muted'>+ $($Items.Count - $MaxItems) more</li>")
        }
        return $html.ToString()
    }

    $hostPoolItems = New-MapItemsHtml -Items $Data.HostPools -Label { param($x) "Host pool: $($x.Name)" }
    $workspaceItems = New-MapItemsHtml -Items $Data.Workspaces -Label { param($x) "Workspace: $($x.Name)" }
    $appGroupItems = New-MapItemsHtml -Items $Data.ApplicationGroups -Label { param($x) "App group: $($x.Name)" }
    $vmItems = New-MapItemsHtml -Items $Data.SessionHostVms -Label { param($x) "VM: $($x.Name) ($($x.HardwareProfile.VmSize))" }
    $nicItems = New-MapItemsHtml -Items $Data.NetworkInterfaces -Label { param($x) "NIC: $($x.Name)" }
    $vnetItems = New-MapItemsHtml -Items $Data.VirtualNetworks -Label { param($x) "VNet: $($x.Name)" }
    $peItems = New-MapItemsHtml -Items $Data.PrivateEndpoints -Label { param($x) "Private endpoint: $($x.Name)" }
    $storageItems = New-MapItemsHtml -Items $Data.ProfileStorageCandidates -Label { param($x) "Storage: $($x.StorageAccountName) ($($x.Sku.Name))" }
    $lawItems = New-MapItemsHtml -Items $Data.LogAnalyticsWorkspaces -Label { param($x) "Workspace: $($x.Name)" }
    $diagItems = New-MapItemsHtml -Items $Data.Diagnostics -Label { param($x) "Diagnostic: $($x.ResourceName)" }
    $iamItems = New-MapItemsHtml -Items $Data.RoleAssignments -Label { param($x) "$($x.RoleDefinitionName): $($x.DisplayName)" } -MaxItems 10

    return @"
<div class="arch-map">
  <div class="arch-row">
    <div class="arch-card primary">
      <div class="arch-icon">🖥️</div>
      <h3>AVD control plane</h3>
      <ul>$hostPoolItems$appGroupItems$workspaceItems</ul>
    </div>
    <div class="arch-arrow">→</div>
    <div class="arch-card">
      <div class="arch-icon">⚙️</div>
      <h3>Session host compute</h3>
      <ul>$vmItems</ul>
    </div>
    <div class="arch-arrow">→</div>
    <div class="arch-card">
      <div class="arch-icon">🌐</div>
      <h3>Network path</h3>
      <ul>$vnetItems$nicItems$peItems</ul>
    </div>
  </div>
  <div class="arch-row secondary">
    <div class="arch-card">
      <div class="arch-icon">💾</div>
      <h3>Profiles / storage</h3>
      <ul>$storageItems</ul>
    </div>
    <div class="arch-card">
      <div class="arch-icon">📊</div>
      <h3>Monitoring</h3>
      <ul>$lawItems$diagItems</ul>
    </div>
    <div class="arch-card">
      <div class="arch-icon">🔐</div>
      <h3>IAM access</h3>
      <ul>$iamItems</ul>
    </div>
  </div>
</div>
"@
}

function New-DocumentationGapRows {
    param([object]$Data)
    $rows = [System.Collections.Generic.List[object]]::new()
    if ($Data.HostPools.Count -eq 0) { $rows.Add([pscustomobject]@{ Area='AVD'; Gap='No host pools found in selected scope'; Action='Confirm subscription/resource group scope or deploy AVD resources.' }) | Out-Null }
    if ($Data.RoleAssignments.Count -eq 0) { $rows.Add([pscustomobject]@{ Area='IAM'; Gap='No role assignments collected'; Action='Grant roleAssignments/read or run from a scope with IAM visibility.' }) | Out-Null }
    if ($Data.VirtualNetworks.Count -eq 0) { $rows.Add([pscustomobject]@{ Area='Network'; Gap='No VNets collected in selected scope'; Action='Confirm network resource group scope or document hub/spoke VNets separately.' }) | Out-Null }
    if ($Data.Diagnostics.Count -eq 0) { $rows.Add([pscustomobject]@{ Area='Monitoring'; Gap='No diagnostic settings found for AVD/session host resources'; Action='Configure diagnostics to Log Analytics or document the monitoring exception.' }) | Out-Null }
    if ($Data.ProfileStorageCandidates.Count -eq 0) { $rows.Add([pscustomobject]@{ Area='Storage'; Gap='No FSLogix/profile storage candidates identified by name/tag'; Action='Tag profile storage or document FSLogix storage mapping manually.' }) | Out-Null }
    foreach ($warning in $Data.Warnings) { $rows.Add([pscustomobject]@{ Area='Collection'; Gap=$warning; Action='Review permissions or module compatibility.' }) | Out-Null }
    return @($rows)
}

function New-HtmlReport {
    param([object]$Data)

    $ctx = $Data.Context
    $hostPoolRows = @($Data.HostPools | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            Name = $_.Name
            ResourceGroup = (Get-RgFromArmId $_.Id)
            Location = $_.Location
            Type = $_.HostPoolType
            LoadBalancer = $_.LoadBalancerType
            StartVmOnConnect = $_.StartVMOnConnect
            PublicNetworkAccess = $_.PublicNetworkAccess
            Tags = (New-TagSummary $_.Tags)
        }
    })
    $workspaceRows = @($Data.Workspaces | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=(Get-RgFromArmId $_.Id); Location=$_.Location; ApplicationGroupReferences=(@($_.ApplicationGroupReference) -join ', '); Tags=(New-TagSummary $_.Tags) } })
    $appGroupRows = @($Data.ApplicationGroups | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=(Get-RgFromArmId $_.Id); Location=$_.Location; Type=$_.ApplicationGroupType; HostPool=(ConvertTo-ShortId $_.HostPoolArmPath); Tags=(New-TagSummary $_.Tags) } })
    $scalingRows = @($Data.ScalingPlans | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=(Get-RgFromArmId $_.Id); Location=$_.Location; TimeZone=$_.TimeZone; HostPoolCount=@($_.HostPoolReference).Count; Tags=(New-TagSummary $_.Tags) } })
    $vmRows = @($Data.SessionHostVms | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Size=$_.HardwareProfile.VmSize; Zones=(@($_.Zones) -join ', '); OSDisk=$_.StorageProfile.OsDisk.ManagedDisk.StorageAccountType; Tags=(New-TagSummary $_.Tags) } })
    $nicRows = @($Data.NetworkInterfaces | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; PrivateIp=(@($_.IpConfigurations | ForEach-Object { $_.PrivateIpAddress }) -join ', '); Subnet=(@($_.IpConfigurations | ForEach-Object { ConvertTo-ShortId $_.Subnet.Id }) -join ', '); NSG=(ConvertTo-ShortId $_.NetworkSecurityGroup.Id); AcceleratedNetworking=$_.EnableAcceleratedNetworking } })
    $vnetRows = @($Data.VirtualNetworks | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; AddressSpace=(@($_.AddressSpace.AddressPrefixes) -join ', '); Subnets=(@($_.Subnets | ForEach-Object { "$($_.Name) [$($_.AddressPrefix)]" }) -join '; '); Tags=(New-TagSummary $_.Tags) } })
    $nsgRows = @($Data.NetworkSecurityGroups | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; RuleCount=@($_.SecurityRules).Count; Tags=(New-TagSummary $_.Tags) } })
    $routeRows = @($Data.RouteTables | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; RouteCount=@($_.Routes).Count; DisableBgpRoutePropagation=$_.DisableBgpRoutePropagation; Tags=(New-TagSummary $_.Tags) } })
    $peRows = @($Data.PrivateEndpoints | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Subnet=(ConvertTo-ShortId $_.Subnet.Id); Connections=(@($_.PrivateLinkServiceConnections | ForEach-Object { ConvertTo-ShortId $_.PrivateLinkServiceId }) -join ', '); Tags=(New-TagSummary $_.Tags) } })
    $storageRows = @($Data.ProfileStorageCandidates | Sort-Object StorageAccountName | ForEach-Object { [pscustomobject]@{ Name=$_.StorageAccountName; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Sku=$_.Sku.Name; Kind=$_.Kind; PublicNetworkAccess=$_.PublicNetworkAccess; Tags=(New-TagSummary $_.Tags) } })
    $iamRows = @($Data.RoleAssignments | Sort-Object Scope, RoleDefinitionName | ForEach-Object { [pscustomobject]@{ Principal=$_.DisplayName; PrincipalType=$_.ObjectType; Role=$_.RoleDefinitionName; Scope=$_.Scope } })
    $lawRows = @($Data.LogAnalyticsWorkspaces | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Sku=$_.Sku; RetentionInDays=$_.RetentionInDays; Tags=(New-TagSummary $_.Tags) } })
    $diagRows = @($Data.Diagnostics | Sort-Object ResourceType, ResourceName | ForEach-Object { [pscustomobject]@{ Resource=$_.ResourceName; Type=$_.ResourceType; Diagnostic=$_.DiagnosticName; Workspace=(ConvertTo-ShortId $_.WorkspaceId); Storage=(ConvertTo-ShortId $_.StorageAccountId); EventHub=(ConvertTo-ShortId $_.EventHubAuthorizationRuleId) } })
    $alertRows = @($Data.ActivityLogAlerts | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Enabled=$_.Enabled; Scopes=(@($_.Scopes) -join ', '); Tags=(New-TagSummary $_.Tags) } })
    $gapRows = New-DocumentationGapRows -Data $Data
    $architectureMap = New-ArchitectureMapHtml -Data $Data

    $generated = $Data.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss UTC')

    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AVD-DocAssess Report</title>
<style>
:root { --bg:#0f172a; --panel:#111827; --card:#ffffff; --muted:#64748b; --line:#e2e8f0; --accent:#2563eb; --warn:#b45309; }
body { margin:0; font-family: Segoe UI, Arial, sans-serif; background:#f8fafc; color:#0f172a; }
header { background:linear-gradient(135deg,#0f172a,#1d4ed8); color:white; padding:32px 40px; }
header h1 { margin:0 0 8px; font-size:34px; }
header p { margin:4px 0; color:#dbeafe; }
main { padding:28px 40px 60px; }
section { background:white; border:1px solid var(--line); border-radius:14px; padding:22px; margin:0 0 22px; box-shadow:0 1px 2px rgba(15,23,42,.04); }
h2 { margin:0 0 14px; font-size:22px; }
h3 { margin:22px 0 10px; font-size:17px; color:#1e3a8a; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; }
.card { background:#f8fafc; border:1px solid var(--line); border-radius:12px; padding:16px; }
.card .num { font-size:30px; font-weight:700; color:#1d4ed8; }
.card .label { color:var(--muted); font-size:13px; }
.table-wrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th,td { text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { background:#f1f5f9; color:#334155; font-weight:600; position:sticky; top:0; }
.empty { color:var(--muted); font-style:italic; }
.warning { border-left:4px solid var(--warn); background:#fffbeb; padding:12px 14px; border-radius:8px; }
.arch-map { display:flex; flex-direction:column; gap:18px; }
.arch-row { display:grid; grid-template-columns:minmax(240px,1fr) 42px minmax(240px,1fr) 42px minmax(240px,1fr); gap:10px; align-items:stretch; }
.arch-row.secondary { grid-template-columns:repeat(3,minmax(240px,1fr)); }
.arch-card { border:1px solid #cbd5e1; border-radius:16px; padding:18px; background:linear-gradient(180deg,#ffffff,#f8fafc); box-shadow:0 8px 18px rgba(15,23,42,.06); }
.arch-card.primary { border-color:#93c5fd; background:linear-gradient(180deg,#eff6ff,#ffffff); }
.arch-icon { font-size:26px; margin-bottom:6px; }
.arch-card h3 { margin:0 0 10px; color:#0f172a; font-size:17px; }
.arch-card ul { margin:0; padding-left:18px; line-height:1.6; }
.arch-card li { margin:3px 0; }
.arch-arrow { display:flex; align-items:center; justify-content:center; color:#2563eb; font-size:34px; font-weight:800; }
.muted { color:var(--muted); font-style:italic; }
@media (max-width: 1050px) { .arch-row, .arch-row.secondary { grid-template-columns:1fr; } .arch-arrow { transform:rotate(90deg); min-height:30px; } }
footer { color:var(--muted); font-size:12px; margin-top:28px; }
</style>
</head>
<body>
<header>
  <h1>AVD-DocAssess Report</h1>
  <p>Generated: $(ConvertTo-HtmlSafe $generated)</p>
  <p>Subscription: $(ConvertTo-HtmlSafe $ctx.Subscription.Name) ($(ConvertTo-HtmlSafe $ctx.Subscription.Id)) · Tenant: $(ConvertTo-HtmlSafe $ctx.Tenant.Id)</p>
  <p>Scope: $(ConvertTo-HtmlSafe $Data.Scope)</p>
</header>
<main>
<section>
  <h2>Executive summary</h2>
  <div class="cards">
    <div class="card"><div class="num">$($Data.HostPools.Count)</div><div class="label">Host pools</div></div>
    <div class="card"><div class="num">$($Data.SessionHosts.Count)</div><div class="label">Session hosts</div></div>
    <div class="card"><div class="num">$($Data.ApplicationGroups.Count)</div><div class="label">Application groups</div></div>
    <div class="card"><div class="num">$($Data.Workspaces.Count)</div><div class="label">Workspaces</div></div>
    <div class="card"><div class="num">$($Data.VirtualNetworks.Count)</div><div class="label">VNets</div></div>
    <div class="card"><div class="num">$($Data.RoleAssignments.Count)</div><div class="label">IAM assignments</div></div>
  </div>
  <h3>Documentation gaps / collection notes</h3>
  $(New-TableHtml -Headers @('Area','Gap','Action') -Rows $gapRows -EmptyMessage 'No documentation gaps detected by the v1 collector.')
</section>

<section>
  <h2>Architecture dependency map</h2>
  $architectureMap
</section>

<section>
  <h2>AVD inventory</h2>
  <h3>Host pools</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','Type','LoadBalancer','StartVmOnConnect','PublicNetworkAccess','Tags') -Rows $hostPoolRows)
  <h3>Workspaces</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','ApplicationGroupReferences','Tags') -Rows $workspaceRows)
  <h3>Application groups</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','Type','HostPool','Tags') -Rows $appGroupRows)
  <h3>Scaling plans</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','TimeZone','HostPoolCount','Tags') -Rows $scalingRows)
  <h3>Session hosts</h3>
  $(New-TableHtml -Headers @('HostPool','Name','ResourceGroup','Status','AllowNewSession','Sessions','AgentVersion','UpdateState','VmResourceId') -Rows $Data.SessionHosts)
  <h3>Session host VMs</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','Size','Zones','OSDisk','Tags') -Rows $vmRows)
</section>

<section>
  <h2>IAM</h2>
  $(New-TableHtml -Headers @('Principal','PrincipalType','Role','Scope') -Rows $iamRows)
</section>

<section>
  <h2>Networking</h2>
  <h3>Virtual networks and subnets</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','AddressSpace','Subnets','Tags') -Rows $vnetRows)
  <h3>Session host NICs</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','PrivateIp','Subnet','NSG','AcceleratedNetworking') -Rows $nicRows)
  <h3>Network security groups</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','RuleCount','Tags') -Rows $nsgRows)
  <h3>Route tables</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','RouteCount','DisableBgpRoutePropagation','Tags') -Rows $routeRows)
  <h3>Private endpoints</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','Subnet','Connections','Tags') -Rows $peRows)
</section>

<section>
  <h2>FSLogix / profile storage candidates</h2>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','Sku','Kind','PublicNetworkAccess','Tags') -Rows $storageRows -EmptyMessage 'No likely FSLogix/profile storage accounts found by name or tags.')
</section>

<section>
  <h2>Monitoring and logging</h2>
  <h3>Log Analytics workspaces</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','Sku','RetentionInDays','Tags') -Rows $lawRows)
  <h3>Diagnostic settings</h3>
  $(New-TableHtml -Headers @('Resource','Type','Diagnostic','Workspace','Storage','EventHub') -Rows $diagRows)
  <h3>Activity log alerts</h3>
  $(New-TableHtml -Headers @('Name','ResourceGroup','Location','Enabled','Scopes','Tags') -Rows $alertRows)
</section>

<footer>
  AVD-DocAssess v$($script:ToolVersion). Generated read-only from Azure Resource Manager metadata. Do not commit client-generated reports.
</footer>
</main>
</body>
</html>
"@
}

function Resolve-ReportPath {
    if ($OutputPath) { return $OutputPath }
    return (Join-Path (Get-Location) ("AVD-DocAssess-Report-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
}

function Invoke-Main {
    Write-Host "AVD-DocAssess v$($script:ToolVersion)" -ForegroundColor Cyan
    $context = Connect-DocAssessAzure
    $data = Get-AvdDocumentationData -Context $context
    $html = New-HtmlReport -Data $data
    $path = Resolve-ReportPath
    $parent = Split-Path -Parent $path
    if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Set-Content -Path $path -Value $html -Encoding UTF8
    Write-Host "HTML report saved to: $path" -ForegroundColor Green

    if ($OpenReport) {
        if ($env:ACC_CLOUD) {
            Write-Host 'OpenReport ignored in Azure Cloud Shell. Download the HTML file from Cloud Shell instead.' -ForegroundColor Yellow
        } else {
            Start-Process $path
        }
    }
}

Invoke-Main
