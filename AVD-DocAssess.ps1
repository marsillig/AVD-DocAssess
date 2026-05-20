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
$script:ToolVersion = '0.2.0'
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


function ConvertTo-FriendlyScope {
    param([AllowNull()][string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Scope)) { return '' }
    if ($Scope -eq '/') { return 'Tenant root' }
    if ($Scope -match '/managementGroups/([^/]+)$') { return "Management group: $($Matches[1])" }
    if ($Scope -match '/subscriptions/([^/]+)$') { return "Subscription: $($Matches[1])" }
    if ($Scope -match '/resourceGroups/([^/]+)$') { return "Resource group: $($Matches[1])" }
    if ($Scope -match '/providers/([^/]+/[^/]+)/([^/]+)$') { return "$($Matches[1]): $($Matches[2])" }
    return ConvertTo-ShortId $Scope
}

function ConvertTo-FriendlyList {
    param([AllowNull()][object[]]$Values)
    $items = @($Values | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ConvertTo-FriendlyScope ([string]$_) })
    return ($items -join ', ')
}


function Get-SessionHostSubnetIds {
    param([object]$Data)
    return @($Data.NetworkInterfaces | ForEach-Object {
        foreach ($ipconfig in @($_.IpConfigurations)) { $ipconfig.Subnet.Id }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
}

function Get-SubnetNatGatewayName {
    param([object]$Subnet)
    if ($Subnet.NatGateway -and $Subnet.NatGateway.Id) { return ConvertTo-ShortId $Subnet.NatGateway.Id }
    return ''
}

function Test-IsAvdRelatedRoleAssignment {
    param([object]$RoleAssignment, [object]$Data)
    $scopeText = [string]$RoleAssignment.Scope
    if ($scopeText -match 'Microsoft\.DesktopVirtualization') { return $true }
    if ($RoleAssignment.RoleDefinitionName -match 'Desktop Virtualization|Virtual Machine|Network|Monitoring|Reader|Contributor|Owner') {
        foreach ($hp in @($Data.HostPools)) {
            $rg = Get-RgFromArmId $hp.Id
            if ($rg -and $scopeText -match "/resourceGroups/$([regex]::Escape($rg))(\/|$)") { return $true }
        }
    }
    return $false
}

function New-FindingRows {
    param([object]$Data)
    $rows = [System.Collections.Generic.List[object]]::new()

    $unavailableHosts = @($Data.SessionHosts | Where-Object { $_.Status -and $_.Status -ne 'Available' })
    if ($unavailableHosts.Count -gt 0) {
        $rows.Add([pscustomobject]@{ Priority='High'; Area='Session hosts'; Observation="$($unavailableHosts.Count) session host(s) are not Available"; Recommendation='Review host health, AVD agent status, domain/Entra join, and FSLogix profile dependencies.' }) | Out-Null
    }

    $publicHostPools = @($Data.HostPools | Where-Object { $_.PublicNetworkAccess -eq 'Enabled' -or [string]::IsNullOrWhiteSpace([string]$_.PublicNetworkAccess) })
    if ($publicHostPools.Count -gt 0) {
        $rows.Add([pscustomobject]@{ Priority='Medium'; Area='Connectivity'; Observation="$($publicHostPools.Count) host pool(s) allow public network access or did not expose a private-only setting"; Recommendation='Confirm whether AVD Private Link is required for this environment and document the accepted connectivity model.' }) | Out-Null
    }

    if (@($Data.PrivateEndpoints).Count -eq 0) {
        $rows.Add([pscustomobject]@{ Priority='Medium'; Area='Private endpoints'; Observation='No private endpoints were discovered in the assessed scope'; Recommendation='If Private Link is part of the target architecture, include the hub/spoke networking resource groups in scope or document why public access is accepted.' }) | Out-Null
    }

    $sessionHostSubnetIds = Get-SessionHostSubnetIds -Data $Data
    $sessionHostSubnetsWithoutNat = @()
    foreach ($subnetId in $sessionHostSubnetIds) {
        $subnet = @($Data.VirtualNetworks | ForEach-Object { $_.Subnets } | Where-Object { $_.Id -eq $subnetId } | Select-Object -First 1)
        if (-not $subnet -or -not $subnet.NatGateway -or -not $subnet.NatGateway.Id) { $sessionHostSubnetsWithoutNat += $subnetId }
    }
    if ($sessionHostSubnetIds.Count -gt 0 -and $sessionHostSubnetsWithoutNat.Count -gt 0) {
        $rows.Add([pscustomobject]@{ Priority='Medium'; Area='Outbound internet'; Observation="$($sessionHostSubnetsWithoutNat.Count) session host subnet(s) do not show an associated NAT Gateway"; Recommendation='Document the outbound internet path for AVD session hosts. Use NAT Gateway where stable outbound SNAT is required, or document the approved firewall/NVA/proxy egress design.' }) | Out-Null
    }

    if (@($Data.VirtualNetworkGateways).Count -eq 0 -and @($Data.ExpressRouteCircuits).Count -eq 0) {
        $rows.Add([pscustomobject]@{ Priority='Medium'; Area='Hybrid connectivity'; Observation='No VPN Gateway or ExpressRoute circuit was discovered in the assessed scope'; Recommendation='Confirm whether AVD session hosts require line-of-sight to on-premises domain controllers, DNS, applications, or file services, and document the approved hybrid connectivity path.' }) | Out-Null
    }

    $vnetsWithoutCustomDns = @($Data.VirtualNetworks | Where-Object { -not $_.DhcpOptions -or -not $_.DhcpOptions.DnsServers -or @($_.DhcpOptions.DnsServers).Count -eq 0 })
    if ($Data.VirtualNetworks.Count -gt 0 -and $vnetsWithoutCustomDns.Count -gt 0) {
        $rows.Add([pscustomobject]@{ Priority='Low'; Area='DNS'; Observation="$($vnetsWithoutCustomDns.Count) VNet(s) use Azure-provided DNS or did not expose custom DNS servers"; Recommendation='Document the DNS resolution model for AVD, including domain controller DNS, private endpoints, and conditional forwarding requirements.' }) | Out-Null
    }

    if (@($Data.PrivateDnsZones).Count -eq 0) {
        $rows.Add([pscustomobject]@{ Priority='Low'; Area='Private DNS'; Observation='No Private DNS zones were discovered in the assessed scope'; Recommendation='If Private Link or custom name resolution is used, include the Private DNS zone resource groups in the assessment scope or document the DNS design separately.' }) | Out-Null
    }

    if (@($Data.ScalingPlans).Count -eq 0) {
        $rows.Add([pscustomobject]@{ Priority='Medium'; Area='Cost management'; Observation='No AVD scaling plans were discovered'; Recommendation='Document the operating schedule/capacity approach, or configure AVD autoscale for pooled host pools where appropriate.' }) | Out-Null
    }

    if (@($Data.Diagnostics).Count -eq 0) {
        $rows.Add([pscustomobject]@{ Priority='Medium'; Area='Monitoring'; Observation='No diagnostic settings were collected for AVD/session host resources'; Recommendation='Send AVD diagnostics to Log Analytics and document retention, alerting, and operational ownership.' }) | Out-Null
    }

    $lrsProfileStorage = @($Data.ProfileStorageCandidates | Where-Object { $_.Sku.Name -match '_LRS$' })
    if ($lrsProfileStorage.Count -gt 0) {
        $rows.Add([pscustomobject]@{ Priority='Medium'; Area='FSLogix storage'; Observation="$($lrsProfileStorage.Count) profile storage candidate(s) use locally redundant storage"; Recommendation='Validate whether ZRS/GZRS is required for the customer availability target and document the decision.' }) | Out-Null
    }

    $untaggedHostPools = @($Data.HostPools | Where-Object { -not $_.Tags -or $_.Tags.Count -eq 0 })
    if ($untaggedHostPools.Count -gt 0) {
        $rows.Add([pscustomobject]@{ Priority='Low'; Area='Governance'; Observation="$($untaggedHostPools.Count) host pool(s) have no tags"; Recommendation='Add standard tags such as Environment, Owner, CostCenter, Application, and SupportTeam.' }) | Out-Null
    }

    if ($rows.Count -eq 0) {
        $rows.Add([pscustomobject]@{ Priority='Info'; Area='Summary'; Observation='No high-level documentation concerns were detected by the current collector'; Recommendation='Review the appendix tables for completeness and validate the architecture narrative with the customer.' }) | Out-Null
    }

    return @($rows)
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


function Get-ObjectPropertyValue {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string[]]$Names
    )
    if ($null -eq $InputObject) { return $null }
    foreach ($name in $Names) {
        $prop = $InputObject.PSObject.Properties[$name]
        if ($prop -and -not [string]::IsNullOrWhiteSpace([string]$prop.Value)) { return $prop.Value }
    }
    return $null
}

function Get-CustomerNameFromContext {
    param([object]$Context)

    $tenantIdValue = $Context.Tenant.Id
    $tenant = Invoke-ReadOnly -OperationName 'Get-AzTenant' -Optional -ScriptBlock {
        if ($tenantIdValue) { Get-AzTenant -TenantId $tenantIdValue -ErrorAction Stop } else { Get-AzTenant -ErrorAction Stop | Select-Object -First 1 }
    }

    $domain = Get-ObjectPropertyValue -InputObject $tenant -Names @('DefaultDomain','PrimaryDomain','Domain','Name')
    if (-not $domain) {
        $domains = Get-ObjectPropertyValue -InputObject $tenant -Names @('Domains','VerifiedDomains')
        if ($domains) {
            $domain = @($domains | ForEach-Object {
                if ($_ -is [string]) { $_ } else { Get-ObjectPropertyValue -InputObject $_ -Names @('Name','DomainName','Id') }
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1)
        }
    }

    if (-not $domain -and $Context.Account.Id -match '@(.+)$') { $domain = $Matches[1] }
    if (-not $domain) { $domain = $Context.Subscription.Name }
    if (-not $domain) { $domain = $tenantIdValue }

    return [string]$domain
}

function Get-DiagnosticSettingsSafe {
    param([string]$ResourceId)
    if ([string]::IsNullOrWhiteSpace($ResourceId)) { return @() }
    return @(Invoke-ReadOnly -OperationName "Get-AzDiagnosticSetting ($ResourceId)" -Optional -ScriptBlock {
        Get-AzDiagnosticSetting -ResourceId $ResourceId -ErrorAction Stop -WarningAction SilentlyContinue
    })
}



function Get-ResourcesAcrossScope {
    param(
        [Parameter(Mandatory)][string]$OperationName,
        [Parameter(Mandatory)][scriptblock]$ByResourceGroupScript,
        [scriptblock]$SubscriptionScript
    )

    if ($ResourceGroupName) {
        return @(Invoke-ReadOnly -OperationName $OperationName -Optional -ScriptBlock { & $ByResourceGroupScript $ResourceGroupName })
    }

    if ($SubscriptionScript) {
        $result = @(Invoke-ReadOnly -OperationName $OperationName -Optional -ScriptBlock $SubscriptionScript)
        if ($result.Count -gt 0) { return $result }
    }

    $resourceGroups = @(Invoke-ReadOnly -OperationName 'Get-AzResourceGroup' -Optional -ScriptBlock { Get-AzResourceGroup -ErrorAction Stop })
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($rg in $resourceGroups) {
        $rgName = $rg.ResourceGroupName
        $items = @(Invoke-ReadOnly -OperationName "$OperationName ($rgName)" -Optional -ScriptBlock { & $ByResourceGroupScript $rgName })
        foreach ($item in $items) { $all.Add($item) | Out-Null }
    }
    return @($all)
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
                VmResource = (ConvertTo-FriendlyScope $sessionHost.ResourceId)
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

    $natGateways = if ($ResourceGroupName) {
        @(Invoke-ReadOnly -OperationName 'Get-AzNatGateway' -Optional -ScriptBlock { Get-AzNatGateway -ResourceGroupName $ResourceGroupName -ErrorAction Stop })
    } else {
        @(Invoke-ReadOnly -OperationName 'Get-AzNatGateway' -Optional -ScriptBlock { Get-AzNatGateway -ErrorAction Stop })
    }

    $virtualNetworkGateways = Get-ResourcesAcrossScope -OperationName 'Get-AzVirtualNetworkGateway' -ByResourceGroupScript {
        param($rgName) Get-AzVirtualNetworkGateway -ResourceGroupName $rgName -ErrorAction Stop
    }

    $localNetworkGateways = Get-ResourcesAcrossScope -OperationName 'Get-AzLocalNetworkGateway' -ByResourceGroupScript {
        param($rgName) Get-AzLocalNetworkGateway -ResourceGroupName $rgName -ErrorAction Stop
    }

    $expressRouteCircuits = Get-ResourcesAcrossScope -OperationName 'Get-AzExpressRouteCircuit' -ByResourceGroupScript {
        param($rgName) Get-AzExpressRouteCircuit -ResourceGroupName $rgName -ErrorAction Stop
    } -SubscriptionScript {
        Get-AzExpressRouteCircuit -ErrorAction Stop
    }

    $privateDnsZones = Get-ResourcesAcrossScope -OperationName 'Get-AzPrivateDnsZone' -ByResourceGroupScript {
        param($rgName) Get-AzPrivateDnsZone -ResourceGroupName $rgName -ErrorAction Stop
    } -SubscriptionScript {
        Get-AzPrivateDnsZone -ErrorAction Stop
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

    $profileStorageCandidates = @($storageAccounts | Where-Object {
        $_.StorageAccountName -match 'fslogix|profile|avd' -or
        ($_.Tags.Keys -contains 'FSLogixStorageAccount') -or
        ($_.Tags.Keys -contains 'Purpose' -and $_.Tags['Purpose'] -match 'fslogix|profile|avd')
    })

    return [pscustomobject]@{
        Context = $Context
        CustomerName = (Get-CustomerNameFromContext -Context $Context)
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
        NatGateways = $natGateways
        VirtualNetworkGateways = $virtualNetworkGateways
        LocalNetworkGateways = $localNetworkGateways
        ExpressRouteCircuits = $expressRouteCircuits
        PrivateDnsZones = $privateDnsZones
        PrivateEndpoints = $privateEndpoints
        StorageAccounts = $storageAccounts
        ProfileStorageCandidates = $profileStorageCandidates
        RoleAssignments = $roleAssignments
        LogAnalyticsWorkspaces = $workspacesLa
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


function New-CollapsibleSectionHtml {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Content,
        [switch]$Open
    )
    $openAttr = if ($Open) { ' open' } else { '' }
    return "<details class='collapsible'$openAttr><summary><span class='plus'></span>$(ConvertTo-HtmlSafe $Title)</summary><div class='collapsible-body'>$Content</div></details>"
}

function New-TagSummary {
    param([AllowNull()][hashtable]$Tags)
    if (-not $Tags -or $Tags.Count -eq 0) { return '' }
    return (($Tags.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
}



function New-ArchitectureMapHtml {
    param([object]$Data)

    function New-CompactItemsHtml {
        param(
            [object[]]$Items,
            [scriptblock]$Label,
            [string]$EmptyText = 'None discovered',
            [int]$MaxItems = 3
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

    function New-ChipHtml {
        param([string]$Text, [string]$Kind = 'info')
        return "<span class='lz-chip $Kind'>$(ConvertTo-HtmlSafe $Text)</span>"
    }

    $avdRelatedAssignments = @($Data.RoleAssignments | Where-Object { Test-IsAvdRelatedRoleAssignment -RoleAssignment $_ -Data $Data })
    $inheritedAssignments = @($Data.RoleAssignments | Where-Object { -not (Test-IsAvdRelatedRoleAssignment -RoleAssignment $_ -Data $Data) })
    $unavailableHosts = @($Data.SessionHosts | Where-Object { $_.Status -and $_.Status -ne 'Available' })
    $sessionHostSubnetIds = Get-SessionHostSubnetIds -Data $Data
    $subnetsWithNat = 0
    foreach ($subnetId in $sessionHostSubnetIds) {
        $subnet = @($Data.VirtualNetworks | ForEach-Object { $_.Subnets } | Where-Object { $_.Id -eq $subnetId } | Select-Object -First 1)
        if ($subnet -and $subnet.NatGateway -and $subnet.NatGateway.Id) { $subnetsWithNat++ }
    }

    $identityChips = @(
        New-ChipHtml -Text "$($Data.RoleAssignments.Count) IAM assignments" -Kind 'info'
        New-ChipHtml -Text "$($avdRelatedAssignments.Count) AVD-related" -Kind 'good'
        New-ChipHtml -Text "$($inheritedAssignments.Count) inherited/broader" -Kind 'neutral'
    ) -join ''

    $controlPlaneItems = @(
        New-CompactItemsHtml -Items $Data.Workspaces -Label { param($x) "Workspace: $($x.Name)" }
        New-CompactItemsHtml -Items $Data.ApplicationGroups -Label { param($x) "App group: $($x.Name)" }
        New-CompactItemsHtml -Items $Data.HostPools -Label { param($x) "Host pool: $($x.Name)" }
    ) -join ''

    $monitoringChips = if (@($Data.Diagnostics).Count -gt 0) {
        New-ChipHtml -Text 'Diagnostics configured' -Kind 'good'
    } else {
        New-ChipHtml -Text 'Diagnostics not discovered' -Kind 'warn'
    }
    $monitoringItems = @(
        New-CompactItemsHtml -Items $Data.LogAnalyticsWorkspaces -Label { param($x) "Log Analytics: $($x.Name)" }
        New-CompactItemsHtml -Items $Data.Diagnostics -Label { param($x) "Diagnostic: $($x.ResourceName)" } -EmptyText 'No diagnostic settings discovered'
    ) -join ''

    $computeChips = if ($unavailableHosts.Count -gt 0) {
        New-ChipHtml -Text "$($unavailableHosts.Count) host unavailable" -Kind 'bad'
    } else {
        New-ChipHtml -Text 'Hosts available' -Kind 'good'
    }
    $computeItems = New-CompactItemsHtml -Items $Data.SessionHostVms -Label { param($x) "VM: $($x.Name) ($($x.HardwareProfile.VmSize))" }

    $networkChips = @(
        if (@($Data.NatGateways).Count -gt 0 -or $subnetsWithNat -gt 0) { New-ChipHtml -Text 'NAT Gateway present' -Kind 'good' } else { New-ChipHtml -Text 'NAT Gateway missing' -Kind 'warn' }
        if (@($Data.PrivateEndpoints).Count -gt 0) { New-ChipHtml -Text 'Private endpoint present' -Kind 'good' } else { New-ChipHtml -Text 'Private endpoint missing' -Kind 'warn' }
        if ($sessionHostSubnetIds.Count -gt 0) { New-ChipHtml -Text "$($sessionHostSubnetIds.Count) session host subnet(s)" -Kind 'info' }
    ) -join ''
    $networkItems = @(
        New-CompactItemsHtml -Items $Data.VirtualNetworks -Label { param($x) "VNet: $($x.Name)" }
        New-CompactItemsHtml -Items $Data.NatGateways -Label { param($x) "NAT: $($x.Name)" } -EmptyText 'No NAT Gateway discovered'
    ) -join ''

    $hybridChips = @(
        if (@($Data.VirtualNetworkGateways).Count -gt 0) { New-ChipHtml -Text 'VPN Gateway present' -Kind 'good' } else { New-ChipHtml -Text 'VPN Gateway not discovered' -Kind 'neutral' }
        if (@($Data.ExpressRouteCircuits).Count -gt 0) { New-ChipHtml -Text 'ExpressRoute present' -Kind 'good' } else { New-ChipHtml -Text 'ExpressRoute not discovered' -Kind 'neutral' }
        if (@($Data.PrivateDnsZones).Count -gt 0) { New-ChipHtml -Text 'Private DNS present' -Kind 'good' } else { New-ChipHtml -Text 'Private DNS not discovered' -Kind 'warn' }
    ) -join ''
    $hybridItems = @(
        New-CompactItemsHtml -Items $Data.VirtualNetworkGateways -Label { param($x) "VPN Gateway: $($x.Name)" } -EmptyText 'No VPN Gateway discovered'
        New-CompactItemsHtml -Items $Data.ExpressRouteCircuits -Label { param($x) "ExpressRoute: $($x.Name)" } -EmptyText 'No ExpressRoute circuit discovered'
        New-CompactItemsHtml -Items $Data.PrivateDnsZones -Label { param($x) "Private DNS: $($x.Name)" } -EmptyText 'No Private DNS zone discovered'
    ) -join ''

    $storageChips = if (@($Data.ProfileStorageCandidates).Count -gt 0) {
        New-ChipHtml -Text "$($Data.ProfileStorageCandidates.Count) profile candidate(s)" -Kind 'info'
    } else {
        New-ChipHtml -Text 'Profile storage not identified' -Kind 'warn'
    }
    $storageItems = New-CompactItemsHtml -Items $Data.ProfileStorageCandidates -Label { param($x) "Storage: $($x.StorageAccountName) ($($x.Sku.Name))" } -EmptyText 'No profile storage candidate discovered'

    return @"
<div class="lz-map">
  <div class="lz-titlebar">
    <div>
      <div class="lz-eyebrow">Architecture view</div>
      <div class="lz-title">Azure Virtual Desktop deployment flow</div>
    </div>
    <div class="lz-legend">Summary view only — details remain in the sections below</div>
  </div>

  <div class="lz-layer top">
    <div class="lz-box identity">
      <div class="lz-icon">🔐</div>
      <h3>Identity & IAM</h3>
      <div class="lz-chips">$identityChips</div>
    </div>
    <div class="lz-box control">
      <div class="lz-icon">🖥️</div>
      <h3>AVD control plane</h3>
      <ul>$controlPlaneItems</ul>
    </div>
    <div class="lz-box monitor">
      <div class="lz-icon">📊</div>
      <h3>Monitoring</h3>
      <div class="lz-chips">$monitoringChips</div>
      <ul>$monitoringItems</ul>
    </div>
  </div>

  <div class="lz-connector down">↓</div>

  <div class="lz-layer middle">
    <div class="lz-box compute wide">
      <div class="lz-icon">⚙️</div>
      <h3>Session host compute</h3>
      <div class="lz-chips">$computeChips</div>
      <ul>$computeItems</ul>
    </div>
  </div>

  <div class="lz-connector split">↙ outbound / profiles ↘</div>

  <div class="lz-layer bottom">
    <div class="lz-box network">
      <div class="lz-icon">🌐</div>
      <h3>Network & outbound internet</h3>
      <div class="lz-chips">$networkChips</div>
      <ul>$networkItems</ul>
    </div>
    <div class="lz-box hybrid">
      <div class="lz-icon">🔗</div>
      <h3>Hybrid connectivity & DNS</h3>
      <div class="lz-chips">$hybridChips</div>
      <ul>$hybridItems</ul>
    </div>
    <div class="lz-box storage">
      <div class="lz-icon">💾</div>
      <h3>Profiles / storage</h3>
      <div class="lz-chips">$storageChips</div>
      <ul>$storageItems</ul>
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


function New-FindingCardsHtml {
    param([AllowNull()][object[]]$Rows)
    $safeRows = @($Rows)
    if ($safeRows.Count -eq 0) { return '<p class="empty">No executive findings generated.</p>' }
    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append('<div class="findings-grid">')
    foreach ($row in $safeRows) {
        $priority = if ($row.Priority) { [string]$row.Priority } else { 'Info' }
        $priorityClass = $priority.ToLowerInvariant()
        if ($priorityClass -notin @('high','medium','low','info')) { $priorityClass = 'info' }
        [void]$html.Append('<div class="finding-card">')
        [void]$html.Append("<span class='badge badge-$priorityClass'>$(ConvertTo-HtmlSafe $priority)</span>")
        [void]$html.Append("<h3>$(ConvertTo-HtmlSafe $row.Area)</h3>")
        [void]$html.Append("<p><strong>Observation:</strong> $(ConvertTo-HtmlSafe $row.Observation)</p>")
        [void]$html.Append("<p><strong>Recommended action:</strong> $(ConvertTo-HtmlSafe $row.Recommendation)</p>")
        [void]$html.Append('</div>')
    }
    [void]$html.Append('</div>')
    return $html.ToString()
}

function New-SectionFindingsHtml {
    param([AllowNull()][object[]]$Rows)
    $safeRows = @($Rows)
    if ($safeRows.Count -eq 0) { return '' }

    $html = [System.Text.StringBuilder]::new()
    [void]$html.Append('<div class="section-findings">')
    foreach ($row in $safeRows) {
        $priority = if ($row.Priority) { [string]$row.Priority } else { 'Info' }
        $priorityClass = $priority.ToLowerInvariant()
        if ($priorityClass -notin @('high','medium','low','info')) { $priorityClass = 'info' }
        [void]$html.Append("<div class='section-finding section-finding-$priorityClass'>")
        [void]$html.Append("<div class='section-finding-head'><span class='mini-badge mini-badge-$priorityClass'>$(ConvertTo-HtmlSafe $priority)</span><strong>$(ConvertTo-HtmlSafe $row.Area)</strong></div>")
        [void]$html.Append("<div class='section-finding-text'><strong>Observation:</strong> $(ConvertTo-HtmlSafe $row.Observation)</div>")
        [void]$html.Append("<div class='section-finding-text'><strong>Recommended action:</strong> $(ConvertTo-HtmlSafe $row.Recommendation)</div>")
        [void]$html.Append('</div>')
    }
    [void]$html.Append('</div>')
    return $html.ToString()
}

function New-HtmlReport {
    param([object]$Data)

    $ctx = $Data.Context
    $reportCustomerName = if ($Data.CustomerName) { $Data.CustomerName } else { $ctx.Subscription.Name }
    $reportTitle = "$(ConvertTo-HtmlSafe $reportCustomerName) - Azure Virtual Desktop Deployment Report"
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
    $workspaceRows = @($Data.Workspaces | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=(Get-RgFromArmId $_.Id); Location=$_.Location; ApplicationGroups=(ConvertTo-FriendlyList @($_.ApplicationGroupReference)); Tags=(New-TagSummary $_.Tags) } })
    $appGroupRows = @($Data.ApplicationGroups | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=(Get-RgFromArmId $_.Id); Location=$_.Location; Type=$_.ApplicationGroupType; HostPool=(ConvertTo-ShortId $_.HostPoolArmPath); Tags=(New-TagSummary $_.Tags) } })
    $scalingRows = @($Data.ScalingPlans | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=(Get-RgFromArmId $_.Id); Location=$_.Location; TimeZone=$_.TimeZone; HostPoolCount=@($_.HostPoolReference).Count; Tags=(New-TagSummary $_.Tags) } })
    $vmRows = @($Data.SessionHostVms | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Size=$_.HardwareProfile.VmSize; Zones=(@($_.Zones) -join ', '); OSDisk=$_.StorageProfile.OsDisk.ManagedDisk.StorageAccountType; Tags=(New-TagSummary $_.Tags) } })
    $nicRows = @($Data.NetworkInterfaces | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; PrivateIp=(@($_.IpConfigurations | ForEach-Object { $_.PrivateIpAddress }) -join ', '); Subnet=(@($_.IpConfigurations | ForEach-Object { ConvertTo-ShortId $_.Subnet.Id }) -join ', '); NSG=(ConvertTo-ShortId $_.NetworkSecurityGroup.Id); AcceleratedNetworking=$_.EnableAcceleratedNetworking } })
    $vnetRows = @($Data.VirtualNetworks | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; AddressSpace=(@($_.AddressSpace.AddressPrefixes) -join ', '); Subnets=(@($_.Subnets | ForEach-Object { "$($_.Name) [$($_.AddressPrefix)]" }) -join '; '); Tags=(New-TagSummary $_.Tags) } })
    $nsgRows = @($Data.NetworkSecurityGroups | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; RuleCount=@($_.SecurityRules).Count; Tags=(New-TagSummary $_.Tags) } })
    $routeRows = @($Data.RouteTables | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; RouteCount=@($_.Routes).Count; DisableBgpRoutePropagation=$_.DisableBgpRoutePropagation; Tags=(New-TagSummary $_.Tags) } })
    $natRows = @($Data.NatGateways | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Sku=$_.Sku.Name; PublicIpCount=@($_.PublicIpAddresses).Count; PublicIpPrefixCount=@($_.PublicIpPrefixes).Count; IdleTimeoutInMinutes=$_.IdleTimeoutInMinutes; Zones=(@($_.Zones) -join ', '); Tags=(New-TagSummary $_.Tags) } })
    $subnetOutboundRows = @($Data.VirtualNetworks | Sort-Object Name | ForEach-Object { $vnet = $_; @($vnet.Subnets | ForEach-Object { [pscustomobject]@{ VNet=$vnet.Name; Subnet=$_.Name; AddressPrefix=$_.AddressPrefix; NatGateway=(Get-SubnetNatGatewayName $_); RouteTable=(ConvertTo-ShortId $_.RouteTable.Id); NSG=(ConvertTo-ShortId $_.NetworkSecurityGroup.Id) } }) })
    $vnetDnsRows = @($Data.VirtualNetworks | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; DnsServers=(@($_.DhcpOptions.DnsServers) -join ', '); UsesAzureProvidedDns=((-not $_.DhcpOptions) -or (-not $_.DhcpOptions.DnsServers) -or @($_.DhcpOptions.DnsServers).Count -eq 0) } })
    $vngRows = @($Data.VirtualNetworkGateways | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; GatewayType=$_.GatewayType; VpnType=$_.VpnType; Sku=$_.Sku.Name; EnableBgp=$_.EnableBgp; ActiveActive=$_.ActiveActive; Tags=(New-TagSummary $_.Tags) } })
    $lngRows = @($Data.LocalNetworkGateways | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; GatewayIpAddress=$_.GatewayIpAddress; AddressPrefixes=(@($_.LocalNetworkAddressSpace.AddressPrefixes) -join ', '); Tags=(New-TagSummary $_.Tags) } })
    $erRows = @($Data.ExpressRouteCircuits | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; ServiceProvider=$_.ServiceProviderProperties.ServiceProviderName; PeeringLocation=$_.ServiceProviderProperties.PeeringLocation; BandwidthMbps=$_.ServiceProviderProperties.BandwidthInMbps; Sku=$_.Sku.Tier; Family=$_.Sku.Family; ProvisioningState=$_.ServiceProviderProvisioningState; Tags=(New-TagSummary $_.Tags) } })
    $privateDnsRows = @($Data.PrivateDnsZones | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; RecordSets=$_.NumberOfRecordSets; Tags=(New-TagSummary $_.Tags) } })
    $peRows = @($Data.PrivateEndpoints | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Subnet=(ConvertTo-ShortId $_.Subnet.Id); Connections=(@($_.PrivateLinkServiceConnections | ForEach-Object { ConvertTo-ShortId $_.PrivateLinkServiceId }) -join ', '); Tags=(New-TagSummary $_.Tags) } })
    $storageRows = @($Data.ProfileStorageCandidates | Sort-Object StorageAccountName | ForEach-Object { [pscustomobject]@{ Name=$_.StorageAccountName; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Sku=$_.Sku.Name; Kind=$_.Kind; PublicNetworkAccess=$_.PublicNetworkAccess; Tags=(New-TagSummary $_.Tags) } })
    $iamRows = @($Data.RoleAssignments | Sort-Object Scope, RoleDefinitionName | ForEach-Object { [pscustomobject]@{ Principal=$_.DisplayName; PrincipalType=$_.ObjectType; Role=$_.RoleDefinitionName; Scope=(ConvertTo-FriendlyScope $_.Scope) } })
    $avdIamRows = @($Data.RoleAssignments | Where-Object { Test-IsAvdRelatedRoleAssignment -RoleAssignment $_ -Data $Data } | Sort-Object Scope, RoleDefinitionName | ForEach-Object { [pscustomobject]@{ Principal=$_.DisplayName; PrincipalType=$_.ObjectType; Role=$_.RoleDefinitionName; Scope=(ConvertTo-FriendlyScope $_.Scope) } })
    $inheritedIamRows = @($Data.RoleAssignments | Where-Object { -not (Test-IsAvdRelatedRoleAssignment -RoleAssignment $_ -Data $Data) } | Sort-Object Scope, RoleDefinitionName | ForEach-Object { [pscustomobject]@{ Principal=$_.DisplayName; PrincipalType=$_.ObjectType; Role=$_.RoleDefinitionName; Scope=(ConvertTo-FriendlyScope $_.Scope) } })
    $lawRows = @($Data.LogAnalyticsWorkspaces | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Name=$_.Name; ResourceGroup=$_.ResourceGroupName; Location=$_.Location; Sku=$_.Sku; RetentionInDays=$_.RetentionInDays; Tags=(New-TagSummary $_.Tags) } })
    $diagRows = @($Data.Diagnostics | Sort-Object ResourceType, ResourceName | ForEach-Object { [pscustomobject]@{ Resource=$_.ResourceName; Type=$_.ResourceType; Diagnostic=$_.DiagnosticName; Workspace=(ConvertTo-ShortId $_.WorkspaceId); Storage=(ConvertTo-ShortId $_.StorageAccountId); EventHub=(ConvertTo-ShortId $_.EventHubAuthorizationRuleId) } })
    $findingRows = New-FindingRows -Data $Data
    $inventoryFindingRows = @($findingRows | Where-Object { $_.Area -in @('Session hosts','Cost management','Governance','Summary') })
    $networkFindingRows = @($findingRows | Where-Object { $_.Area -in @('Connectivity','Private endpoints','Outbound internet','Hybrid connectivity','DNS','Private DNS') })
    $storageFindingRows = @($findingRows | Where-Object { $_.Area -in @('FSLogix storage') })
    $monitoringFindingRows = @($findingRows | Where-Object { $_.Area -in @('Monitoring') })
    $inventoryFindingsHtml = New-SectionFindingsHtml -Rows $inventoryFindingRows
    $networkFindingsHtml = New-SectionFindingsHtml -Rows $networkFindingRows
    $storageFindingsHtml = New-SectionFindingsHtml -Rows $storageFindingRows
    $monitoringFindingsHtml = New-SectionFindingsHtml -Rows $monitoringFindingRows
    $gapRows = New-DocumentationGapRows -Data $Data
    $architectureMap = New-ArchitectureMapHtml -Data $Data

    $avdInventoryHtml = @(
        (New-CollapsibleSectionHtml -Title 'Host pools' -Open -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','Type','LoadBalancer','StartVmOnConnect','PublicNetworkAccess','Tags') -Rows $hostPoolRows)),
        (New-CollapsibleSectionHtml -Title 'Workspaces' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','ApplicationGroups','Tags') -Rows $workspaceRows)),
        (New-CollapsibleSectionHtml -Title 'Application groups' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','Type','HostPool','Tags') -Rows $appGroupRows)),
        (New-CollapsibleSectionHtml -Title 'Scaling plans' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','TimeZone','HostPoolCount','Tags') -Rows $scalingRows)),
        (New-CollapsibleSectionHtml -Title 'Session hosts' -Open -Content (New-TableHtml -Headers @('HostPool','Name','ResourceGroup','Status','AllowNewSession','Sessions','AgentVersion','UpdateState','VmResource') -Rows $Data.SessionHosts)),
        (New-CollapsibleSectionHtml -Title 'Session host VMs' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','Size','Zones','OSDisk','Tags') -Rows $vmRows))
    ) -join "`n"

    $iamSummaryHtml = @(
        (New-CollapsibleSectionHtml -Title 'AVD-related assignments' -Open -Content (New-TableHtml -Headers @('Principal','PrincipalType','Role','Scope') -Rows $avdIamRows -EmptyMessage 'No AVD-related role assignments were identified in the assessed scope.')),
        (New-CollapsibleSectionHtml -Title 'Inherited / broader-scope assignments' -Content (New-TableHtml -Headers @('Principal','PrincipalType','Role','Scope') -Rows $inheritedIamRows -EmptyMessage 'No broader-scope role assignments were collected.'))
    ) -join "`n"

    $networkingHtml = @(
        (New-CollapsibleSectionHtml -Title 'Virtual networks and subnets' -Open -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','AddressSpace','Subnets','Tags') -Rows $vnetRows)),
        (New-CollapsibleSectionHtml -Title 'Session host NICs' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','PrivateIp','Subnet','NSG','AcceleratedNetworking') -Rows $nicRows)),
        (New-CollapsibleSectionHtml -Title 'Network security groups' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','RuleCount','Tags') -Rows $nsgRows)),
        (New-CollapsibleSectionHtml -Title 'Subnet outbound configuration' -Open -Content (New-TableHtml -Headers @('VNet','Subnet','AddressPrefix','NatGateway','RouteTable','NSG') -Rows $subnetOutboundRows)),
        (New-CollapsibleSectionHtml -Title 'NAT Gateways' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','Sku','PublicIpCount','PublicIpPrefixCount','IdleTimeoutInMinutes','Zones','Tags') -Rows $natRows -EmptyMessage 'No NAT Gateways were discovered in the assessed scope.')),
        (New-CollapsibleSectionHtml -Title 'VNet DNS configuration' -Open -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','DnsServers','UsesAzureProvidedDns') -Rows $vnetDnsRows)),
        (New-CollapsibleSectionHtml -Title 'VPN Gateways' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','GatewayType','VpnType','Sku','EnableBgp','ActiveActive','Tags') -Rows $vngRows -EmptyMessage 'No VPN Gateways were discovered in the assessed scope.')),
        (New-CollapsibleSectionHtml -Title 'Local Network Gateways' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','GatewayIpAddress','AddressPrefixes','Tags') -Rows $lngRows -EmptyMessage 'No Local Network Gateways were discovered in the assessed scope.')),
        (New-CollapsibleSectionHtml -Title 'ExpressRoute circuits' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','ServiceProvider','PeeringLocation','BandwidthMbps','Sku','Family','ProvisioningState','Tags') -Rows $erRows -EmptyMessage 'No ExpressRoute circuits were discovered in the assessed scope.')),
        (New-CollapsibleSectionHtml -Title 'Private DNS zones' -Content (New-TableHtml -Headers @('Name','ResourceGroup','RecordSets','Tags') -Rows $privateDnsRows -EmptyMessage 'No Private DNS zones were discovered in the assessed scope.')),
        (New-CollapsibleSectionHtml -Title 'Route tables' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','RouteCount','DisableBgpRoutePropagation','Tags') -Rows $routeRows)),
        (New-CollapsibleSectionHtml -Title 'Private endpoints' -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','Subnet','Connections','Tags') -Rows $peRows))
    ) -join "`n"

    $monitoringHtml = @(
        (New-CollapsibleSectionHtml -Title 'Log Analytics workspaces' -Open -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','Sku','RetentionInDays','Tags') -Rows $lawRows)),
        (New-CollapsibleSectionHtml -Title 'Diagnostic settings' -Content (New-TableHtml -Headers @('Resource','Type','Diagnostic','Workspace','Storage','EventHub') -Rows $diagRows))
    ) -join "`n"

    $profileStorageHtml = New-CollapsibleSectionHtml -Title 'Profile storage candidates' -Open -Content (New-TableHtml -Headers @('Name','ResourceGroup','Location','Sku','Kind','PublicNetworkAccess','Tags') -Rows $storageRows -EmptyMessage 'No likely FSLogix/profile storage accounts found by name or tags.')

    $generated = $Data.GeneratedAt.ToString('yyyy-MM-dd HH:mm:ss UTC')

    return @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$reportTitle</title>
<style>
:root {
  color-scheme: light;
  --bg:#f8fafc;
  --surface:#ffffff;
  --surface-soft:#f1f5f9;
  --line:#dbe5ef;
  --line-strong:#cbd5e1;
  --text:#0f172a;
  --muted:#64748b;
  --accent:#2563eb;
  --accent-soft:#eff6ff;
  --cyan:#0891b2;
  --lime:#65a30d;
  --warn:#b45309;
  --danger:#b91c1c;
}
* { box-sizing:border-box; }
body {
  margin:0;
  font-family:'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background:var(--bg);
  color:var(--text);
  line-height:1.5;
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
}
.container { max-width:1280px; margin:0 auto; padding:32px 24px 48px; }
header.hero {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:24px;
  background:linear-gradient(180deg,#ffffff,#f8fbff);
  border:1px solid var(--line);
  border-radius:18px;
  padding:32px;
  margin-bottom:18px;
  box-shadow:0 14px 35px rgba(15,23,42,.07);
}
.brand { display:flex; flex-direction:column; gap:7px; }
.brand-name { font-size:34px; font-weight:800; letter-spacing:-.03em; color:var(--text); }
.brand-name .dot { color:var(--lime); }
.brand-sub { font-size:13px; color:var(--muted); letter-spacing:.02em; }
.report-mark {
  min-width:150px;
  min-height:112px;
  border-radius:18px;
  background:linear-gradient(135deg,var(--accent),#0f766e);
  color:white;
  display:flex;
  flex-direction:column;
  justify-content:center;
  align-items:center;
  box-shadow:0 14px 28px rgba(37,99,235,.18);
}
.report-mark .big { font-size:38px; font-weight:800; line-height:1; }
.report-mark .label { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.12em; opacity:.85; margin-top:8px; }
.meta-bar {
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
  gap:1px;
  background:var(--line);
  border:1px solid var(--line);
  border-radius:14px;
  overflow:hidden;
  margin-bottom:24px;
  box-shadow:0 6px 18px rgba(15,23,42,.04);
}
.meta-bar .cell { background:var(--surface); padding:14px 18px; }
.meta-label { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.1em; margin-bottom:5px; font-weight:700; }
.meta-value { font-size:14px; color:var(--text); font-weight:600; word-break:break-word; }
section {
  background:var(--surface);
  border:1px solid var(--line);
  border-radius:18px;
  padding:26px;
  margin:0 0 22px;
  box-shadow:0 8px 24px rgba(15,23,42,.045);
}
h2 { margin:0 0 16px; font-size:22px; letter-spacing:-.015em; }
h3 { margin:22px 0 10px; font-size:16px; color:#1e3a8a; }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:14px; margin-bottom:18px; }
.card {
  background:linear-gradient(180deg,#ffffff,#f8fafc);
  border:1px solid var(--line);
  border-radius:14px;
  padding:16px;
}
.card .num { font-size:34px; font-weight:800; color:var(--accent); line-height:1; letter-spacing:-.03em; }
.card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; font-weight:700; margin-top:6px; }
.table-wrap { overflow-x:auto; border:1px solid var(--line); border-radius:12px; }
table { width:100%; border-collapse:collapse; font-size:13px; background:#fff; }
th,td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
th { background:#f1f5f9; color:#334155; font-weight:700; font-size:11px; text-transform:uppercase; letter-spacing:.05em; position:sticky; top:0; }
tr:last-child td { border-bottom:0; }
.empty { color:var(--muted); font-style:italic; }
.warning { border-left:4px solid var(--warn); background:#fffbeb; padding:12px 14px; border-radius:8px; }
.report-intro { color:#334155; max-width:1100px; line-height:1.6; margin:8px 0 18px; }
.findings-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px; margin-top:14px; }
.finding-card {
  border:1px solid var(--line);
  border-radius:14px;
  padding:16px;
  background:linear-gradient(180deg,#ffffff,#f8fafc);
}
.finding-card h3 { margin:3px 0 8px; color:var(--text); }
.finding-card p { margin:8px 0; color:#334155; }
.badge { display:inline-block; border-radius:999px; padding:3px 10px; font-size:11px; font-weight:800; margin-bottom:8px; text-transform:uppercase; letter-spacing:.04em; }
.badge-high { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
.badge-medium { background:#fef3c7; color:#92400e; border:1px solid #fde68a; }
.badge-low { background:#dbeafe; color:#1e40af; border:1px solid #bfdbfe; }
.badge-info { background:#dcfce7; color:#166534; border:1px solid #bbf7d0; }
.section-findings { display:grid; gap:9px; margin:12px 0 18px; }
.section-finding { border:1px solid var(--line); border-left:4px solid var(--accent); border-radius:12px; padding:11px 13px; background:#f8fafc; }
.section-finding-high { border-left-color:#ef4444; background:#fff7f7; }
.section-finding-medium { border-left-color:#f59e0b; background:#fffbeb; }
.section-finding-low { border-left-color:#3b82f6; background:#eff6ff; }
.section-finding-info { border-left-color:#22c55e; background:#f0fdf4; }
.section-finding-head { display:flex; align-items:center; gap:8px; margin-bottom:5px; color:var(--text); }
.section-finding-text { color:#334155; font-size:13px; margin:3px 0; }
.mini-badge { display:inline-block; border-radius:999px; padding:2px 8px; font-size:10px; font-weight:800; text-transform:uppercase; letter-spacing:.04em; }
.mini-badge-high { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
.mini-badge-medium { background:#fef3c7; color:#92400e; border:1px solid #fde68a; }
.mini-badge-low { background:#dbeafe; color:#1e40af; border:1px solid #bfdbfe; }
.mini-badge-info { background:#dcfce7; color:#166534; border:1px solid #bbf7d0; }
.appendix-note { color:#475569; font-size:14px; margin-top:-4px; }
.collapsible { border:1px solid var(--line); border-radius:14px; margin:12px 0; background:#fff; overflow:hidden; }
.collapsible summary { cursor:pointer; list-style:none; padding:14px 16px; font-weight:800; color:#1e3a8a; background:#f8fafc; display:flex; align-items:center; gap:10px; }
.collapsible summary:hover { background:#eff6ff; }
.collapsible summary::-webkit-details-marker { display:none; }
.collapsible .plus::before { content:'+'; display:inline-flex; align-items:center; justify-content:center; width:21px; height:21px; border-radius:999px; color:white; background:var(--accent); font-weight:900; line-height:1; }
.collapsible[open] .plus::before { content:'−'; background:#475569; }
.collapsible-body { padding:14px 16px 18px; }
.lz-map {
  border:1px solid var(--line);
  border-radius:18px;
  padding:22px;
  background:linear-gradient(180deg,#ffffff,#f8fafc);
  box-shadow:0 10px 26px rgba(15,23,42,.045);
}
.lz-titlebar { display:flex; align-items:flex-start; justify-content:space-between; gap:18px; margin-bottom:18px; }
.lz-eyebrow { font-size:11px; color:var(--accent); text-transform:uppercase; letter-spacing:.12em; font-weight:800; }
.lz-title { font-size:20px; font-weight:800; color:var(--text); letter-spacing:-.02em; }
.lz-legend { color:var(--muted); font-size:13px; text-align:right; max-width:320px; }
.lz-layer { display:grid; gap:16px; align-items:stretch; }
.lz-layer.top { grid-template-columns:1fr 1.35fr 1fr; }
.lz-layer.middle { grid-template-columns:minmax(280px, .72fr); justify-content:center; }
.lz-layer.bottom { grid-template-columns:1fr 1fr 1fr; }
.lz-box {
  border:1px solid var(--line-strong);
  border-radius:16px;
  padding:16px;
  background:#fff;
  min-height:154px;
  box-shadow:0 8px 18px rgba(15,23,42,.04);
}
.lz-box.control { border-color:#93c5fd; background:linear-gradient(180deg,#eff6ff,#ffffff); }
.lz-box.compute { border-color:#67e8f9; background:linear-gradient(180deg,#ecfeff,#ffffff); }
.lz-box.network { border-color:#bfdbfe; }
.lz-box.storage { border-color:#c4b5fd; }
.lz-box.hybrid { border-color:#99f6e4; }
.lz-box.identity { border-color:#fde68a; }
.lz-box.monitor { border-color:#bbf7d0; }
.lz-icon { font-size:24px; margin-bottom:6px; }
.lz-box h3 { margin:0 0 10px; color:var(--text); font-size:16px; }
.lz-box ul { margin:10px 0 0; padding-left:18px; line-height:1.48; }
.lz-box li { margin:4px 0; overflow-wrap:anywhere; }
.lz-chips { display:flex; flex-wrap:wrap; gap:6px; margin:8px 0 4px; }
.lz-chip { display:inline-flex; align-items:center; border-radius:999px; padding:3px 9px; font-size:11px; font-weight:800; border:1px solid var(--line); }
.lz-chip.good { background:#dcfce7; color:#166534; border-color:#bbf7d0; }
.lz-chip.warn { background:#fef3c7; color:#92400e; border-color:#fde68a; }
.lz-chip.bad { background:#fee2e2; color:#991b1b; border-color:#fecaca; }
.lz-chip.info { background:#dbeafe; color:#1e40af; border-color:#bfdbfe; }
.lz-chip.neutral { background:#f1f5f9; color:#475569; border-color:#cbd5e1; }
.lz-connector { text-align:center; color:var(--accent); font-weight:900; font-size:24px; margin:8px 0; }
.lz-connector.split { font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:#64748b; }
.muted { color:var(--muted); font-style:italic; }
@media (max-width:1050px) { .lz-layer.top, .lz-layer.bottom, .lz-layer.middle { grid-template-columns:1fr; } .lz-legend { text-align:left; } .lz-titlebar { flex-direction:column; } }
footer { margin-top:30px; padding-top:22px; border-top:1px solid var(--line); color:var(--muted); font-size:13px; text-align:center; }
@media (max-width:760px) { .container { padding:20px 14px 36px; } header.hero { flex-direction:column; align-items:flex-start; padding:24px; } .report-mark { width:100%; min-height:86px; } section { padding:20px; } }
</style>
</head>
<body>
<div class="container">
  <header class="hero">
    <div class="brand">
      <div class="brand-name">$(ConvertTo-HtmlSafe $reportCustomerName)<span class="dot">.</span></div>
      <div class="brand-sub">Azure Virtual Desktop Deployment Report</div>
    </div>
    <div class="report-mark">
      <div class="big">AVD</div>
      <div class="label">Documentation</div>
    </div>
  </header>
  <div class="meta-bar">
    <div class="cell"><div class="meta-label">Generated</div><div class="meta-value">$(ConvertTo-HtmlSafe $generated)</div></div>
    <div class="cell"><div class="meta-label">Subscription</div><div class="meta-value">$(ConvertTo-HtmlSafe $ctx.Subscription.Name)</div></div>
    <div class="cell"><div class="meta-label">Subscription ID</div><div class="meta-value">$(ConvertTo-HtmlSafe $ctx.Subscription.Id)</div></div>
    <div class="cell"><div class="meta-label">Tenant</div><div class="meta-value">$(ConvertTo-HtmlSafe $ctx.Tenant.Id)</div></div>
    <div class="cell"><div class="meta-label">Scope</div><div class="meta-value">$(ConvertTo-HtmlSafe $Data.Scope)</div></div>
  </div>
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
  <p class="report-intro">This report documents the Azure Virtual Desktop deployment discovered in the selected Azure scope. It highlights the main components, visible dependencies, and items that should be validated with the customer before the design is considered fully documented.</p>
</section>

<section>
  <h2>Architecture dependency map</h2>
  $architectureMap
</section>

<section>
  <h2>Technical inventory appendix</h2>
  <p class="appendix-note">The tables below provide the supporting Azure inventory used to build the customer summary and architecture map.</p>
  $inventoryFindingsHtml
  $avdInventoryHtml
</section>

<section>
  <h2>IAM access summary</h2>
  $iamSummaryHtml
</section>

<section>
  <h2>Networking</h2>
  $networkFindingsHtml
  $networkingHtml
</section>

<section>
  <h2>FSLogix / profile storage candidates</h2>
  $storageFindingsHtml
  $profileStorageHtml
</section>

<section>
  <h2>Monitoring and logging</h2>
  $monitoringFindingsHtml
  $monitoringHtml
</section>

<footer>
  AVD-DocAssess v$($script:ToolVersion). Generated read-only from Azure Resource Manager metadata. Do not commit client-generated reports.
</footer>
</main>
</div>
</body>
</html>
"@
}


function Write-DocAssessBanner {
    $width = 63
    function Format-BannerLine {
        param([string]$Text, [switch]$Center)
        if ($Text.Length -gt $width) { $Text = $Text.Substring(0, $width) }
        if ($Center) {
            $left = [math]::Floor(($width - $Text.Length) / 2)
            $right = $width - $Text.Length - $left
            return ('|' + (' ' * $left) + $Text + (' ' * $right) + '|')
        }
        return ('|      ' + $Text.PadRight($width - 6) + '|')
    }

    $border = '+' + ('-' * $width) + '+'
    $blank = '|' + (' ' * $width) + '|'
    $banner = @(
        $border,
        $blank,
        (Format-BannerLine -Text "AVD-DocAssess  v$($script:ToolVersion)" -Center),
        (Format-BannerLine -Text 'Azure Virtual Desktop Documentation Assessment'),
        (Format-BannerLine -Text 'https://virtex.cloud'),
        (Format-BannerLine -Text 'github.com/marsillig/AVD-DocAssess'),
        $blank,
        $border
    ) -join "`n"

    Write-Host $banner -ForegroundColor Cyan
}

function Resolve-ReportPath {
    if ($OutputPath) { return $OutputPath }
    return (Join-Path (Get-Location) ("AVD-DocAssess-Report-{0}.html" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
}

function Invoke-Main {
    Write-DocAssessBanner
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
