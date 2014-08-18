# 07/25/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Connect-PfaHost() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $HostName,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $HostConnect = $null
    $HostConnect = [ordered]@{
        name = $HostName
        vol = $Volume
    } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/host/$HostName/volume/$Volume" -Body $HostConnect -WebSession $Session -ContentType "application/json"
}

# 07/25/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function New-PfaSnapshot() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $SnapshotVolume,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $SnapshotSuffix,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Snapshot = $null
    $Snapshot = [ordered]@{
        snap = "true"
        source = [Object[]]"$SnapshotVolume"
        suffix = $SnapshotSuffix
    } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/volume" -Body $Snapshot -WebSession $Session -ContentType "application/json"
}

# 07/25/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function New-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Name,
        [Parameter()][ValidateNotNullOrEmpty()][string] $Size = $null,
        [Parameter()][ValidateNotNullOrEmpty()][string] $Source = $null,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
        #TODO: Add Overwrite support.
    )

    $Volume = $null
    If($Source) {
        $Volume = @{
            source = $Source
        } | ConvertTo-Json
    } Else {
        $Volume = @{
            size = $Size
        } | ConvertTo-Json
    }
    Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/volume/$Name" -Body $Volume -WebSession $Session -ContentType "application/json"
}

# Added 08/18/2014, barkz.
function Get-PfaAPIToken {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
	    [Parameter()][ValidateNotNullOrEmpty()][string] $Username,
	    [Parameter()][ValidateNotNullOrEmpty()][string] $Password
    )
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $AuthAction = @{
        password = $Username
        username = $Password
    }
    return(Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/auth/apitoken" -Body $AuthAction)
}

# 07/25/2014 -- Original -- barkz
# 08/13/2014 -- Removed Write-Host and fixed return output. -- barkz
# 08/18/2014 -- Updated to support new Session management and API Token retrieval. -- barkz
Function Connect-PfaController() {
    [CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $APIToken
	)
	
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
	$SessionAction = @{
		api_token = $APIToken
	}
	$Response = Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.1/auth/session" -Body $SessionAction -SessionVariable Session
	$Session
}

# 07/25/2014 -- Original -- barkz
# 08/13/2014 -- Removed Write-Host and fixed return output. -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Disconnect-PfaController() {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Respone = Invoke-RestMethod -Method Delete -Uri "https://$FlashArray/api/1.1/auth/session" -WebSession $Session
}

# 07/25/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Get-PfaHosts() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    return(Invoke-RestMethod -Method Get -Uri "https://$FlashArray/api/1.2/host" -WebSession $Session -ContentType "application/json")
}

# 08/14/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Get-PfaAlerts() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Uri = "https://$FlashArray/api/1.2/message?audit=true"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

# 08/11/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Get-PfaArray() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    return(Invoke-RestMethod -Method Get -Uri "https://$FlashArray/api/1.2/array" -WebSession $Session)
}

# 07/25/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Get-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Uri = "https://$FlashArray/api/1.2/volume"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

# 08/05/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Get-PfaVolumeStatistics() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Uri = "https://$FlashArray/api/1.2/volume/$Volume"+"?action=monitor"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

# 08/14/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Disconnect-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $HostName,
   		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    return(Invoke-RestMethod -Method Delete -Uri "https://$FlashArray/api/1.2/host/$HostName/volume/$Volume" -WebSession $Session)
}

# Added 08/14/2014, barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Remove-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
        #[Parameter()][ValidateNotNullOrEmpty()][string] $Eradicate
    )
    try {
        return(Invoke-RestMethod -Method Delete -Uri "https://$FlashArray/api/1.2/volume/$Volume" -WebSession $Session)
    } catch {
        Write-Host "ERROR"
    }
}

# 07/25/2014 -- Original -- barkz
# 08/18/2014 -- Updated to support new Session management. -- barkz
Function Get-PfaSnapshot() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    $Uri = "https://$FlashArray/api/1.2/volume?snap=true"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

# 07/25/2014 -- Original -- barkz
Export-ModuleMember -Function Connect-PfaController
Export-ModuleMember -Function Disconnect-PfaController
Export-ModuleMember -Function New-PfaSnapshot
Export-ModuleMember -Function New-PfaVolume
Export-ModuleMember -Function Connect-PfaHost
Export-ModuleMember -Function Get-PfaVolume
Export-ModuleMember -Function Get-PfaVolumeStatistics
Export-ModuleMember -Function Get-PfaHosts
Export-ModuleMember -Function Get-PfaArray
Export-ModuleMember -Function Get-PfaSnapshot
# Added 08/14/2014, barkz
Export-ModuleMember -Function Get-PfaAlerts
Export-ModuleMember -Function Remove-PfaVolume
Export-ModuleMember -Function Disconnect-PfaVolume
# Added 08/18/2014, barkz
Export-ModuleMember -Function Get-PfaAPIToken