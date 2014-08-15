# 07/25/2014 -- Original -- barkz
Function Connect-PfaHost() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $HostName,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume
    )
    $HostConnect = $null
    $HostConnect = [ordered]@{
        name = $HostName
        vol = $Volume
    } | ConvertTo-Json
    Connect-PfaController -FlashArray $FlashArray
    Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/host/$HostName/volume/$Volume" -Body $HostConnect -WebSession $Session -ContentType "application/json"
    Disconnect-PfaController -FlashArray $FlashArray
}

# 07/25/2014 -- Original -- barkz
Function New-PfaSnapshot() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $SnapshotVolume,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $SnapshotSuffix
    )
    $Snapshot = $null
    $Snapshot = [ordered]@{
        snap = "true"
        source = [Object[]]"$SnapshotVolume"
        suffix = $SnapshotSuffix
    } | ConvertTo-Json
    Connect-PfaController -FlashArray $FlashArray
    Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/volume" -Body $Snapshot -WebSession $Session -ContentType "application/json"
    Disconnect-PfaController -FlashArray $FlashArray
}

# 07/25/2014 -- Original -- barkz
Function New-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Name,
        [Parameter()][ValidateNotNullOrEmpty()][string] $Size = $null,
        [Parameter()][ValidateNotNullOrEmpty()][string] $Source = $null
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

    Connect-PfaController -FlashArray $FlashArray
    Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/volume/$Name" -Body $Volume -WebSession $Session -ContentType "application/json"
    Disconnect-PfaController -FlashArray $FlashArray
}

# Added 08/13/2014, barkz.
Function New-PfaApiToken() {

}

# 07/25/2014 -- Original -- barkz
# 08/13/2014 -- Removed Write-Host and fixed return output. -- barkz
Function Connect-PfaController() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
	    [Parameter()][ValidateNotNullOrEmpty()][string] $Username = "pureuser",
	    [Parameter()][ValidateNotNullOrEmpty()][string] $Password = "pureuser"
    )
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    $AuthAction = @{
        password = $Username
        username = $Password
    }
    $ApiToken = Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/auth/apitoken" -Body $AuthAction

    $SessionAction = @{
        api_token = $ApiToken.api_token
    }
    $Connect = Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/auth/session" -Body $SessionAction -SessionVariable Session
    $Global:Session = $Session
}

# 07/25/2014 -- Original -- barkz
# 08/13/2014 -- Removed Write-Host and fixed return output. -- barkz
Function Disconnect-PfaController() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
    )
    $Disconnect = Invoke-RestMethod -Method Delete -Uri "https://${FlashArray}/api/1.2/auth/session" -WebSession $Session
}

# 07/25/2014 -- Original -- barkz
Function Get-PfaHosts() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
    )
    Connect-PfaController -FlashArray $FlashArray
    return(Invoke-RestMethod -Method Get -Uri "https://$FlashArray/api/1.2/host" -WebSession $Session -ContentType "application/json")
    Disconnect-PfaController -FlashArray $FlashArray
}

# 08/14/2014 -- Original -- barkz
Function Get-PfaAlerts() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
    )
    Connect-PfaController -FlashArray $FlashArray
    $Uri = "https://$FlashArray/api/1.2/message?audit=true"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
    Disconnect-PfaController -FlashArray $FlashArray
}

# 08/11/2014 -- Original -- barkz
Function Get-PfaArray() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
    )
    Connect-PfaController -FlashArray $FlashArray
    return(Invoke-RestMethod -Method Get -Uri "https://$FlashArray/api/1.2/array" -WebSession $Session)
    Disconnect-PfaController -FlashArray $FlashArray
}

# 07/25/2014 -- Original -- barkz
Function Get-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
    )
    Connect-PfaController -FlashArray $FlashArray
    $Uri = "https://$FlashArray/api/1.2/volume"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
    Disconnect-PfaController -FlashArray $FlashArray
}

# 08/05/2014 -- Original -- barkz
Function Get-PfaVolumeStatistics() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume
    )
    Connect-PfaController -FlashArray $FlashArray
    $Uri = "https://$FlashArray/api/1.2/volume/$Volume"+"?action=monitor"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
    Disconnect-PfaController -FlashArray $FlashArray
}

# 08/14/2014 -- Original -- barkz
Function Disconnect-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $HostName
        #[Parameter()][ValidateNotNullOrEmpty()][string] $Eradicate
    )
    Connect-PfaController -FlashArray $FlashArray
    return(Invoke-RestMethod -Method Delete -Uri "https://$FlashArray/api/1.2/host/$HostName/volume/$Volume" -WebSession $Session)
    Disconnect-PfaController -FlashArray $FlashArray
}

# Added 08/14/2014, barkz.
Function Remove-PfaVolume() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume
        #[Parameter()][ValidateNotNullOrEmpty()][string] $Eradicate
    )
    Connect-PfaController -FlashArray $FlashArray
    try {
        return(Invoke-RestMethod -Method Delete -Uri "https://$FlashArray/api/1.2/volume/$Volume" -WebSession $Session)
    } catch {
        Write-Host "ERROR"
    }
    Disconnect-PfaController -FlashArray $FlashArray
}

# 07/25/2014 -- Original -- barkz
Function Get-PfaSnapshot() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
    )
    Connect-PfaController -FlashArray $FlashArray
    $Uri = "https://$FlashArray/api/1.2/volume?snap=true"
    return(Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
    Disconnect-PfaController -FlashArray $FlashArray
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
# Added 08/14/2014, barkz.
Export-ModuleMember -Function Get-PfaAlerts
Export-ModuleMember -Function Remove-PfaVolume
Export-ModuleMember -Function Disconnect-PfaVolume
