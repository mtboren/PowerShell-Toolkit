Function Connect-PfaHost() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $HostName,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume
        #TODO: Add LUN parameter support.
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

Function Get-PfaHosts() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
        #TODO: Add All parameter support.
        #TODO: Add Chap parameter support.
        #TODO: Add Personality parameter support.
        #TODO: Add Space parameter support.
    )

    Connect-PfaController -FlashArray $FlashArray
    Invoke-RestMethod -Method Get -Uri "https://$FlashArray/api/1.2/host" -WebSession $Session -ContentType "application/json" | Format-Table -AutoSize
    Disconnect-PfaController -FlashArray $FlashArray
}

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
    Write-Host $AuthAction.Values
    $ApiToken = Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/auth/apitoken" -Body $AuthAction
 
    $SessionAction = @{
        api_token = $ApiToken.api_token
    }
    Invoke-RestMethod -Method Post -Uri "https://$FlashArray/api/1.2/auth/session" -Body $SessionAction -SessionVariable Session
    $Global:Session = $Session
    Invoke-RestMethod -Method Get -Uri "https://$FlashArray/api/1.2/array" -WebSession $Session | Format-Table -AutoSize
}

Function Disconnect-PfaController() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray
    )
    Invoke-RestMethod -Method Delete -Uri "https://${FlashArray}/api/1.2/auth/session" -WebSession $Session
}

Function Get-PfaVolumeStatistics() {
    [CmdletBinding()]
    Param(
	    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $FlashArray,
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][string] $Volume
    )
    Connect-PfaController -FlashArray $FlashArray
    $Uri = "https://$FlashArray/api/1.2/volume/$Volume"+"?action=monitor"
    Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json"
    Disconnect-PfaController -FlashArray $FlashArray
}

#Examples
#New-PfaSnapshot -FlashArray 0.0.0.0 -SnapshotVolume SAMPLE -SnapshotSuffix ([Guid]::NewGuid())
#New-PfaVolume -FlashArray 0.0.0.0 -Name SAMPLE3 -Size 500M 
#New-PfaVolume -FlashArray 0.0.0.0 -Name SAMPLE4 -Source SAMPLE1
#Connect-PfaHost -FlashArray 0.0.0.0 -HostName MYHOST -Volume SAMPLE4
#Get-PfaVolumeStatistics -FlashArray 0.0.0.0 -Volume SAMPLE4
#Get-PfaHosts -FlashArray 0.0.0.0

Export-ModuleMember -Function Connect-PfaController
Export-ModuleMember -Function Disconnect-PfaController
Export-ModuleMember -Function New-PfaSnapshot
Export-ModuleMember -Function New-PfaVolume
Export-ModuleMember -Function Connect-PfaHost
Export-ModuleMember -Function Get-PfaVolumeStatistics
Export-ModuleMember -Function Get-PfaHosts
