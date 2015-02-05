<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2014 v4.1.74
	 Created by:   	barkz@PureStoragePowerShell.com
	 Coded to:		Blade Runner (Soundtrack from the Motion Picture)
	 Organization: 	Pure Storage, Inc.
	 Filename:     	PureStoragePowerShell.psm1
	 Version:		2.0.0.1
	 Copyright:		2014 Pure Storage, Inc.
	-------------------------------------------------------------------------
	 Module Name: PureStoragePowerShell

	Disclaimer
 	The sample script and documentation are provided AS IS and are not supported by 
	the author or the author’s employer, unless otherwise agreed in writing. You bear 
	all risk relating to the use or performance of the sample script and documentation. 
	The author and the author’s employer disclaim all express or implied warranties 
	(including, without limitation, any warranties of merchantability, title, infringement 
	or fitness for a particular purpose). In no event shall the author, the author’s employer 
	or anyone else involved in the creation, production, or delivery of the scripts be liable 
	for any damages whatsoever arising out of the use or performance of the sample script and 
	documentation (including, without limitation, damages for loss of business profits, 
	business interruption, loss of business information, or other pecuniary loss), even if 
	such person has been advised of the possibility of such damages.
	===========================================================================
#>

<# 	Base requirement for Pure Storage PowerShell Toolkit is PowerShell 3.0 which provides
 	support for the Invoke-RestMethod cmdlet. See http://technet.microsoft.com/en-us/library/hh849971.aspx
 	for full details.
#>
#Requires -Version 3

#region Miscellenaous-Cmdlets
<#
	.SYNOPSIS
		Access the Github repository for the Pure Storage PowerShell Toolkit.
	
	.DESCRIPTION
		Using this cmdlet will open up the default web browser and navigate to the Pure Storage
		Github repository.
	
	.EXAMPLE
		PS C:\> Open-PureStorageGitHub
#>
function Open-PureStorageGitHub
{
	$link = "https://github.com/purestorage/PowerShell-Toolkit"
	$browserProcess = [System.Diagnostics.Process]::Start($link)
}

<#
	.SYNOPSIS
		Retrieve the currently active Windows Server power scheme.
	
	.DESCRIPTION
		Determine what the current Windows Server power scheme that is being used to ensure the host
		is optimally configured for performance.
	
	.EXAMPLE
		PS C:\> Get-WindowsPowerScheme

#>
function Get-WindowsPowerScheme()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $ComputerName
	)
	$PowerScheme = Get-WmiObject -Class WIN32_PowerPlan -Namespace "root\cimv2\power" -ComputerName $ComputerName -Filter "isActive='true'"
	Write-Host $ComputerName "is set to" $PowerScheme.ElementName
}

<#
	.SYNOPSIS
		Set the queue depth for the QLogic HBA (ql2300.sys).
	
	.DESCRIPTION
		Set the queue depth for the QLogic HBA (ql2300.sys).
	
	.PARAMETER Qd
		Value for queue depth.		

	.EXAMPLE
		PS C:\> Set-QueueDepth -Qd 64
#>
function Set-QueueDepth()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][int] $Qd
	)
	$DriverParam = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\ql2300\Parameters\Device\"
	If (!$DriverParam.DriverParameter)
	{
		$Confirm = Read-Host "The Queue Depth setting for the QLogic Driver (ql2300.sys) does not exist would you like to create it? Y/N"
		switch ($Confirm)
		{
			"Y" { Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\ql2300\Parameters\Device" -Name "DriverParameter" -Value "qd=$Qd" }
			"N" { }
		}
	}
	Else
	{
		$CurrentQD = $DriverParam.DriverParameter
		$Confirm = Read-Host "QLogic Driver Queue Depth is $CurrentQD. Do you want to update to $Qd ? Y/N"
		switch ($Confirm)
		{
			"Y" { Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\ql2300\Parameters\Device" -Name "DriverParameter" -Value "qd=$Qd" }
			"N" { }
		}
	}
}

<#
	.SYNOPSIS
		Retrieves the queue depth for the QLogic HBA (ql2300.sys).
	
	.DESCRIPTION
		Retrieves the queue depth for the QLogic HBA (ql2300.sys).
	
	.EXAMPLE
		PS C:\> Get-QueueDepth
#>
function Get-QueueDepth()
{
	$DriverParam = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\ql2300\Parameters\Device\"
	"Queue Depth is " + $DriverParam.DriverParameter
}

<#
	.SYNOPSIS
		Retrieves the HBAs installed on the specific computer. 

	.DESCRIPTION
		Retrieves the HBAs installed on the specific computer. 
	
	.PARAMETER ComputernName
		Server name to retrieve Host Bus Adapater (HBA) information.
	
	.EXAMPLE
		PS C:\> Get-HBAObject -ComputerName MyServer
#>
function Get-HostBusAdapter()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)][string] $ComputerName
	)
	
	$Namespace = "root\WMI"
	try
	{
		$port = Get-WmiObject -ComputerName $ComputerName -Class MSFC_FibrePortHBAAttributes -Namespace $Namespace @PSBoundParameters
		$hbas = Get-WmiObject -ComputerName $ComputerName -Class MSFC_FCAdapterHBAAttributes -Namespace $Namespace @PSBoundParameters
		$hbaProp = $hbas | Get-Member -MemberType Property, AliasProperty | Select -ExpandProperty name | ? { $_ -notlike "__*" }
		$hbas = $hbas | Select $hbaProp
		$hbas | %{ $_.NodeWWN = ((($_.NodeWWN) | % { "{0:x2}" -f $_ }) -join ":").ToUpper() }
		
		ForEach ($hba in $hbas)
		{
			Add-Member -MemberType NoteProperty -InputObject $hba -Name FabricName -Value (($port | ? { $_.instancename -eq $hba.instancename }).attributes | Select @{ Name = 'Fabric Name'; Expression = { (($_.fabricname | % { "{0:x2}" -f $_ }) -join ":").ToUpper() } }, @{ Name = 'Port WWN'; Expression = { (($_.PortWWN | % { "{0:x2}" -f $_ }) -join ":").ToUpper() } }) -passThru
		}
	}
	catch
	{
		Throw $Error.ErrorDetails.ToString()
	}
}

#endregion

#region FA-Authentication-Cmdlets
<#
	.SYNOPSIS
		Retrieve the REST API version from the Pure Storage FlashArray.
	
	.DESCRIPTION
		The Get-PfaApiVersion cmdlet queries the Pure Storage FlashArray to retrieve the highest REST API version that has been installed on the FlashArray. This cmdlet can be used as standalone but is only used with the toolkit from the Connect-PfaController cmdlet in order to dynamically set the $PureStorageUriBase global variable. 
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaApiVersion -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaApiVersion()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, Position = 0)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
	
	try
	{
		$Uri = "https://$FlashArray/api/api_version"
		$Return = (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session)
		$global:PureStorageRestApi = $Return.Version.Item($Return.Version.Count - 1).ToString()
		$global:PureStorageURIBase = "https://$FlashArray/api/$global:PureStorageRestApi"
	}
	Catch
	{
		Throw "Cannot retrieve Pure Storage FlashArray ($FlashArray) REST API version."
	}
}

<#
	.SYNOPSIS
		Generates a REST API token that can be used to create a REST session.

	.DESCRIPTION
		A detailed description of the Get-PfaAPIToken function.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Username
		Purity user login name used to generate the REST API token. Sometimes referred to as sAMAccountName.

	.PARAMETER Password
		Purity user login password used to generate the REST API token.

	.PARAMETER RESTAPI
		What REST API version to target. Purity Operating Environment has the following released versions: 1.0, 1.1, 1.2, 1.3. The 
		default is 1.3 the latest version of the REST API.

		NOTE: This parameter can be set when retrieving an API Token but once a connection is made to a Pure Storage FlashArray using the Connect-PfaController cmdlet the latest REST API will automatically be used in subsequent cmdlets.

	.EXAMPLE
		PS C:\> $MyToken = Get-PfaAPIToken -FlashArray 1.1.1.1 -Username pureuser -Password pureuser -RESTAPI 1.2
		This example shows how to get an API Token and assign it to the $MyToken variable for use with the Connect-PfaController cmdlet.

	.EXAMPLE
		PS C:\Users\barkz> $MySession = Get-PfaAPIToken -FlashArray 10.21.8.82 -Username pureuser -Password pureuser -RESTAPI 1.2 | Connect-PfaController -FlashArray 10.21.8.82
		This example shows how to pass a retrieved API Token using ValueFromPipelineByPropertyName to Connect-PfaController cmdlet and assigning a new session variable to $MySession.
#>
function Get-PfaApiToken()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, Position = 0)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True, Position = 1)][ValidateNotNullOrEmpty()][string] $Username,
		[Parameter(Mandatory = $True, Position = 2)][ValidateNotNullOrEmpty()][string] $Password,
		[ValidateSet('1.0', '1.1', '1.2', '1.3')][string]$RESTAPI = "1.3"
	)
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
	
	try
	{
		if (-not (Test-Connection -ComputerName $FlashArray -Quiet))
		{
			Throw "Cannot contact Pure Storage FlashArray ($FlashArray)."
		}
		else
		{
			$AuthAction = @{ username = $Username; password = $Password }
			$global:PureStorageURIBase = "https://$FlashArray/api/$RESTAPI"
			
			try
			{
				$Uri = "$PureStorageURIBase/auth/apitoken"
				return (Invoke-RestMethod -Method POST -Uri $Uri -Body $AuthAction)
			}
			Catch
			{
				Throw "Error retrieving API Token from Pure Storage FlashArray ($FlashArray) with $Username."
			}
		}
	}
	Catch
	{
		Throw "Cannot contact Pure Storage FlashArray ($FlashArray)."
	}
}

<#
	.SYNOPSIS
		Connects to the Pure Storage FlashArray.
	
	.DESCRIPTION
		Using the API Token established from the Get-PfaApiToken cmdlet a session is established to the FlashArray. 
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER API_Token
		Retrieved API Token for a given user on the Pure Storage FlashArray.

	.EXAMPLE
		PS C:\> $MySession = Connect-PfaController -FlashArray 1.1.1.1 -API_Token $MyToken.api_token
		This example shows how to set the $MySession variable by passing the $MyToken.api_token.
	
	.EXAMPLE
		PS C:\Users\barkz> $MySession = Get-PfaAPIToken -FlashArray 10.21.8.82 -Username pureuser -Password pureuser -RESTAPI 1.2 | Connect-PfaController -FlashArray 10.21.8.82
		This example shows how to pass a retrieved API Token using ValueFromPipelineByPropertyName to Connect-PfaController cmdlet and assigning a new session variable to $MySession.

#>
function Connect-PfaController()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True, Position = 0)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True, Position = 1, ValueFromPipelineByPropertyName = $True)][ValidateNotNullOrEmpty()][string] $API_Token
	)
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
	
	$SessionAuthentication = @{ api_token = $API_Token }
	
	try
	{
		$Uri = "$PureStorageURIBase/auth/session"
		$Return = Invoke-RestMethod -Method POST -Uri $Uri -Body $SessionAuthentication -SessionVariable Session
		$Session
		Get-PfaApiVersion -FlashArray $FlashArray -Session $Session

	}
	Catch
	{
		
		Throw "Error creating REST session with Pure Storage FlashArray ($FlashArray)."
	}
}

<#
	.SYNOPSIS
		Disconnect from a Pure Storage FlashArray session.
	
	.DESCRIPTION
		Disconnect from an established session with the Pure Storage FlashArray. Each individual session needs to be disconnected to ensure all sessions have been deleted.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\>  Disconnect-PfaController -FlashArray 1.1.1.1 -Session $MySession
	
#>
function Disconnect-PfaController()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	try
	{
		$Uri = "$PureStorageURIBase/auth/session"
		$Return = Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session
	}
	Catch
	{
		
		Throw "Error disconnecting from the Pure Storage FlashArray ($FlashArray)."
	}
	
}

#endregion
	
#region FA-VSS-Cmdlets
<#
	.SYNOPSIS
		Exposes a Pure Storage created Volume Shadow Copy Service (VSS) snapshot. 
	
	.DESCRIPTION
		A detailed description of the Get-PfaShadowCopy function. These cmdlets are meant to be
		examples of automating Diskshadow through Windows PowerShell, these examples can be
		enhanced to support greater flexibility and more complicated use cases.
	
	.PARAMETER ScriptName
		Assigned name of the script that will be autogenerated. Default is PUREVSS-SNAP.
		
	.PARAMETER MetadataFile
		The metadata file (.cab) created during a backup operation which contains the details about the volume shadow copy.
	
	.PARAMETER ShadowCopyAlias
		A simple name to alias the Shadow Copy ID.

	.PARAMETER ExposeAs
		A drive letter on the host sytem to expose the VSS snapshot. Eg. X:

	.EXAMPLE
		PS C:\> Get-PfaShadowCopy -ScriptName SampleScript -MetadataFile SampleMetaDataFile -ShadowCopyAlias SampleAlias -ExposeAs X:
#>
function Get-PfaShadowCopy()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][string]$ScriptName = "PUREVSS-SNAP",
		[Parameter(Mandatory = $True)][string]$MetadataFile,
		[Parameter(Mandatory = $True)][string]$ShadowCopyAlias,
		[Parameter(Mandatory = $True)][string]$ExposeAs
	)
	
	$dsh = "./$ScriptName.PFA"
	"RESET",
	"LOAD METADATA $MetadataFile.cab",
	"IMPORT",
	"EXPOSE %$ShadowCopyAlias% $ExposeAs",
	"EXIT" | Set-Content $dsh
	DISKSHADOW /s $dsh
	Remove-Item $dsh
}

<#
	.SYNOPSIS
		Initiate a new Microsoft Volume Shadow Copy Service (VSS) snapshot.
	
	.DESCRIPTION
		The New-PfaShadowCopy cmdlet uses Microsoft Diskshadow utility to initiate a volume shadow
		copy service snapshot using the Pure Storage VSS Hardware Provider. The GUID for the Pure
		Storage VSS Provider is {781c006a-5829-4a25-81e3-d5e43bd005ab} and should be used to ensure
		that the proper provider is used. These cmdlets are meant to be examples of automating 
		Diskshadow through Windows PowerShell, these examples can be enhanced to support greater 
		flexibility and more complicated use cases.
	
	.PARAMETER Volume
		Identification of the Pure Storage volume that needs to be quiesced. Eg. F:

	.PARAMETER ScriptName
		Assigned name of the script that will be autogenerated. Default is PUREVSS-SNAP.
		
	.PARAMETER MetadataFile
		The metadata file (.cab) created during a backup operation which contains the details about the volume shadow copy.
	
	.PARAMETER ShadowCopyAlias
		A simple name to alias the Shadow Copy ID.

	.PARAMETER VerboseMode
		Display all executed details for the volume shadow copy service operations.

	.EXAMPLE
		PS C:\> New-PfaShadowCopy -Volume VOLUME1 -Scriptname MyScript -MetadataFile SampleMetadata -ShadowCopyAlias SampleAlias -VerboseMode On
	
#>
function New-PfaShadowCopy()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][string]$Volume,
		[Parameter(Mandatory = $True)][string]$ScriptName = "PUREVSS-SNAP",
		[Parameter(Mandatory = $True)][string]$MetadataFile,
		[Parameter(Mandatory = $True)][string]$ShadowCopyAlias,
		[ValidateSet('On', 'Off')][string]$VerboseMode = "On"
	)
	$dsh = "./$ScriptName.PFA"
	"RESET",
	"SET CONTEXT PERSISTENT",
	"SET OPTION TRANSPORTABLE",
	"SET METADATA $MetadataFile.cab",
	"SET VERBOSE $VerboseMode",
	"BEGIN BACKUP",
	"ADD VOLUME $Volume ALIAS $ShadowCopyAlias PROVIDER {781c006a-5829-4a25-81e3-d5e43bd005ab}",
	"CREATE",
	"END BACKUP" | Set-Content $dsh
	DISKSHADOW /s $dsh
	Remove-Item $dsh
}

#endregion

#region FA-Array-Cmdlets
<#
	.SYNOPSIS
		Displays the following real-time performance data.
	
	.DESCRIPTION
		Latency
			usec_per_read_op - average arrival-to-completion time, measured in microseconds, for a host read operation.
			usec_per_write_op - average arrival-to-completion time, measured in microseconds, for a host write operation.
			queue_depth - average number of queued I/O requests.

		IOPS
			reads_per_sec - number of read requests processed per second.
			writes_per_sec - number of write requests processed per second.
		
		Bandwidth
			input_per_sec - number of bytes read per second.
			output_per_sec - number of bytes written per second.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Watch-PfaPerformance -FlashArray 1.1.1.1 -Session $MySession
#>
function Watch-PfaPerformance()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/array" + "?action=monitor"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
	
}

<#
	.SYNOPSIS
		List FlashArray attributes.
	
	.DESCRIPTION
		List FlashArray attributes.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaArray -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaArray
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Array = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array" -WebSession $Session
	
	New-Object -TypeName PSObject -Property @{
		"Version" = $array.version
		"Revision" = $array.revision
		"Name" = $array.array_name
		"ID" = $array.id
	}
}

<#
	.SYNOPSIS
		Displays the historical performance data.
	
	.DESCRIPTION
		Display historical performance data at a specified resolution. 
		Valid historical values are: 1h, 3h, 24h, 7d, 30d, 90d, 1y
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaArrayConfiguration -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaHistoricalPerformance()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateSet('1h', '3h', '24h', '7d', '30d', '90d', '1y')][string]$TimePeriod,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/array" + "?action=monitor&historical=$TimePeriod"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Retrieves all FlashArray configuration information. The same details can be retrieved via
		the Pure Storage FlashArray Web Management Interface (GUI) from the System tab.
	
	.DESCRIPTION
		Provides detailed information about the configuration of the FlashArray.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaConfiguration -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaConfiguration
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Array = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array" -WebSession $Session
	$Banner = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?banner=true" -WebSession $Session
	$Idle_timeout = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?idle_timeout=true" -WebSession $Session
	$NTPServer = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?ntpserver=true" -WebSession $Session
	$PhoneHomeStatus = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?phonehome=true" -WebSession $Session
	$Proxy = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?proxy=true" -WebSession $Session
	$RelayHost = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?relayhost=true" -WebSession $Session
	$SCSItimeout = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?scsi_timeout=true" -WebSession $Session
	$SenderDomain = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?senderdomain=true" -WebSession $Session
	$SpaceStats = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?space=true" -WebSession $Session
	$SyslogServer = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?syslogserver=true" -WebSession $Session
	$Controllers = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?controllers=true" -WebSession $Session
	$ConnectionKey = Invoke-RestMethod -Method GET -Uri "$PureStorageURIBase/array?connection_key=true" -WebSession $Session
	
	New-Object -TypeName PSObject -Property @{
		"Version" = $array.version
		"Revision" = $array.revision
		"Name" = $array.array_name
		"ID" = $array.id
		"Banner" = $banner.banner
		"Controllers" = $controllers
		"IdleTimeout" = $idle_timeout.idle_timeout
		"NTPServer" = $ntpServer.ntpserver
		"PhoneHomeStatus" = $phoneHomeStatus.phonehome
		"Proxy" = $proxy.proxy
		"RelayHost" = $relayHost.relayhost
		"SCSITimeout" = $SCSItimeout.scsitimeout
		"SenderDomain" = $senderDomain.senderdomain
		"SpaceStats" = $spaceStats
		"SyslogServer" = $syslogServer.syslogserver
		"ConnectionKey" = $ConnectionKey.connection_key
	}
}

<#
	.SYNOPSIS
		Retrieves usable physical storage information.
	
	.DESCRIPTION
		Displays the amount of usable physical storage on the array and the amount of storage occupied 
		by data and metadata.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaSpace -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaSpace
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$uri = "$PureStorageURIBase/array?space=true"
	Invoke-RestMethod -Method GET -Uri $uri -WebSession $Session
}

<#
	.SYNOPSIS
		Lists connected arrays.
	
	.DESCRIPTION
		Lists connected arrays.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaConnection -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaConnection
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/connection"
	Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Displays the status of the console lock.
	
	.DESCRIPTION
		Displays the status of the console lock.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaConsoleLock -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaConsoleLock
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/console_lock"
	Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Lists information about the status of the transmission logs for the phonehome facility.
	
	.DESCRIPTION
		Lists information about the status of the transmission logs for the phonehome facility.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaPhoneHome -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaPhoneHome
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/phonehome"
	Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Lists information about the status (enabled or disabled) of a remote assist session.
	
	.DESCRIPTION
		Lists information about the status (enabled or disabled) of a remote assist session.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaRemoteAssist -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaRemoteAssist
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/remoteassist"
	Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Creates a new connection to a target array.
	
	.DESCRIPTION
		Creates a new connection to a target array.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER TargetFlashArray
		The address of the array to be connected.
	
	.PARAMETER ConnectionKey
		The connection_key of the array to be connected.
	
	.PARAMETER ReplicationAddress (OPTIONAL)
		The replication address of the array to be connected.
	
	.PARAMETER Type (PRESET)
		The type(s) of connection desired. The only option supported in this version is 'replication'.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaConnection -FlashArray 1.1.1.1 -TargetFlashArray 2.2.2.2 -ConnectionKey <Key> -ReplicationAddress 3.3.3.3 -Session $MySession
#>
function New-PfaConnection
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $ManagementAddress,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $ConnectionKey,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $ReplicationAddress,
		#[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Type = "replication",
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$ArrayConnection = $null
	$ArrayConnection = [ordered]@{
		management_address = $ManagementAddress
		connection_key = $ConnectionKey
		replication_address = $ReplicationAddress
		type = [Object[]]"replication"
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/array/connection"
	Invoke-RestMethod -Method POST -Uri $Uri -Body $ArrayConnection -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Removes a connection to a target array.
	
	.DESCRIPTION
		Removes a new connection to a target array.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		The address of the array to be disconnected.
	
	.EXAMPLE
		PS C:\> Remove-PfaConnection -FlashArray 1.1.1.1 -Name DEMOARRAY -Session $MySession
#>
function Remove-PfaConnection
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/connection/$Name"
	Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Sets a common "message of the day" (MOTD) that is sent to all Purity users. The banner message 
		is displayed in the login pane of the Purity GUI and via SSH after users log in.
	
	.DESCRIPTION
		Sets a common "message of the day" (MOTD) that is sent to all Purity users. The banner message 
		is displayed in the login pane of the Purity GUI and via SSH after users log in.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Banner
		Message of the day (MOTD)
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaBanner -FlashArray 1.1.1.1 -Banner "This is my test banner" -Session $MySession
#>
function Set-PfaBanner
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Banner,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)

	$Uri = "$PureStorageURIBase/array?banner=$Banner"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Sets the idle time limit, in minutes, of the Purity GUI and CLI sessions. 
	
	.DESCRIPTION
		Sets the idle time limit, in minutes, of the Purity GUI and CLI sessions. Valid values are between
		5 and 180 minutes. The default timeout value is 30 minutes. Specifying a value of zero disables the 
		automatic log-off feature. Changes made to the idle_timeout value do not apply to existing Purity 
		sessions.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER IdleTimeout
		Valid values are between 5 and 180 minutes. The default timeout value is 30 minutes. Specifying a 
		value of zero disables the automatic log-off feature.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaIdleTimeout -FlashArray 1.1.1.1 -IdleTimeout 60 -Session $MySession
#>
function Set-PfaIdleTimeout
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][int] $IdleTimeout,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array?idle_timeout=$IdleTimeout"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Renames the array.
	
	.DESCRIPTION
		Renames the array.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		New FlashArray name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaName -FlashArray 1.1.1.1 -Name MyFlashArray -Session $MySession
#>
function Set-PfaName
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array?name=$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Specifies alternate NTP servers, by IP address or hostname, assigned as the array source for 
		reference time.
	
	.DESCRIPTION
		Specifies alternate NTP servers, by IP address or hostname, assigned as the array source for 
		reference time. Supersedes any previous NTP server assignments.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Servers
		One more more new NTP Server hostname or IP address. Separated by commas.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaNtpServer -FlashArray 1.1.1.1 -Name MyNtpServer -Session $MySession
#>
function Set-PfaNtpServer
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string[]] $Servers,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$AddNtpServer = $null
	$AddNtpServer = @{
		ntpserver = [Object[]]$Servers
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/array?ntpserver"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $AddNtpServer -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Sets the proxy host for the phonehome facility when HTTPS is the phonehome protocol.
	
	.DESCRIPTION
		Sets the proxy host for the phonehome facility when HTTPS is the phonehome protocol (the phonehome 
		facility itself determines which protocol to use). The format for the value is https://HOSTNAME:PORT, 
		where HOSTNAME is the name of the proxy host and PORT is the TCP/IP port number used by the proxy host.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		New proxy (HOSTNAME:PORT).
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaProxy -FlashArray 1.1.1.1 -Name MyProxy -Session $MySession
#>
function Set-PfaProxy
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array?proxy=$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Sets the hostname or IP address of the electronic mail relay server.
	
	.DESCRIPTION
		Sets the hostname or IP address of the electronic mail relay server currently being used
		as a forwarding point for email alerts generated by the array. To set Purity to send alert 
		email messages directly to recipient addresses rather than routing them via a relay (mail 
		forwarding) server, set relayhost to an empty string.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		New relay hostname or IP address.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaRelayHost -FlashArray 1.1.1.1 -Name MyProxy -Session $MySession
#>
function Set-PfaRelayHost
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array?relayhost=$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Changes the amount of time, in seconds, that can lapse during an I/O interruption before the 
		target ports log out of the fabric. The default timeout value is 60 seconds.
	
	.DESCRIPTION
		Changes the amount of time, in seconds, that can lapse during an I/O interruption before the 
		target ports log out of the fabric. The default timeout value is 60 seconds.

		Changing the default timeout value may cause an initiator to mistakenly interpret the status 
		of the FlashArray as failed or generate a host timeout. Contact the Pure Storage Support team 
		before you change the scsi_timeout value
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Timeout
		New relay hostname or IP address.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaScsiTimeout -FlashArray 1.1.1.1 -Timeout MyProxy -Session $MySession
#>
function Set-PfaScsiTimeout
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][int] $Timeout,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array?scsi_timeout=$Timeout"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Sets the domain name from which Purity sends email alert messages.
	
	.DESCRIPTION
		Sets the domain name from which Purity sends email alert messages.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		New domain name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaSenderDomain -FlashArray 1.1.1.1 -Name MyDomain -Session $MySession
#>
function Set-PfaSenderDomain
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array?senderdomain=$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Specifies the remote syslog servers for delivering notifications.
	
	.DESCRIPTION
		Specifies the remote syslog servers for delivering notifications. The format for the value is 
		tcp://HOST:PORT or udp://HOST:PORT.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Servers
		One or more syslogserver names. Separated with commas.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaSyslogServer -FlashArray 1.1.1.1 -Name MySyslogServer, MySyslogServer1, MySyslogServer2 -Session $MySession
#>
function Set-PfaSyslogServer
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Servers,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$AddSyslogServer = $null
	$AddSyslogServer = @{
		syslogserver = [Object[]]$Servers
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/array?syslogserver"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $AddSyslogServer -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Enables root login through the console.
	
	.DESCRIPTION
		Enables (true) the console lock which prevents the root user from logging in through the system console.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Enable-PfaConsoleLock -FlashArray 1.1.1.1 -Session $MySession
#>
function Enable-PfaConsoleLock
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)

	$Uri = "$PureStorageURIBase/array/console_lock?enabled=true"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session
}

<#
	.SYNOPSIS
		Disables root login through the console.
	
	.DESCRIPTION
		Disables (false) the console lock which prevents the root user from logging in through the system console.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Enable-PfaConsoleLock -FlashArray 1.1.1.1 -Session $MySession
#>
function Disable-PfaConsoleLock
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/console_lock?enabled=false"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disables phonehome actions.
	
	.DESCRIPTION
		Enables (true) the automatic hourly transmission of array logs to the Pure Storage Support team.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Enable-PfaPhonehome -FlashArray 1.1.1.1 -Session $MySession
#>
function Enable-PfaPhonehome
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/phonehome?enabled=true"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disables phonehome actions.
	
	.DESCRIPTION
		Disables (false) the automatic hourly transmission of array logs to the Pure Storage Support team.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Disable-PfaPhonehome -FlashArray 1.1.1.1 -Session $MySession
#>
function Disable-PfaPhonehome
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/phonehome?enabled=false"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Transmits event logs stored in the array to the Pure Storage Support team via the phonehome channel. 
	
	.DESCRIPTION
		Transmits event logs stored in the array to the Pure Storage Support team via the phonehome channel. Specify the 
		phonehome log time period as any of the following: send_all, send_today, send_yesterday, cancel.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER TimePeriod
		Specify the phonehome log time period as any of the following: send_all, send_today, send_yesterday, cancel.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Send-PfaPhonehome -FlashArray 1.1.1.1 -TimePeriod All -Session $MySession
#>
function Send-PfaPhonehomeLogs()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateSet('All', 'Today', 'Yesterday', 'Cancel')][string]$TimePeriod,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	switch ($TimePeriod)
	{
		"All" { $Action = "send_all" }
		"Today" { $Action = "send_today" }
		"Yesterday" { $Action = "send_yesterday" }
		"Cancel" { $Action = "cancel" }
	}
	
	$Uri = "$PureStorageURIBase/array/phonehome" + "?action=$Action"
	$Return = (Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Enables a remote assist session.
	
	.DESCRIPTION
		Enables (true) the automatic hourly transmission of array logs to the Pure Storage Support team.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Connect-PfaRemoteAssist -FlashArray 1.1.1.1 -Session $MySession
#>
function Connect-PfaRemoteAssist
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/remoteassist?action=connect"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disables a remote assist session.
	
	.DESCRIPTION
		Disables (false) the automatic hourly transmission of array logs to the Pure Storage Support team.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Disconnect-PfaRemoteAssist -FlashArray 1.1.1.1 -Session $MySession
#>
function Disconnect-PfaRemoteAssist
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/array/remoteassist?action=disconnect"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json"
}

#endregion

#region FA-Volumes-Snapshots-Cmdlets
<#
	.SYNOPSIS
		Lists all volumes.
	
	.DESCRIPTION
		Lists all volumes.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaVolumes -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaVolumes()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists all volumes with pending eradication time remaining.
	
	.DESCRIPTION
		Lists all volumes with pending eradication time remaining.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaPendingVolumes -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaPendingVolumes()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume?pending=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists only volumes pending eradication.
	
	.DESCRIPTION
		Lists only volumes pending eradication.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaPendingOnlyVolumes -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaPendingOnlyVolumes()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume?pending_only=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists all snapshots (true).
	
	.DESCRIPTION
		Lists all snapshots (true).
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaSnapshots -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaSnapshots()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume?snap=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists size and space consumption attributes for each volume.
	
	.DESCRIPTION
		Lists size and space consumption attributes for each volume.
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaVolumeSpace -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaVolumesSpace()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume?space=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Displays the following real-time performance data.
	
	.DESCRIPTION
		Latency
			usec_per_read_op - average arrival-to-completion time, measured in microseconds, for a host read operation.
			usec_per_write_op - average arrival-to-completion time, measured in microseconds, for a host write operation.
			queue_depth - average number of queued I/O requests.

		IOPS
			reads_per_sec - number of read requests processed per second.
			writes_per_sec - number of write requests processed per second.
		
		Bandwidth
			input_per_sec - number of bytes read per second.
			output_per_sec - number of bytes written per second.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Watch-PfaVolumePerformance -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Watch-PfaVolumePerformance()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume/$Name" + "?action=monitor"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
	
}

<#
	.SYNOPSIS
		Displays the historical performance data for a volume.
	
	.DESCRIPTION
		Display historical performance data at a specified resolution. 
		Valid historical values are: 1h, 3h, 24h, 7d, 30d, 90d, 1y
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaHistoricalVolumePerformance -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Get-PfaHistoricalVolumePerformance()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateSet('1h', '3h', '24h', '7d', '30d', '90d', '1y')][string]$TimePeriod,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume/$Name" + "?action=monitor&historical=$TimePeriod"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists specific volume.
	
	.DESCRIPTION
		Lists specific volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Get-PfaVolume()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume/$Name"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists specific volume snapshots.
	
	.DESCRIPTION
		Lists specific volume snapshots.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaVolumeSnapshots -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Get-PfaVolumeSnapshots()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume/$Name" + "?snap=true"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists specific volume space information.
	
	.DESCRIPTION
		Lists specific volume space information.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaVolumeSpace -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Get-PfaVolumeSpace()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume/$Name" + "?space=true"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists shared connections for a specific volume.
	
	.DESCRIPTION
		Lists shared connections for a specific volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaVolumeSharedConnections -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Get-PfaVolumeSharedConnections()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume/$Name" + "/hgroup"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists private connections for a specific volume.
	
	.DESCRIPTION
		Lists private connections for a specific volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaVolumePrivateConnections -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Get-PfaVolumePrivateConnections()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/volume/$Name" + "/host"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists block differences for the specified volume.
	
	.DESCRIPTION
		Lists block differences for the specified volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume or snapshot name to be used as the base for the diff. If a base volume or snapshot is not 
		specified, all mapped blocks for the volume are returned.
	
	.PARAMETER BlockSize
		Granularity, in bytes, at which to compare.

	.PARAMETER Length
		Length of the region, in bytes, to compare.

	.PARAMETER Offset
		Absolute offset, in bytes, of the region to compare. Must be a multiple of block_size.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaVolumePrivateConnections -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Get-PfaVolumeDiff()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $BlockSize,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Length,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Offset,	
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	If (!$Offset)
	{
		$Uri = "$PureStorageURIBase/volume/$Name" + "/diff?block_size=$BlockSize&length=$Length"
	}
	Else
	{
		$Uri = "$PureStorageURIBase/volume/$Name" + "/diff?block_size=$BlockSize&length=$Length&offset=$Offset"
	}
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Creates a volume or copies a volume or snapshot. Either the size or source parameter must be specified.
	
	.DESCRIPTION
		Creates a volume or copies a volume or snapshot. Either the size or source parameter must be specified.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Size
		Creates a volume with the specified provisioned size.

		Enter the size as a number (bytes) or as a string with a single character unit symbol. Valid 
		unit symbols are S, K, M, G, T, P, denoting 512-byte sectors, KiB, MiB, GiB, TiB, and PiB respectively.
		"Ki" denotes 2^10, "Mi" denotes 2^20, and so on. If the unit symbol is not specified, the unit defaults 
		to sectors.
	
	.PARAMETER Source
		Creates a new volume from a snapshot as the source.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Size 100G -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Source Volume2.Snapshot -Session $MySession
#>
function New-PfaVolume()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter()][ValidateNotNullOrEmpty()][string] $Size = $null,
		[Parameter()][ValidateNotNullOrEmpty()][string] $Source = $null,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Volume = $null
	If ($Source)
	{
		$Volume = @{
			source = $Source
		} | ConvertTo-Json
	}
	Else
	{
		$Volume = @{
			size = $Size
		} | ConvertTo-Json
	}
	$Uri = "$PureStorageURIBase/volume/$Name"
	Invoke-RestMethod -Method Post -Uri $Uri -Body $Volume -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Overwrites an existing volume.
	
	.DESCRIPTION
		Overwrites an existing volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Source
		Creates a new volume from a snapshot as the source.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Refresh-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Source Volume2.Snapshot -Session $MySession
#>
function Refresh-PfaVolume()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Source,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Json = [ordered]@{
		overwrite = "true"
		source = $Source
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/volume/$Name"
	Invoke-RestMethod -Method Post -Uri $Uri -Body $Json -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Creates a volume or copies a volume or snapshot. Either the size or source parameter must be specified.
	
	.DESCRIPTION
		Creates a volume or copies a volume or snapshot. Either the size or source parameter must be specified.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Volumes
		One or more volume name(s) separated by commas.
	
	.PARAMETER Suffix
		Specify a custom suffix that is added to the snapshot name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Suffix TEST -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1, Volume2, Volume3, Volume4 -Suffix TEST -Session $MySession
#>
function New-PfaSnapshot()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string[]] $Volumes,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Suffix,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	foreach ($Volume in $Volumes)
	{
		$Snapshot = $null
		$Snapshot = [ordered]@{
			snap = "true"
			source = [Object[]]"$Volume"
			suffix = $Suffix
		} | ConvertTo-Json
		$Uri = "$PureStorageURIBase/volume"
		Invoke-RestMethod -Method Post -Uri $Uri -Body $Snapshot -WebSession $Session -ContentType "application/json"
	}
}

<#
	.SYNOPSIS
		Destroys the specified volume or snapshot.
	
	.DESCRIPTION
		Destroys the specified volume or snapshot.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Remove-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Remove-PfaVolume()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	try
	{
		$Uri = "$PureStorageURIBase/volume/$Name"
		$Return = Invoke-RestMethod -Method Delete -Uri $Uri -WebSession $Session
	}
	catch
	{
		Throw("Error removing volume ($Name).")
	}
}

<#
	.SYNOPSIS
		Destroys the specified snapshot.
	
	.DESCRIPTION
		Destroys the specified snapshot.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Snapshot name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Remove-PfaSnapshot -FlashArray 1.1.1.1 -Name Volume1.Snapshot -Session $MySession
#>
function Remove-PfaSnapshot()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	try
	{
		$Uri = "$PureStorageURIBase/volume/$Name"
		$Return = Invoke-RestMethod -Method Delete -Uri $Uri -WebSession $Session
	}
	catch
	{
		Throw ("Error removing snapshot ($Name).")
	}
}

<#
	.SYNOPSIS
		Eradicates the specified volume or snapshot.
	
	.DESCRIPTION
		Eradicates the specified volume or snapshot.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Eradicate-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Eradicate-PfaVolume()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	try
	{
		$Uri = "$PureStorageURIBase/volume/$Volume" + "?eradicate=true"
		$Response = Invoke-RestMethod -Method Delete -Uri $Uri -WebSession $Session
	}
	catch
	{
		Throw ("Error eradicating volume/snapshot ($Name).")
	}
}

<#
	.SYNOPSIS
		Renames the specified volume.
	
	.DESCRIPTION
		Renames the specified volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER CurrentName
		Current name of volume to rename.

	.PARAMETER NewName
		Current name of volume to rename.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Rename-PfaVolume -FlashArray 1.1.1.1 -CurrentName Volume1 -NewName Volume9 -Session $MySession
#>
function Rename-PfaVolume
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $CurrentName,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $NewName,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Rename = @{
		name ="$New"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/volume/$Old"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $Rename -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Resizes a volume.
	
	.DESCRIPTION
		Resizes a volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Size
		Creates a volume with the specified provisioned size.

		Enter the size as a number (bytes) or as a string with a single character unit symbol. Valid 
		unit symbols are S, K, M, G, T, P, denoting 512-byte sectors, KiB, MiB, GiB, TiB, and PiB respectively.
		"Ki" denotes 2^10, "Mi" denotes 2^20, and so on. If the unit symbol is not specified, the unit defaults 
		to sectors.
	
	.PARAMETER Truncate
		This is a switch setting to use when resizing a volume that requires truncation.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Resize-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Size 100G -Session $MySession

	.EXAMPLE
		PS C:\> Resize-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Size 50G -Truncate -Session $MySession
#>
function Resize-PfaVolume
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Size,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Truncate,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If (!$Truncate)
	{
		$Resize = @{
			size = "$Size"
		} | ConvertTo-Json
	}
	Else
	{
		$Resize = @{
			size = "$Size"
			truncate = "true"
		} | ConvertTo-Json
		
	}
	$Uri = "$PureStorageURIBase/volume/$Name"
	try
	{
		$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $Resize -WebSession $Session -ContentType "application/json"
	}
	catch
	{
		$Error = ($_ | ConvertFrom-Json)
		switch ($Error.msg)
		{
			"Implicit truncation not permitted."
			{
				Write-Error "Volume $Name cannot be resized without requiring truncation. Please re-run Resize-PfaVolume with the -Truncate switch."
			}
		}
		
	}
}

<#
	.SYNOPSIS
		Recovers the contents of the specified volume. Set the parameter to recover. 
	
	.DESCRIPTION
		Recovers the contents of the specified volume. Set the parameter to recover.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Size
		Creates a volume with the specified provisioned size.

		Enter the size as a number (bytes) or as a string with a single character unit symbol. Valid 
		unit symbols are S, K, M, G, T, P, denoting 512-byte sectors, KiB, MiB, GiB, TiB, and PiB respectively.
		"Ki" denotes 2^10, "Mi" denotes 2^20, and so on. If the unit symbol is not specified, the unit defaults 
		to sectors.
	
	.PARAMETER Source
		Creates a new volume from a snapshot as the source.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Size 100G -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Source Volume2.Snapshot -Session $MySession
#>
function Recover-PfaVolume
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Recover = @{
		action = "recover"
	} | ConvertTo-Json 
	$Uri = "$PureStorageURIBase/volume/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $Recover -WebSession $Session -ContentType "application/json"
	#$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Recovers the contents of the specified volume. Set the parameter to recover. 
	
	.DESCRIPTION
		Recovers the contents of the specified volume. Set the parameter to recover.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Recover-PfaSnapshot -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Recover-PfaSnapshot
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Recover = @{
		action = "recover"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/volume/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $Recover -WebSession $Session -ContentType "application/json"
}

#endregion

#region FA-Hosts-Cmdlets
<#
	.SYNOPSIS
		Lists all hosts on the array.
	
	.DESCRIPTION
		Lists all hosts on the array.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Display (OPTIONAL)
		Chap: Displays host and target user names and indicates whether host and target passwords have been set.

		Personality: Displays the personality setting associated with the specified hosts.

		Space: Displays information about provisioned (virtual) size and physical storage consumption for each 
		volume connected to the specified hosts.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaHosts -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaHosts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateSet('Chap', 'Personality', 'Space')][string]$Display,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	switch ($Display)
	{
		"Chap" { $Uri = "$PureStorageURIBase/host?chap=true" }
		"Personality" { $Uri = "$PureStorageURIBase/host?personality=true" }
		"Space" { $Uri = "$PureStorageURIBase/host?space=true" }
		default { $Uri = "$PureStorageURIBase/host" }
	}
	
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists attributes for a specific host on the array.
	
	.DESCRIPTION
		Lists attributes for a specific host on the array.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Display (OPTIONAL)
		Chap: Displays host and target user names and indicates whether host and target passwords have been set.

		Personality: Displays the personality setting associated with the specified hosts.

		Space: Displays information about provisioned (virtual) size and physical storage consumption for each 
		volume connected to the specified hosts.
	
	.SWITCH Volume (OPTIONAL)
		Display all shared and private connections for the specified host.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaHost -FlashArray 1.1.1.1 -Name HOST1 -Session $MySession
#>
function Get-PfaHost()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateSet('Chap', 'Personality', 'Space')][string]$Display,
		[Parameter(Mandatory = $False)][ValidateSet('All', 'Shared', 'Private')][string]$Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	switch ($Display)
	{
		"Chap" { $Uri = "$PureStorageURIBase/host/$Name" + "?chap=true" }
		"Personality" { $Uri = "$PureStorageURIBase/host/$Name" + "?personality=true" }
		"Space" { $Uri = "$PureStorageURIBase/host/$Name" + "?space=true" }
		default
		{
			if ($Volume)
			{
				switch ($Volume)
				{
					"All" { $Uri = "$PureStorageURIBase/host/$Name/volume" }
					"Shared" { $Uri = "$PureStorageURIBase/host/$Name/volume" + "?shared=true" }
					"Private" { $Uri = "$PureStorageURIBase/host/$Name/volume" + "?private=true" }
					default
					{
						$Uri = "$PureStorageURIBase/host/$Name/volume"
					}
				}
			}
			else
			{
				$Uri = "$PureStorageURIBase/host/$Name"
			}
		}
	}
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Creates a host with the specified name.
	
	.DESCRIPTION
		Creates a host with the specified name.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host to create.

	.PARAMETER IQNList (OPTIONAL)
		Sets the list of iSCSI qualified names (IQNs) for the new host.
	
	.SWITCH WWNList (OPTIONAL)
		Sets the list of Fibre Channel worldwide names (WWNs) for the new host.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaHost -FlashArray 1.1.1.1 -Name HOST1 -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaHost -FlashArray 1.1.1.1 -Name HOST1 -IQNList iqn.1992-01.TEST.com.example -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaHost -FlashArray 1.1.1.1 -Name HOST1 -WWNList 1111999900009999,2222999900009999,3333999900009999,4444999900009999 -Session $MySession
#>
function New-PfaHost()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $IQNList,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $WWNList,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	if ($IQNList)
	{
		$NewHost = $null
		$NewHost = @{
			iqnlist = [Object[]]$IQNList
		} | ConvertTo-Json
		$Uri = "$PureStorageURIBase/host/$Name"
		Invoke-RestMethod -Method POST -Uri $Uri -Body $NewHost -WebSession $Session -ContentType "application/json"
	}
	elseif ($WWNList)
	{
		$NewHost = $null
		$NewHost = @{
			wwnlist = [Object[]]$WWNList
		} | ConvertTo-Json
		$Uri = "$PureStorageURIBase/host/$Name"
		Invoke-RestMethod -Method POST -Uri $Uri -Body $NewHost -WebSession $Session -ContentType "application/json"
	}
	else
	{
		$Uri = "$PureStorageURIBase/host/$Name"
		Invoke-RestMethod -Method POST -Uri $Uri -WebSession $Session
	}
}

<#
	.SYNOPSIS
		Assigns the same LUN to each connection. The connection fails for any host for which the specified LUN is already in use.
	
	.DESCRIPTION
		Assigns the same LUN to each connection. The connection fails for any host for which the specified LUN is already in use.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host to connect.

	.PARAMETER Volume
		Volume to attach to host.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Connect-PfaVolume -FlashArray 1.1.1.1 -Name HOST1 -Volume VOLUME1 -Session $MySession
#>
function Connect-PfaHost()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$HostConnect = $null
	$HostConnect = [ordered]@{
		name = $Name
		vol = $Volume
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/host/$Name/volume/$Volume"
	Invoke-RestMethod -Method Post -Uri $Uri -Body $HostConnect -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Assigns the same LUN to each connection. The connection fails for any host for which the specified LUN is already in use.
	
	.DESCRIPTION
		Assigns the same LUN to each connection. The connection fails for any host for which the specified LUN is already in use.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host to connect.

	.PARAMETER Volume
		Volume to attach to host.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Connect-PfaVolume -FlashArray 1.1.1.1 -Name HOST1 -Volume VOLUME1 -Session $MySession
#>
function Connect-PfaVolume()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$HostConnect = $null
	$HostConnect = [ordered]@{
		name = $Name
		vol = $Volume
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/host/$Name/volume/$Volume"
	Invoke-RestMethod -Method Post -Uri $Uri -Body $HostConnect -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Breaks the connection between a host and volume.
	
	.DESCRIPTION
		Breaks the connection between a host and volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Volume
		Volume to disconnect from host.

	.PARAMETER Host
		Name of host to disconnect.

	.PARAMETER HostGroup 
		Name of host group to disconnect.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Disconnect-PfaVolume -FlashArray 1.1.1.1 -Volume VOLUME1 -Host HOST1 -Session $MySession

	.EXAMPLE
		PS C:\> Disconnect-PfaVolume -FlashArray 1.1.1.1 -Volume VOLUME1 -HostGroup HOSTGROUP1 -Session $MySession
#>
function Disconnect-PfaVolume()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Host = $null,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $HostGroup = $null,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	If ($HostName)
	{
		$Uri = "$PureStorageURIBase/host/$HostName/volume/$Volume"
	}
	Else
	{
		If ($HostGroupName)
		{
			$Uri = "$PureStorageURIBase/hgroup/$HostGroupName/volume/$Volume"
		}
	}
	$Return = Invoke-RestMethod -Method Delete -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Destroys the specified host.
	
	.DESCRIPTION
		Destroys the specified host.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Host name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Remove-PfaHost -FlashArray 1.1.1.1 -Name HOST1 -Session $MySession
#>
function Remove-PfaHost()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	#try
	#{
		$Uri = "$PureStorageURIBase/host/$Name"
		$Return = Invoke-RestMethod -Method Delete -Uri $Uri -WebSession $Session
	#}
	#catch
	#{
#		Throw ("Error removing host ($Name).")
#	}
}

#endregion

#region FA-HostGroups-Cmdlets
<#
	.SYNOPSIS
		Lists all or a specific host group.

	.DESCRIPTION
		Lists all or a specific host group.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name (OPTIONAL)
		Host group name.
	
	.PARAMETER Space (OPTIONAL)
		List space usage for all or a specific host group.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Get-HostGroups -FlashArray 1.1.1.1 -Session $MySession

	.EXAMPLE
		PS C:\> Get-HostGroups -FlashArray 1.1.1.1 -Space -Session $MySession

	.EXAMPLE
		PS C:\> Get-HostGroups -FlashArray 1.1.1.1 -Name HOSTGROUP1 -Space -Session $MySession
#>
function Get-PfaHostGroups()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Name = $null,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Space,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	If ($Name)
	{
		If (!$Space)
		{
			$Uri = "$PureStorageURIBase/hgroup/$Name"
		}
		else
		{
			$Uri = "$PureStorageURIBase/hgroup/$Name" + "?space=true"
		}
	}
	Else
	{
		If (!$Space)
		{
			$Uri = "$PureStorageURIBase/hgroup"
		}
		else
		{
			$Uri = "$PureStorageURIBase/hgroup?space=true"
		}
	}
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists volumes associated with the specified host groups and the LUNs used to address them.

	.DESCRIPTION
		Lists volumes associated with the specified host groups and the LUNs used to address them.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Host group name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Get-HostGroupVolumes -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaHostGroupVolumes()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/hgroup/$Name" + "/volume"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Creates a host group with the specified name.
	
	.DESCRIPTION
		Creates a host group with the specified name.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to create.

	.PARAMETER HostList (OPTIONAL)
		List of member hosts.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaHost -FlashArray 1.1.1.1 -Name HOSTGROUP1 -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaHost -FlashArray 1.1.1.1 -Name HOSTGROUP1 -HostList HOSTA,HOSTB,HOSTC,HOSTD -Session $MySession
#>
function New-PfaHostGroup()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $HostList,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	if ($HostList)
	{
		$NewHostList = $null
		$NewHostList = @{
			hostlist = [Object[]]$HostList
		} | ConvertTo-Json
		$Uri = "$PureStorageURIBase/hgroup/$Name"
		$Return = Invoke-RestMethod -Method POST -Uri $Uri -Body $NewHostList -WebSession $Session -ContentType "application/json"
	}
	else
	{
		$Uri = "$PureStorageURIBase/hgroup/$Name"
		$Return = Invoke-RestMethod -Method POST -Uri $Uri -WebSession $Session
	}
}

<#
	.SYNOPSIS
		Connects a volume to all hosts in the specified host group.

	.DESCRIPTION
		Connects a volume to all hosts in the specified host group.

		If the LUN is not specified, when the volume is connected to the host group, Purity 
		assigns the same LUN to each connection. All hosts in the group use this LUN to 
		communicate with the volume.	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to connect.

	.PARAMETER Volume
		Volume to connect to host group.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaHost -FlashArray 1.1.1.1 -Name HOSTGROUP1 -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaHost -FlashArray 1.1.1.1 -Name HOSTGROUP1 -HostList HOSTA,HOSTB,HOSTC,HOSTD -Session $MySession
#>
function Connect-PfaHostGroup()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/hgroup/$Name/volume/$Volume"
	$Return = Invoke-RestMethod -Method Post -Uri $Uri -Body $HostConnect -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Adds host members of the host group.
	
	.DESCRIPTION
		Adds host members of the host group.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to create.

	.PARAMETER HostList
		Adds a list of hosts to the existing list.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Add-PfaHostGroupHosts -FlashArray 1.1.1.1 -Name HOSTGROUP1 -HostList HOSTA,HOSTB,HOSTC,HOSTD -Session $MySession
#>
function Add-PfaHostGroupHosts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $HostList,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$AddHostList = $null
	$AddHostList = @{
		addhostlist = [Object[]]$HostList
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/hgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $AddHostList -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Removes host members of the host group.
	
	.DESCRIPTION
		Removes host members of the host group.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to create.

	.PARAMETER HostList
		Removes list of hosts from the existing list.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Remove-PfaHostGroupHosts -FlashArray 1.1.1.1 -Name HOSTGROUP1 -HostList HOSTA,HOSTB,HOSTC,HOSTD -Session $MySession
#>
function Remove-PfaHostGroupHosts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $HostList,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$RemoveHostList = $null
	$RemoveHostList = @{
		remhostlist = [Object[]]$HostList
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/hgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $RemoveHostList -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Replaces host members of the host group.
	
	.DESCRIPTION
		Replaces host members of the host group.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to create.

	.PARAMETER HostList
		Removes list of hosts from the existing list.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Update-PfaHostGroupHosts -FlashArray 1.1.1.1 -Name HOSTGROUP1 -HostList HOSTA,HOSTB,HOSTC,HOSTD -Session $MySession
#>
function Update-PfaHostGroupHosts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $HostList,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$ReplaceHostList = $null
	$ReplaceHostList = @{
		hostlist = [Object[]]$HostList
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/hgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $ReplaceHostList -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Rename host group.
	
	.DESCRIPTION
		Rename host group.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to rename.
	
	.PARAMETER NewName
		New name of host group.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Rename-PfaHostGroup -FlashArray 1.1.1.1 -Name HOSTGROUP1 -HostList HOSTA,HOSTB,HOSTC,HOSTD -Session $MySession
#>
function Rename-PfaHostGroup()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $NewName,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$UpdateName = @{
		name = $NewName
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/hgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $UpdateName -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Remove host group.
	
	.DESCRIPTION
		Remove host group.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to remove.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Remove-PfaHostGroup -FlashArray 1.1.1.1 -Name HOSTGROUP1 -Session $MySession
#>
function Remove-PfaHostGroup
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/hgroup/$Name"
	$Return = Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disconnects host group from specified volume.
	
	.DESCRIPTION
		Disconnects host group from specified volume.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Name of host group to disconnect volume.

	.PARAMETER Volume
		Name of volume to disconnect.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Disconnect-PfaHostGroupVolume -FlashArray 1.1.1.1 -Name HOSTGROUP1 -Session $MySession
#>
function Disconnect-PfaHostGroupVolume
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Volume,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/hgroup/$Name" + "/volume/$Volume"
	$Return = Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session -ContentType "application/json"
}

#endregion

#region FA-Protection-Group-Cmdlets
<#
	.SYNOPSIS
		Lists all protection groups.	

	.DESCRIPTION
		Lists all protection groups.	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroups -FlashArray 1.1.1.1 -Session $S

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroups -FlashArray 1.1.1.1 -Name TESTGROUP -Session $S
#>
function Get-PfaProtectionGroups()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup"
	Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Displays the total space consumption for all protection groups. 

	.DESCRIPTION
		Displays the total space consumption for all protection groups. 

	.PARAMETER FlashArray
		A description of the FlashArray parameter.

	.PARAMETER Source
		Switch to show source. Source and Target are mutually exclusive.

	.PARAMETER Target
		Switch to show target. Source and Target are mutually exclusive.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSpace -FlashArray 1.1.1.1 -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSpace -FlashArray 1.1.1.1 -Source -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSpace -FlashArray 1.1.1.1 -Target -Session $MySession
#>
function Get-PfaProtectionGroupsSpace()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Source,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Target,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If ($Source)
	{
		$Uri = "$PureStorageURIBase/pgroup?space=true&source=true&total=true"
	}
	elseif ($Target)
	{
		$Uri = "$PureStorageURIBase/pgroup?space=true&target=true&total=true"
	}
	else
	{
		$Uri = "$PureStorageURIBase/pgroup?space=true&total=true"
	}
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists size and space consumption attributes for each protection group.
	
	.DESCRIPTION
		Lists size and space consumption attributes for each protection group.
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.

	.PARAMETER Source
		Switch to show source. Source and Target are mutually exclusive.

	.PARAMETER Target
		Switch to show target. Source and Target are mutually exclusive.

	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSnapshotSpace -FlashArray 1.1.1.1 -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSnapshotSpace -FlashArray 1.1.1.1 -Source -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSnapshotSpace -FlashArray 1.1.1.1 -Target -Session $MySession
#>
function Get-PfaProtectionGroupsSnapshotSpace()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Source,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Target,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If ($Source)
	{
		$Uri = "$PureStorageURIBase/pgroup?snap=true&space=true&source=true"
	}
	elseif ($Target)
	{
		$Uri = "$PureStorageURIBase/pgroup?snap=true&space=true&target=true"
	}
	else
	{
		$Uri = "$PureStorageURIBase/pgroup?space=true"
	}
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Used with the snap parameter to display (true) replication data transfer statistics, including data 
		transfer start time, data transfer end time, data transfer progress, and amount of logical/physical 
		data transferred.	

	.DESCRIPTION
		Used with the snap parameter to display (true) replication data transfer statistics, including data 
		transfer start time, data transfer end time, data transfer progress, and amount of logical/physical 
		data transferred.	
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsTransferStatisics -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaProtectionGroupsTransferStatisics()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup?snap=true&transfer=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Includes destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds.	

	.DESCRIPTION
		Includes destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds.	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsPending -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaProtectionGroupsPending()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/pgroup?pending=true"
	$Return = Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json"
	return $Return | Where-Object { $_.time_remaining }
}

<#
	.SYNOPSIS
		Displays the snapshot/replication schedule.

	.DESCRIPTION
		Displays the snapshot/replication schedule.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Source
		Switch to show source. Source and Target are mutually exclusive.

	.PARAMETER Target
		Switch to show target. Source and Target are mutually exclusive.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSchedule -FlashArray 1.1.1.1 -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSchedule -FlashArray 1.1.1.1 -Source -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSchedule -FlashArray 1.1.1.1 -Target -Session $MySession
#>
function Get-PfaProtectionGroupsSchedule()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Source,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Target,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If ($Source)
	{
		$Uri = "$PureStorageURIBase/pgroup?retention=true&schedule=true&source=true"
	}
	elseif ($Target)
	{
		$Uri = "$PureStorageURIBase/pgroup?retention=true&schedule=true&target=true"
	}
	else
	{
		$Uri = "$PureStorageURIBase/pgroup?schedule=true"
	}
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists protection groups and snapshots created on this array. 

	.DESCRIPTION
		Lists protection groups and snapshots created on this array. 

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Source
		Switch to show source. Source and Target are mutually exclusive.

	.PARAMETER Target
		Switch to show target. Source and Target are mutually exclusive.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsRetentionPolicy -FlashArray 1.1.1.1 -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsRetentionPolicy -FlashArray 1.1.1.1 -Source -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsRetentionPolicy -FlashArray 1.1.1.1 -Target -Session $MySession
#>
function Get-PfaProtectionGroupsRetentionPolicy()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Source,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Target,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If ($Source)
	{
		$Uri = "$PureStorageURIBase/pgroup?retention=true&source=true"
	}
	elseif ($Target)
	{
		$Uri = "$PureStorageURIBase/pgroup?retention=true&target=true"
	}
	else
	{
		$Uri = "$PureStorageURIBase/pgroup?retention=true"
	}	
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds. 	

	.DESCRIPTION
		Lists destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds. 	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsPendingOnly -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaProtectionGroupsPendingOnly()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/pgroup?pending_only=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists all snapshots (true).
	
	.DESCRIPTION
		Lists all snapshots (true).
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupsSnapshots -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaProtectionGroupsSnapshots()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/pgroup?snap=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists a specific protection group.	

	.DESCRIPTION
		Lists a specific protection group.	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Specific protection group name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroups -FlashArray 1.1.1.1 -Name TESTGROUP -Session $S
#>
function Get-PfaProtectionGroup()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Displays the total space consumption for a protection group. 

	.DESCRIPTION
		Displays the total space consumption for a protection group. 

	.PARAMETER FlashArray
		A description of the FlashArray parameter.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupSpace -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession
#>
function Get-PfaProtectionGroupSpace()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][switch] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?space=true&total=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists size and space consumption attributes for a protection group.
	
	.DESCRIPTION
		Lists size and space consumption attributes for a protection group.
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.

	.PARAMETER Name
		Protection group name.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupSnapshotSpace -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession

#>
function Get-PfaProtectionGroupSnapshotSpace()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][switch] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?space=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Used with the snap parameter to display (true) replication data transfer statistics, including data 
		transfer start time, data transfer end time, data transfer progress, and amount of logical/physical 
		data transferred.	

	.DESCRIPTION
		Used with the snap parameter to display (true) replication data transfer statistics, including data 
		transfer start time, data transfer end time, data transfer progress, and amount of logical/physical 
		data transferred.	
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.

	.PARAMETER Name
		Protection group name.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupTransferStatisics -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession
#>
function Get-PfaProtectionGroupTransferStatisics()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?snap=true&transfer=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Includes destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds.	

	.DESCRIPTION
		Includes destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds.	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupPending -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession
#>
function Get-PfaProtectionGroupPending()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?pending=true"
	$Return = Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json"
	return $Return | Where-Object { $_.time_remaining }
}

<#
	.SYNOPSIS
		Displays the snapshot/replication schedule.

	.DESCRIPTION
		Displays the snapshot/replication schedule.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupSchedule -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession
#>
function Get-PfaProtectionGroupSchedule()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?schedule=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists protection groups and snapshots created on this array. 

	.DESCRIPTION
		Lists protection groups and snapshots created on this array. 

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupRetentionPolicy -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession
#>
function Get-PfaProtectionGroupRetentionPolicy()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?retention=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds. 	

	.DESCRIPTION
		Lists destroyed protection groups that are in the eradication pending state. Time remaining is displayed in seconds. 	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupPendingOnly -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession
#>
function Get-PfaProtectionGroupPendingOnly()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?pending_only=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists all snapshots (true).
	
	.DESCRIPTION
		Lists all snapshots (true).
	
	.PARAMETER FlashArray
		A description of the FlashArray parameter.

	.PARAMETER Name
		Protection group name.
	
	.PARAMETER Session
		A description of the Session parameter.
	
	.EXAMPLE
		PS C:\> Get-PfaProtectionGroupSnapshots -FlashArray 1.1.1.1 -Name PGROUP1 -Session $MySession
#>
function Get-PfaProtectionGroupSnapshots()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/pgroup/$Name" + "?snap=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Creates a new snapshot of a Pure Storage Protection Group(s). 
	
	.DESCRIPTION
		The New-PfaProtectionGroupSnapshot creates a new snapshot of the host, host group or volumes
		that are part of a Protection Group. Assumes that the apply_retention will be used for all snapshots.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Identification of the Pure Storage Protection Group to snapshot.

	.PARAMETER SnapshotSuffix (Optional)
		Suffix to use for the new Protection Group snapshot. The snapshot suffixes must consist of 
		between 1 and 63 characters (alphanumeric and '-'), starting and ending with a letter or a
		number. It MUST NOT consist of all numeric values.

	.PARAMETER ReplicateNow
		Replicates this snapshot to all target arrays.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		PS C:\> New-PfaProtectionGroupSnapshot -FlashArray 1.1.1.1 -Name TESTGROUP -SnapshotSuffix TEST -ReplicateNow -Session $S

	.EXAMPLE
		PS C:\> New-PfaProtectionGroupSnapshot -FlashArray 1.1.1.1 -Name TESTGROUP -ReplicateNow -Session $S
#>
function New-PfaProtectionGroupSnapshot()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $ProtectionGroupName,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $SnapshotSuffix,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $ReplicateNow,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$ProtectionGroupSnapshot = $null
	if (!$SnapshotSuffix)
	{
		if (!$ReplicateNow)
		{
			$ProtectionGroupSnapshot = [ordered]@{
				apply_retention = "true"	
				snap = "true"
				source = [Object[]]$ProtectionGroupName
			} | ConvertTo-Json
		}
		else
		{
			$ProtectionGroupSnapshot = [ordered]@{
				apply_retention = "true"
				replicate_now = "true"
				snap = "true"
				source = [Object[]]$ProtectionGroupName
			} | ConvertTo-Json
		}
	}
	else
	{
		if (!$ReplicateNow)
		{
			$ProtectionGroupSnapshot = [ordered]@{
				apply_retention = "true"
				snap = "true"
				source = [Object[]]$ProtectionGroupName
				suffix = $SnapshotSuffix
			} | ConvertTo-Json
		}
		else
		{
			$ProtectionGroupSnapshot = [ordered]@{
				apply_retention = "true"
				replicate_now = "true"
				snap = "true"
				source = [Object[]]$ProtectionGroupName
				suffix = $SnapshotSuffix
			} | ConvertTo-Json
		}
		
	}
	
	$Uri = "$PureStorageURIBase/pgroup"
	$Return = Invoke-RestMethod -Method POST -Uri $Uri -Body $ProtectionGroupSnapshot -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Creates a new snapshot of a Pure Storage Protection Group(s). 
	
	.DESCRIPTION
		The New-PfaProtectionGroupSnapshot creates a new snapshot of the host, host group or volumes
		that are part of a Protection Group. Assumes that the apply_retention will be used for all snapshots.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER HostGroups
		List of one or more host groups to be included in the new protection group.

	.PARAMETER Hosts
		List of one or more hosts to be included in the new protection group.

	.PARAMETER Volumes
		List of one or more volumes to be included in the new protection group.

	.PARAMETER ReplicationTargets
		List of one or more targets to be included in the new protection group.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		PS C:\> New-PfaProtectionGroup -FlashArray 1.1.1.1 -Name TESTGROUP -HostGroups HG1,HG2 -Session $S

	.EXAMPLE
		PS C:\> New-PfaProtectionGroup -FlashArray 1.1.1.1 -Name TESTGROUP -Hosts HOST1,HOST2,HOST3 -Session $S

	.EXAMPLE
		PS C:\> New-PfaProtectionGroup -FlashArray 1.1.1.1 -Name TESTGROUP -Volumes VOL1,VOl2,VOL3,VOL4,VOL5 -Session $S

	.EXAMPLE
		PS C:\> New-PfaProtectionGroup -FlashArray 1.1.1.1 -Name TESTGROUP -Volumes VOL1,VOl2,VOL3,VOL4,VOL5 -ReplicationTargets ARRAY2 -Session $S
#>
function New-PfaProtectionGroup()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $HostGroups,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $Hosts,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $Volumes,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $ReplicationTargets,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$ProtectionGroup = $null
	
	if ($HostGroups -And $ReplicationTargets)
	{
		$ProtectionGroup = [ordered]@{
			hgrouplist = [Object[]]$HostGroups
			targetlist = [Object[]]$ReplicationTargets
		} | ConvertTo-Json
	}
	elseif ($HostGroups)
	{
		$ProtectionGroup = [ordered]@{
			hgrouplist = [Object[]]$HostGroups
		} | ConvertTo-Json
	}
	
	if ($Hosts -And $ReplicationTargets)
	{
		$ProtectionGroup = [ordered]@{
			hostlist = [Object[]]$Hosts
			targetlist = [Object[]]$ReplicationTargets
		} | ConvertTo-Json
	}
	elseif ($Hosts)
	{
		$ProtectionGroup = [ordered]@{
			hostlist = [Object[]]$Hosts
		} | ConvertTo-Json
	}
	
	
	if ($Volumes -And $ReplicationTargets)
	{
		$ProtectionGroup = [ordered]@{
			vollist = [Object[]]$Volumes
			targetlist = [Object[]]$ReplicationTargets
		} | ConvertTo-Json
	}
	elseif ($Volumes)
	{
		$ProtectionGroup = [ordered]@{
			vollist = [Object[]]$Volumes
		} | ConvertTo-Json
	}
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method POST -Uri $Uri -Body $ProtectionGroup -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Destroys the specified protection group and all of its snapshots.

	.DESCRIPTION
		Destroys the specified protection group and all of its snapshots.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		PS C:\> Remove-PfaProtectionGroup -FlashArray 1.1.1.1 -Name TESTGROUP -Session $S
#>
function Remove-PfaProtectionGroup()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Eradicates a destroyed protection group and all of its snapshots.	

	.DESCRIPTION
		Eradicates a destroyed protection group and all of its snapshots.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		PS C:\> Eradicate-PfaProtectionGroup -FlashArray 1.1.1.1 -Name TESTGROUP -Session $S
#>
function Eradicate-PfaProtectionGroup()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$ProtectionGroup = $null
	$ProtectionGroup = @{
		eradicate = "true"
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method DELETE -Uri $Uri -Body $ProtectionGroup -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Recovers the contents of the specified volume. Set the parameter to recover. 
	
	.DESCRIPTION
		Recovers the contents of the specified volume. Set the parameter to recover.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.
	
	.PARAMETER Name
		Volume name.
	
	.PARAMETER Size
		Creates a volume with the specified provisioned size.

		Enter the size as a number (bytes) or as a string with a single character unit symbol. Valid 
		unit symbols are S, K, M, G, T, P, denoting 512-byte sectors, KiB, MiB, GiB, TiB, and PiB respectively.
		"Ki" denotes 2^10, "Mi" denotes 2^20, and so on. If the unit symbol is not specified, the unit defaults 
		to sectors.
	
	.PARAMETER Source
		Creates a new volume from a snapshot as the source.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Size 100G -Session $MySession

	.EXAMPLE
		PS C:\> New-PfaVolume -FlashArray 1.1.1.1 -Name Volume1 -Source Volume2.Snapshot -Session $MySession
#>
function Recover-PfaProtectionGroup
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$PGroupRecover = @{
		action = "recover"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $PGroupRecover -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Renames a protection group.	

	.DESCRIPTION
		Renames a protection group.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Current protection group name.

	.PARAMETER NewName
		New protection group name.
	
	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Rename-PfaProtectionGroup -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession

	.EXAMPLE
		PS C:\> Rename-PfaProtectionGroup -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Rename-PfaProtectionGroup
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $NewName,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$PGroupUpdate = @{
		name = $NewName
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $PGroupUpdate -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Enable the protection group replication schedule.	

	.DESCRIPTION
		Enable the protection group replication schedule.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Enable-PfaProtectionGroupReplication -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Enable-PfaProtectionGroupReplication
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$PGroupReplEnable = @{
		replicate_enabled = "true"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $PGroupReplEnable -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disable the protection group replication schedule.	

	.DESCRIPTION
		Disable the protection group replication schedule.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Disable-PfaProtectionGroupReplication -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Disable-PfaProtectionGroupReplication
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$PGroupReplEnable = @{
		replicate_enabled = "false"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $PGroupReplEnable -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Enable the protection group snapshot schedule.	

	.DESCRIPTION
		Enable the protection group snapshot schedule.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Enable-PfaProtectionGroupSnapshots -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Enable-PfaProtectionGroupSnapshots
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$PGroupSnapEnable = @{
		snap_enabled = "true"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $PGroupSnapEnable -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disable the protection group snapshot schedule.	

	.DESCRIPTION
		Disable the protection group snapshot schedule.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Disable-PfaProtectionGroupSnapshots -FlashArray 1.1.1.1 -Name Volume1 -Session $MySession
#>
function Disable-PfaProtectionGroupSnapshots
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$PGroupSanpEnable = @{
		snap_enabled = "false"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $PGroupSnapEnable -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Creates a new snapshot of a Pure Storage Protection Group(s). 
	
	.DESCRIPTION
		The New-PfaProtectionGroupSnapshot creates a new snapshot of the host, host group or volumes
		that are part of a Protection Group. Assumes that the apply_retention will be used for all snapshots.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER HostGroups
		Add one or more host groups to be included in the new protection group.

	.PARAMETER Hosts
		Add one or more hosts to be included in the new protection group.

	.PARAMETER Volumes
		Add one or more volumes to be included in the new protection group.

	.PARAMETER ReplicationTargets
		Add one or more targets to be included in the new protection group.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		PS C:\> Add-PfaProtectionGroupMembers -FlashArray 1.1.1.1 -Name TESTGROUP -HostGroups HG1,HG2 -Session $S
#>
function Add-PfaProtectionGroupMembers()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $HostGroups,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $Hosts,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $Volumes,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $ReplicationTargets,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$UpdateProtectionGroup = $null
	
	if ($HostGroups)
	{
		$UpdateProtectionGroup = [ordered]@{
			addhgrouplist = [Object[]]$HostGroups
		} | ConvertTo-Json
	}
	elseif ($Hosts)
	{
		$UpdateProtectionGroup = [ordered]@{
			addhostlist = [Object[]]$Hosts
		} | ConvertTo-Json
	}
	elseif ($Volumes)
	{
		$UpdateProtectionGroup = [ordered]@{
			addvollist = [Object[]]$Volumes
		} | ConvertTo-Json
	}
	elseif ($ReplicationTargets)
	{
		$UpdateProtectionGroup = [ordered]@{
			addtargetlist = [Object[]]$ReplicationTargets
		} | ConvertTo-Json
	}
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $UpdateProtectionGroup -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Removes a members (HostGroups, Hosts, Volumes or Replication Targets from the existing list.
	
	.DESCRIPTION
		Removes a members (HostGroups, Hosts, Volumes or Replication Targets from the existing list.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER HostGroups
		Remove one or more host groups to be included in the new protection group.

	.PARAMETER Hosts
		Remove one or more hosts to be included in the new protection group.

	.PARAMETER Volumes
		Remove one or more volumes to be included in the new protection group.

	.PARAMETER ReplicationTargets
		Remove one or more targets to be included in the new protection group.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		PS C:\> Add-PfaProtectionGroupMembers -FlashArray 1.1.1.1 -Name TESTGROUP -HostGroups HG1,HG2 -Session $S
#>
function Remove-PfaProtectionGroupMembers()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $HostGroups,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $Hosts,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $Volumes,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $ReplicationTargets,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$UpdateProtectionGroup = $null
	
	if ($HostGroups)
	{
		$UpdateProtectionGroup = [ordered]@{
			remhgrouplist = [Object[]]$HostGroups
		} | ConvertTo-Json
	}
	elseif ($Hosts)
	{
		$UpdateProtectionGroup = [ordered]@{
			remhostlist = [Object[]]$Hosts
		} | ConvertTo-Json
	}
	elseif ($Volumes)
	{
		$UpdateProtectionGroup = [ordered]@{
			remvollist = [Object[]]$Volumes
		} | ConvertTo-Json
	}
	elseif ($ReplicationTargets)
	{
		$UpdateProtectionGroup = [ordered]@{
			remtargetlist = [Object[]]$ReplicationTargets
		} | ConvertTo-Json
	}
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $UpdateProtectionGroup -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Allows (true) or disallows (false) a protection group from being replicated.	

	.DESCRIPTION
		Allows (true) or disallows (false) a protection group from being replicated.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER Replication
		Allow or Disallow replication.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		PS C:\> Update-PfaProtectionGroupReplication -FlashArray 1.1.1.1 -Name TESTGROUP -Replication Allow -Session $S
#>
function Update-PfaProtectionGroupReplication()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateSet('Allow', 'Disallow')][string]$Replication,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	switch ($Replication)
	{
		"Allow" {
			$UpdateProtectionGroup = @{
				allowed = "true"
			} | ConvertTo-Json
		}
		"Disallow" {
			$UpdateProtectionGroup = @{
				allowed = "false"
			} | ConvertTo-Json
		}
	}
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $UpdateProtectionGroup -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Modifies the replication schedule of the protection group. Specifies the range of time at which to 
		suspend replication. See below example for the dictionary format.

	.DESCRIPTION
		Modifies the replication schedule of the protection group. Specifies the range of time at which to 
		suspend replication. See below example for the dictionary format.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Name
		Protection group name.

	.PARAMETER StartTime
		Start time of blackout period. Format 24hr clock, Eg. 2pm = 14, 8pm = 20

	.PARAMETER EndTime
		Start time of blackout period. Format 24hr clock, Eg. 2pm = 14, 8pm = 20

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.

	.EXAMPLE
		Creates a blackout period between 2am and 6am.
	
		PS C:\> Update-PfaProtectionGroupReplication -FlashArray 1.1.1.1 -Name TESTGROUP -StartTime 2 -EndTime 6 -Session $S
#>
function Set-PfaProtectionGroupReplicationBlackout()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][int] $StartTime,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][int] $EndTime,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$EndTimeSeconds = $EndTime * 3600
	$StartTimeSeconds = $StartTime * 3600
	
	$SetBlackout = [ordered]@{
		replicate_blackout = @{
			end = $EndTimeSeconds
			start = $StartTimeSeconds
		}
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/pgroup/$Name"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $SetBlackout -WebSession $Session -ContentType "application/json"
}

#endregion

#region FA-Connection-Port-Cmdlets
<#
	.SYNOPSIS
		Lists array ports and the worldwide names assigned to each port.	

	.DESCRIPTION
		Lists array ports and the worldwide names assigned to each port.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaPorts -FlashArray 1.1.1.1 -Session $S
#>
function Get-PfaPorts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$uri = "$PureStorageURIBase/port"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Displays host worldwide names (both those discovered by Purity and those assigned by administrators) and the 
		array ports (targets) on which they are eligible to communicate.

	.DESCRIPTION
		Displays host worldwide names (both those discovered by Purity and those assigned by administrators) and the 
		array ports (targets) on which they are eligible to communicate.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaInitiators -FlashArray 1.1.1.1 -Session $S
#>
function Get-PfaInitiators()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/port?initiators=true"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Enables (true) the array ports, opening or blocking communication with hosts.

	.DESCRIPTION
		Enables (true) the array ports, opening or blocking communication with hosts.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Enable-PfaPorts -FlashArray 1.1.1.1 -Session $S
#>
function Enable-PfaPorts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/port?enabled=true"
	$Return = Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disables (false) the array ports, opening or blocking communication with hosts.

	.DESCRIPTION
		Disables (false) the array ports, opening or blocking communication with hosts.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Enable-PfaPorts -FlashArray 1.1.1.1 -Session $S
#>
function Disable-PfaPorts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/port?enabled=false"
	$Return = Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json"
}

#endregion

#region FA-Alerts-Messages-Cmdlets
<#
	.SYNOPSIS
		Lists email recipients that are designated to receive Purity alert messages.	

	.DESCRIPTION
		Lists email recipients that are designated to receive Purity alert messages.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaAlerts -FlashArray 1.1.1.1 -Session $S
#>
function Get-PfaAlerts()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/alert"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists information about the specified email recipient.	

	.DESCRIPTION
		Lists information about the specified email recipient.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Email
		Email recipient, defaults to flasharray-alerts@purestorage.com

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaAlertRecipient -FlashArray 1.1.1.1 -Session $S
#>
function Get-PfaAlertRecipient()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Email = "flasharray-alerts@purestorage.com",
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/alert/$Email"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists information about the specified email recipient.	

	.DESCRIPTION
		Lists information about the specified email recipient.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Email
		Email recipient to add.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaAlertRecipient -FlashArray 1.1.1.1 -Email test@test.com -Session $S
#>
function New-PfaAlertRecipient()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Email,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/alert/$Email"
	$Return = (Invoke-RestMethod -Method POST -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Tests the ability of the array to send alert messages to all of the designated email addresses.
	
	.DESCRIPTION
		Tests the ability of the array to send alert messages to all of the designated email addresses.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Email
		Email recipient to test.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Test-PfaAlertRecipient -FlashArray 1.1.1.1 -Email test@test.com -Session $S
#>
function Test-PfaAlertRecipient()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Email,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Test = [ordered]@{
		action = "test"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/alert/$Email"
	$Return = (Invoke-RestMethod -Method PUT -Uri $Uri -Body $Test -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Enables (true) the transmission of alert messages to the specified email address.	

	.DESCRIPTION
		Enables (true) the transmission of alert messages to the specified email address.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Email
		Email recipient to test.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Enable-PfaAlertRecipient -FlashArray 1.1.1.1 -Email test@test.com -Session $S
#>
function Enable-PfaAlertRecipient()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Email,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$SetStatus = [ordered]@{
		enabled = "true"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/alert/$Email"
	$Return = (Invoke-RestMethod -Method PUT -Uri $Uri -Body $SetStatus -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Disables (false) the transmission of alert messages to the specified email address.	

	.DESCRIPTION
		Disables (false) the transmission of alert messages to the specified email address.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Email
		Email recipient to test.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Disable-PfaAlertRecipient -FlashArray 1.1.1.1 -Email test@test.com -Session $S
#>
function Disable-PfaAlertRecipient()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Email,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$SetStatus = [ordered]@{
		enabled = "false"
	} | ConvertTo-Json
	$Uri = "$PureStorageURIBase/alert/$Email"
	$Return = (Invoke-RestMethod -Method PUT -Uri $Uri -Body $SetStatus -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Disables (false) the transmission of alert messages to the specified email address.	

	.DESCRIPTION
		Disables (false) the transmission of alert messages to the specified email address.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Type
		All: Lists all alert events and audit records.	 

		Audit: Lists audit records instead of alerts.

		Flagged: Lists flagged messages only. The array automatically flags warnings and critical alerts.

		Open: Lists open messages.

		Recent: Lists recent messages. An audit record is considered recent if it relates to a command 
		issued within the past 24 hours. An alert is considered recent if the situation that triggered 
		it is unresolved, or has only been resolved within the past 24 hours.

		User: When audit is set to true, user can be used to list audit records for a specific user.

	.PARAMETER Username (OPTIONAL)
		When audit is set to true, user can be used to list audit records for a specific user.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaMessages -FlashArray 1.1.1.1 -Type Audit -Session $S

	.EXAMPLE
		PS C:\> Get-PfaMessages -FlashArray 1.1.1.1 -Type User -Username User1 -Session $S

#>
function Get-PfaMessages()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateSet('All', 'Audit', 'Flagged', 'Open', 'Recent', 'User')][string]$Type,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Username,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	switch ($Type)
	{
		"All" { $Uri = "$PureStorageURIBase/message" }
		"Audit" { $Uri = "$PureStorageURIBase/message?audit=true" }
		"Flagged" { $Uri = "$PureStorageURIBase/message?flagged=true" }
		"Open" { $Uri = "$PureStorageURIBase/message?open=true" }
		"Recent" { $Uri = "$PureStorageURIBase/message?recent=true" }
		"User" { $Uri = "$PureStorageURIBase/message?user=$Username" }
	}
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Deletes an email address from the list of addresses designated to receive Purity alert messages. 
		You cannot delete the built-in flasharray-alerts@purestorage.com address.	

	.DESCRIPTION
		Deletes an email address from the list of addresses designated to receive Purity alert messages. 
		You cannot delete the built-in flasharray-alerts@purestorage.com address.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Email
		Email recipient to add.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Remove-PfaAlertRecipient -FlashArray 1.1.1.1 -Email test@test.com -Session $S
#>
function Remove-PfaAlertRecipient()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Email,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/alert/$Email"
	$Return = (Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Unflags a message.

	.DESCRIPTION
		Unflags (false) a message.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Id
		Unflags a message.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Hide-PfaMessage -FlashArray 1.1.1.1 -Id 25680 -Session $S
#>
function Hide-PfaMessage()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Id,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/message/$Id" +"?flagged=false"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Flags a message. 

	.DESCRIPTION
		Flags (true) a message. If set to true, flags the message with the specified ID. If set to false, unflags the message.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Id
		Flags a message.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Show-PfaMessage -FlashArray 1.1.1.1 -Id 25680 -Session $S
#>
function Show-PfaMessage()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Id,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/message/$Id" + "?flagged=true"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $HideMessage -WebSession $Session -ContentType "application/json"
}

#endregion

#region FA-SNMP-Manager-Connections-Cmdlets
<#
	.SYNOPSIS
		Lists designated SNMP managers and their communication and security attributes.	

	.DESCRIPTION
		Lists designated SNMP managers and their communication and security attributes.	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER EngineId
		SNMP v3 only. If set to true, displays the SNMP v3 engine ID generated by Purity for the array.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaSnmp -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaSnmp()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $EngineId,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If ($EngineId)
	{
		$Uri = "$PureStorageURIBase/snmp?engine_id=true"
	}
	else
	{
		$Uri = "$PureStorageURIBase/snmp"
	}
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Stops communication with the specified managers and deletes the SNMP manager object.

	.DESCRIPTION
		Stops communication with the specified managers and deletes the SNMP manager object.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Manager
		SNMP v3 only. If set to true, displays the SNMP v3 engine ID generated by Purity for the array.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Remove-PfaSnmpManager -FlashArray 1.1.1.1 -Session $MySession
#>
function Remove-PfaSnmpManager()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Manager,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/snmp/$Manager"
	$Return = Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Lists communication and security attributes for the specified SNMP manager.

	.DESCRIPTION
		Lists communication and security attributes for the specified SNMP manager.
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Manager
		Name of the SNMP manager.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaSnmpManager -FlashArray 1.1.1.1 -Manager SNMPMANAGER -Session $MySession
#>
function Get-PfaSnmpManager()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Manager,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/snmp/$Manager"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Creates a Purity SNMP manager object that identifies a host (SNMP manager) and specifies the protocol 
		attributes for communicating with it.

	.DESCRIPTION
		Creates a Purity SNMP manager object that identifies a host (SNMP manager) and specifies the protocol 
		attributes for communicating with it.

		Once a manager object is created, the transmission of SNMP traps is immediately enabled.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Manager
		Name of the SNMP manager.

	.PARAMETER Hostname
		DNS hostname or IP address of a computer that hosts an SNMP manager to which Purity is to send trap 
		messages when it generates alerts.

	.PARAMETER User
		SNMP v3 only. User ID recognized by the specified SNMP managers which Purity is to use in communications 
		with them. The value must be between 1 and 32 characters in length and from the set {[A-Z], [a-z], [0-9], 
		_ (underscore), and -(hyphen)}.

	.PARAMETER AuthProtocol
		SNMP v3 only. Hash algorithm used to validate the authentication passphrase. Valid values are MD5 or SHA.

	.PARAMETER AuthPassphrase
		SNMP v3 only. Passphrase used by Purity to authenticate the array with the specified managers. The value 
		must be between 1 and 32 characters in length and from the set {[A-Z], [a-z], [0-9], _ (underscore), 
		and - (hyphen)}.

	.PARAMETER PrivacyProtocol
		SNMP v3 only. Passphrase used to encrypt SNMP messages. The value must be between 8 and 63 non-space 
		ASCII characters in length.

	.PARAMETER PrivacyPassphrase
		SNMP v3 only. Encryption protocol for SNMP messages. Valid values are AES or DES.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> New-PfaSnmpv3Manager -FlashArray 1.1.1.1 -Manager TEST -Hostname TEST1 -User Administrator -AuthProtocol MD5 -AuthPassphrase TESTPHRASE -PrivacyProtocol AES -PrivacyPassphrase TESTPHRASE -Session $S
#>
function New-PfaSnmpv3Manager()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Manager,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Hostname,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $User,
		[Parameter(Mandatory = $False)][ValidateSet('MD5', 'SHA')][string]$AuthProtocol,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $AuthPassphrase,
		[Parameter(Mandatory = $False)][ValidateSet('AES', 'DES')][string]$PrivacyProtocol,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $PrivacyPassphrase,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$SnmpManagerv3Config = $null
	$SnmpManagerv3Config = @{
		host = $Hostname
		user = $User
		auth_protocol = $AuthProtocol
		auth_passphrase = $AuthPassphrase
		privacy_protocol = $PrivacyProtocol
		privacy_passphrase = $PrivacyPassphrase
		version = "v3"
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/snmp/$Manager"
	$Return = Invoke-RestMethod -Method POST -Uri $Uri -Body $SnmpManagerv3Config -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Creates a Purity SNMP manager object that identifies a host (SNMP manager) and specifies the protocol 
		attributes for communicating with it.

	.DESCRIPTION
		Creates a Purity SNMP manager object that identifies a host (SNMP manager) and specifies the protocol 
		attributes for communicating with it.

		Once a manager object is created, the transmission of SNMP traps is immediately enabled.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Manager
		Name of the SNMP manager.

	.PARAMETER Hostname
		DNS hostname or IP address of a computer that hosts an SNMP manager to which Purity is to send trap 
		messages when it generates alerts.

	.PARAMETER Community
		SNMP v2c only. Manager community ID under which Purity is to communicate with the specified managers. 
		The value must be between 1 and 32 characters in length and from the set {[A-Z], [a-z], [0-9], 
		_ (underscore), and - (hyphen)}.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> New-PfaSnmpv2cManager -FlashArray 1.1.1.1 -Session $S
#>
function New-PfaSnmpv2cManager()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Manager,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Hostname,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Community,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$SnmpManagerv2cConfig = $null
	$SnmpManagerv2cConfig = @{
		host = $Hostname
		community = $Community
		version = "v2c"
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/snmp/$Manager"
	$Return = Invoke-RestMethod -Method POST -Uri $Uri -Body $SnmpManagerv2cConfig -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Updates a Purity SNMP manager object that identifies a host (SNMP manager) and specifies the protocol 
		attributes for communicating with it.

	.DESCRIPTION
		Creates a Purity SNMP manager object that identifies a host (SNMP manager) and specifies the protocol 
		attributes for communicating with it.

		Once a manager object is created, the transmission of SNMP traps is immediately enabled.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Manager
		Name of the SNMP manager.

	.PARAMETER Name
		New name of the SNMP manager.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Update-PfaSnmpManager -FlashArray 1.1.1.1 -Manager TEST -Name NEWTEST -Session $S
#>
function Update-PfaSnmpManager()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Manager,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Name,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$SnmpManagerName = $null
	$SnmpManagerName = @{
		name = $Name
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/snmp/$Manager"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $SnmpManagerName -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Send test trap to the specified Purity SNMP manager object.

	.DESCRIPTION
		Send test trap to the specified Purity SNMP manager object.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Manager
		Name of the SNMP manager.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Test-PfaSnmpManager -FlashArray 1.1.1.1 -Manager TEST -Session $S
#>
function Test-PfaSnmpManager()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Manager,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$TestSnpManager = @{
		action = "test"	
	}
	
	$Uri = "$PureStorageURIBase/snmp/$Manager"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $TestSnpManager -WebSession $Session -ContentType "application/json"
}

#endregion

#region FA-SSL-Cmdlets
<#
	.SYNOPSIS
		Lists certificate attributes or exports certificates.

	.DESCRIPTION
		Lists certificate attributes or exports certificates.

		If the request does not include parameters, the REST API call returns the attributes of the certificate. 
		Include the certificate or intermediate_certificate parameter to export the respective certificate.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaSslCert -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaSslCert()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/cert"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Exports certificates attributes.

	.DESCRIPTION
		Exports certificates attributes.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.SWITCH Certificate
		If set exports the current certificate
	
	.SWITCH IntermediateCertificate
		If set exports the current intermediate certificate.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Export-PfaSslCert -FlashArray 1.1.1.1 -Certificate -Session $MySession

	.EXAMPLE
		PS C:\> Export-PfaSslCert -FlashArray 1.1.1.1 -IntermediateCertification -Session $MySession

#>
function Export-PfaSslCert()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $Certificate,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][switch] $IntermediateCertificate,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If (!$Certificate)
	{
		If (!$IntermediateCertificate)
		{
			$Uri = "$PureStorageURIBase/cert"
		}
		Else
		{
			$Uri = "$PureStorageURIBase/cert?intermediate_certificate=true"
		}
	}
	Else
	{
		$Uri = "$PureStorageURIBase/cert?certificate=true"
	}
	
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

#endregion

#region FA-Network-Interface-Cmdlets
<#
	.SYNOPSIS
		Lists DNS attributes for the array administrative network.

	.DESCRIPTION
		Lists DNS attributes for the array administrative network.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaDns -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaDns
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/dns"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists DNS attributes for the array administrative network.

	.DESCRIPTION
		Lists DNS attributes for the array administrative network.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Domain
		Domain suffix to be appended by the array when performing DNS lookups.

	.PARAMETER Nameservers
		A list of up to three DNS server IP addresses that replace the current list of name servers. The order of the list 
		is significant. Purity queries DNS servers in the order in which their IP addresses are listed in this option.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaDns -FlashArray 1.1.1.1 -Domain EXAMPLE.COM -Nameservers 9.9.9.9,4.4.4.4,6.6.6.6 -Session $MySession
#>
function Set-PfaDns
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $Domain,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string[]] $Nameservers,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Dns = $null
	If ($Domain)
	{
		If ($Namesevers)
		{
			$Dns = @{
				domain = $Domain
				nameservers = [Object[]]$Nameservers
			} | ConvertTo-Json
		}
		else
		{
			$Dns = @{
				domain = $Domain
			} | ConvertTo-Json
		}
		else
		{
		}
	}
	elseif ($Nameservers)
	{
		$Dns = @{
			nameservers = [Object[]]$Nameservers
		} | ConvertTo-Json
	}
	
	$Uri = "$PureStorageURIBase/dns"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $Dns -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Lists array administrative network interfaces and their statuses (enabled or disabled) and attributes.

	.DESCRIPTION
		Lists array administrative network interfaces and their statuses (enabled or disabled) and attributes.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaNetwork -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaNetwork
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/network"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists the attributes for the specified network component.

	.DESCRIPTION
		Lists the attributes for the specified network component.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Interface
		Interface to retrieve. Eg. CT0.ETH0, CT0.ETH1, CT1.ETH0, REPLBOND, VIR0, VIR1

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaNetworkInterface -FlashArray 1.1.1.1 -Interface CT0.ETH0 -Session $MySession
#>
function Get-PfaNetworkInterface
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][string]$Interface,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/network/$Interface"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}


#endregion

#region FA-Hardware-Cmdlets
<#
	.SYNOPSIS
		Lists array hardware component information.

	.DESCRIPTION
		Lists array hardware component information.

		Returns information about array hardware components that are capable of reporting their status. The display 
		is primarily useful for diagnosing hardware-related problems.	
	
	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaHardware -FlashArray 1.1.1.1 -Session $S
#>
function Get-PfaHardware()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/hardware"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists the attributes for the specified hardware component.

	.DESCRIPTION
		Lists the attributes for the specified hardware component.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Component
		Specific component to query.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaHardware -FlashArray 1.1.1.1 -Session $S
#>
function Get-PfaHardwareComponent()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Component,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/hardware/$Component"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Controls the visual identification of the specified controllers, storage shelves, and storage shelf drive bays.

	.DESCRIPTION
		Controls the visual identification of the specified controllers, storage shelves, and storage shelf drive bays.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Component
		Specific component to query.

	.PARAMETER State
		On or Off for LED.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Show-PfaHardwareLed -FlashArray 1.1.1.1 -Component SH0.BAY0 -State On -Session $S
#>
function Show-PfaHardwareLed()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Component,
		[Parameter(Mandatory = $True)][ValidateSet('On', 'Off')][string]$State,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)

	$LED = $null
	switch ($State)
	{
		"On"
		{
			$LED = @{
				identify = "on"
			} | ConvertTo-Json
		}
		"Off"
		{
			$LED = @{
				identify = "off"
			} | ConvertTo-Json
		}
	}
	
	$Uri = "$PureStorageURIBase/hardware/$Component"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $LED -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Lists SSD and NVRAM modules and their attributes.

	.DESCRIPTION
		Lists SSD and NVRAM modules and their attributes.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaDrive -FlashArray 1.1.1.1 -Session $S
#>
function Get-PfaDrives()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/drive"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists the attributes for the specified drive.

	.DESCRIPTION
		Lists the attributes for the specified drive.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Location
		Location of drive. Eg. SH0.BAY0

	.PARAMETER Session
		Pure Storage FlashArray session created with Connect-PfaController.
	
	.EXAMPLE
		PS C:\> Get-PfaDrive -FlashArray 1.1.1.1 -Location SH0.BAY0 -Session $S
#>
function Get-PfaDrive()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Location,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	$Uri = "$PureStorageURIBase/drive/$Location"
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

#endregion

#region FA-Users-Cmdlets
<#
	.SYNOPSIS
		Lists public key and API token information for all users.

	.DESCRIPTION
		Lists public key and API token information for all users.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Show
		API_Token: Displays a list of users that have REST API access and the dates in which the API tokens were created.

		Public_Key: Displays a list of users that have public key access.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaAdmin -FlashArray 1.1.1.1 -Show API_Token -Session $MySession
#>
function Get-PfaUsers()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateSet('API_Token', 'Public_Key')][string]$Show,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	switch ($Show)
	{
		"API_Token" { $Uri = "$PureStorageURIBase/admin?api_token=true&expose=true" }
		"Public_Key" { $Uri = "$PureStorageURIBase/admin?publickey=true" }
	}
	
	return (Invoke-RestMethod -Method Get -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Lists public key and API token information for all users.

	.DESCRIPTION
		Lists public key and API token information for all users.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Show
		API_Token: Displays a list of users that have REST API access and the dates in which the API tokens were created.

		Public_Key: Displays a list of users that have public key access.

	.PARAMETER User
		Lists public key or API token information for the specified user.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Get-PfaAdmin -FlashArray 1.1.1.1 -Show API_Token -Session $MySession

	.EXAMPLE
		PS C:\> Get-PfaAdmin -FlashArray 1.1.1.1 -Show API_Token -User pureuser -Session $MySession
#>
function Get-PfaUser()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateSet('API_Token', 'Public_Key')][string]$Show,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $User,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	If ($User)
	{
		switch ($Show)
		{
			"API_Token" { $Uri = "$PureStorageURIBase/admin/$User" + "/apitoken" }
			"Public_Key" { $Uri = "$PureStorageURIBase/admin/$User" + "?publickey=true"}
		}
	}
	else
	{
		switch ($Show)
		{
			"API_Token" { $Uri = "$PureStorageURIBase/admin?api_token=true&expose=true" }
			"Public_Key" { $Uri = "$PureStorageURIBase/admin?publickey=true" }
		}
	}
	
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Creates an API token for the specified user.
	
	.DESCRIPTION
		Creates an API token for the specified user.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER User
		Lists public key or API token information for the specified user.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> New-PfaApiToken -FlashArray 1.1.1.1 -User NEWUSER -Session $MySession
#>
function New-PfaApiToken()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $User,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/admin/$User" + "/apitoken" 
	return (Invoke-RestMethod -Method POST -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Clears all user permission cache entries.

	.DESCRIPTION
		Clears all user permission cache entries.

		User permission cache entries are also automatically updated when the user starts a new session.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Clear-PfaPermissionCache -FlashArray 1.1.1.1 -Session $MySession
#>
function Clear-PfaPermissionCache()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$ClearPermCache = $null
	$ClearPermCache = @{
		clear = "true"
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/admin?action=refresh"
	return (Invoke-RestMethod -Method PUT -Uri $Uri -Body $ClearPermCache -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Sets the password or public key or refreshes the user permission cache entries for the specified user.

	.DESCRIPTION
		Sets the password or public key or refreshes the user permission cache entries for the specified user.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER User
		User to update.

	.PARAMETER Old
		Used with the password parameter to change the password for the single, local administrative account pureuser. 
		
	.PARAMETER New
		Used with the Old parameter to change the password for the single, local administrative account pureuser. The value 
		must be between 1 and 32 characters in length and be entered from a standard English (U.S.) keyboard.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaUserPassword -FlashArray 1.1.1.1 -User TESTUSER -Old TESTPWD -New NEWPWD -Session $MySession
#>
function Set-PfaUserPassword()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $User,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $Old,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $New,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Password = $null
	$Password = @{
		old_password = $Old
		password = $New
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/admin/$User"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $Password -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Sets the password or public key or refreshes the user permission cache entries for the specified user.

	.DESCRIPTION
		Sets the password or public key or refreshes the user permission cache entries for the specified user.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER User
		User to update.

	.PARAMETER PublicKey
		Changes the public key for SSH access for the specified user. Only system administrators can change public 
		keys on behalf of other users. If no users are provided as arguments, a request to change the public key will 
		be for the administrator issuing the request and a request to display set public keys will show all users with 
		a public key configured.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Set-PfaUserPublicKey -FlashArray 1.1.1.1 -User TESTUSER -PublicKey <string> -Session $MySession
#>
function Set-PfaUserPublicKey()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $User,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $PublicKey,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$PubKey = $null
	$PubKey = @{
		publickey = $PublicKey
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/admin/$User"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $PubKey -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Deletes API token for the specified user.	

	.DESCRIPTION
		Deletes API token for the specified user.	

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER User
		User to remove the API token.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.
	
	.EXAMPLE
		PS C:\> Remove-PfaApiToken -FlashArray 1.1.1.1 -User NEWUSER -Session $MySession
#>
function Remove-PfaApiToken()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $False)][ValidateNotNullOrEmpty()][string] $User,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/admin/$User" + "/apitoken"
	$Return =  Invoke-RestMethod -Method DELETE -Uri $Uri -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Lists current base configuration information for the directory service.

	.DESCRIPTION
		Lists current base configuration information for the directory service.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Get-PfaDirectoryService -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaDirectoryService()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/directoryservice"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Returns information about the group configuration.

	.DESCRIPTION
		Returns information about the group configuration.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Get-PfaDirectoryServiceGroups -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaDirectoryServiceGroups()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/directoryservice?groups=true"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Returns information about the currently configured CA certificate data.

	.DESCRIPTION
		Returns information about the currently configured CA certificate data.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Get-PfaDirectoryServiceCertificate -FlashArray 1.1.1.1 -Session $MySession
#>
function Get-PfaDirectoryServiceCertificate()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$Uri = "$PureStorageURIBase/directoryservice?certificate=true"
	return (Invoke-RestMethod -Method GET -Uri $Uri -WebSession $Session -ContentType "application/json")
}

<#
	.SYNOPSIS
		Tests the current directory service configuration.

	.DESCRIPTION
		Tests the current directory service configuration; verifies that the URIs can be resolved and that Purity can 
		bind and query the tree using the bind user credentials. The call also verifies that it can find all the configured 
		groups to ensure the Common Names and group base are correctly configured.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Test-PfaDirectoryService -FlashArray 1.1.1.1 -Session $MySession
#>
function Test-PfaDirectoryService()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$DirService = $null
	$DirService = @{
		action = "test"	
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/directoryservice"
	$Return = (Invoke-RestMethod -Method PUT -Uri $Uri -Body $DirService -WebSession $Session -ContentType "application/json")
	return $Return.output
}

<#
	.SYNOPSIS
		Enables directory service support.

	.DESCRIPTION
		Enables directory service support.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Enable-PfaDirectoryService -FlashArray 1.1.1.1 -Session $MySession
#>
function Enable-PfaDirectoryService()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$DirServiceEnabled = $null
	$DirServiceEnabled = @{
		enabled = "true"
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/directoryservice"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $DirServiceEnabled -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Disables directory service support.

	.DESCRIPTION
		Disables directory service support.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Disable-PfaDirectoryService -FlashArray 1.1.1.1 -Session $MySession
#>
function Disable-PfaDirectoryService()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$DirServiceEnabled = $null
	$DirServiceEnabled = @{
		enabled = "false"
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/directoryservice"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $DirServiceEnabled -WebSession $Session -ContentType "application/json"
}

<#
	.SYNOPSIS
		Modifies the directory service configuration.

	.DESCRIPTION
		Modifies the directory service configuration.

	.PARAMETER FlashArray
		Pure Storage FlashArray virtual IP address (eg. vir0) or DNS name.

	.PARAMETER LdapUri
		A list of up to 30 URIs of the directory servers. These must be full URIs including the scheme: 
		ldap:// or ldaps://. The domain names should be resolvable by configured DNS servers. If the scheme
		of the URIs is ldaps://, SSL is enabled. SSL is either enabled or disabled globally, so the scheme 
		of all supplied URIs must be the same. They must also all have the same domain. If base DN is not 
		configured and a URI is provided, the base DN will automatically default to the Domain Components
		of the URIs. Standard ports are assumed (389 for ldap, 636 for ldaps). Non-standard ports can be 
		specified in the URI if they are in use.

	.PARAMETER BaseDN
		Sets the base of the Distinguished Name (DN) of the directory service groups. The base should consist 
		of only Domain Components (DCs). The base_dn will populate with a default value when a URI is entered 
		by parsing domain components from the URI. The base DN should specify DC= for each domain component 
		and multiple DCs should be separated by commas.

	.PARAMETER GroupBase
		Specifies where the configured groups are located in the directory tree. This field consists of 
		Organizational Units (OUs) that combine with the base DN attribute and the configured group CNs to 
		complete the full Distinguished Name of the groups. The group base should specify OU= for each OU 
		and multiple OUs should be separated by commas. The order of OUs is important and should get larger 
		in scope from left to right. Each OU should not exceed 64 characters in length.

	.PARAMETER ArrayAdminGroup
		Sets the common Name (CN) of the directory service group containing administrators with full privileges 
		when managing the FlashArray. The name should be just the Common Name of the group without the CN= 
		specifier. Common Names should not exceed 64 characters in length.

	.PARAMETER StorageAdminGroup
		Sets the common Name (CN) of the configured directory service group containing administrators with 
		storage-related privileges on the FlashArray. This name should be just the Common Name of the group 
		without the CN= specifier. Common Names should not exceed 64 characters in length.

	.PARAMETER ReadOnlyGroup
		Sets the common Name (CN) of the configured directory service group containing users with read-only 
		privileges on the FlashArray. This name should be just the Common Name of the group without the CN= 
		specifier. Common Names should not exceed 64 characters in length.

	.PARAMETER BindUser
		Sets the user name that can be used to bind to and query the directory. Often referred to as 
		sAMAccountName or User Logon Name.

	.PARAMETER BindPassword
		Sets the password of the bind_user user name account.

	.PARAMETER Session
		The session that has been established using the Connect-PfaController and Get-PfaAPIToken cmdlets.

	.EXAMPLE
		PS C:\> Update-PfaDirectoryService -FlashArray 1.1.1.1 -LdapUri 'ldap://10.21.8.5' -BaseDN 'DC=csglab,DC=purestorage,DC=com' -GroupBase OU=SAN_Managers -ArrayAdminGroup Pure_Storage_Admins -StorageAdminGroup Pure_Storage_Users -ReadOnlyGroup Pure_Storage_Readers -BindUser USER1 -BindPassword 'pa$$word' -Session $S
#>
function Update-PfaDirectoryService()
{
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $FlashArray,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string[]] $LdapUri,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $BaseDN,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $GroupBase,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $ArrayAdminGroup,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $StorageAdminGroup,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $ReadOnlyGroup,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $BindUser,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][string] $BindPassword,
		[Parameter(Mandatory = $True)][ValidateNotNullOrEmpty()][Microsoft.PowerShell.Commands.WebRequestSession]$Session
	)
	
	$DirServiceConfig = $null
	$DirServiceConfig = @{
		uri = [Object[]]$LdapUri
		base_dn = $BaseDN
		group_base = $GroupBase
		array_admin_group = $ArrayAdminGroup
		storage_admin_group = $StorageAdminGroup
		readonly_group = $ReadOnlyGroup
		bind_user = $BindUser
		bind_password = $BindPassword
	} | ConvertTo-Json
	
	$Uri = "$PureStorageURIBase/directoryservice"
	$Return = Invoke-RestMethod -Method PUT -Uri $Uri -Body $DirServiceConfig -WebSession $Session -ContentType "application/json"
}

#endregion

#region TBD

function Initialize-DiskRescan
{
}

function Get-QuickFixEngineering
{
}

function Test-Configuration
{
}

#endregion

Export-ModuleMember -function Open-PureStorageGitHub
Export-ModuleMember -function Get-WindowsPowerScheme
Export-ModuleMember -function Get-PfaApiVersion
Export-ModuleMember -function Get-PfaApiToken
Export-ModuleMember -function Connect-PfaController
Export-ModuleMember -function Disconnect-PfaController
Export-ModuleMember -function New-PfaShadowCopy
Export-ModuleMember -function Get-PfaShadowCopy
Export-ModuleMember -function Watch-PfaPerformance
Export-ModuleMember -function Get-PfaHistoricalPerformance
Export-ModuleMember -function Get-PfaSpace
Export-ModuleMember -function Get-PfaConfiguration
Export-ModuleMember -Function Get-PfaConnection
Export-ModuleMember -function Get-PfaConsoleLock
Export-ModuleMember -function Get-PfaPhoneHome
Export-ModuleMember -function Get-PfaRemoteAssist
Export-ModuleMember -function New-PfaConnection
Export-ModuleMember -function Remove-PfaConnection
Export-ModuleMember -function Get-PfaArray
Export-ModuleMember -Function Set-PfaBanner
Export-ModuleMember -Function Set-PfaIdleTimeout
Export-ModuleMember -Function Set-PfaName
Export-ModuleMember -Function Set-PfaNtpServer
Export-ModuleMember -Function Set-PfaProxy
Export-ModuleMember -Function Set-PfaRelayHost
Export-ModuleMember -Function Set-PfaScsiTimeout
Export-ModuleMember -Function Set-PfaSenderDomain
Export-ModuleMember -Function Set-PfaSyslogServer
Export-ModuleMember -Function Enable-PfaConsoleLock
Export-ModuleMember -Function Disable-PfaConsoleLock
Export-ModuleMember -Function Enable-PfaPhonehome
Export-ModuleMember -Function Disable-PfaPhonehome
Export-ModuleMember -Function Send-PfaPhonehomeLogs
Export-ModuleMember -Function Connect-PfaRemoteAssist
Export-ModuleMember -Function Disconnect-PfaRemoteAssist
Export-ModuleMember -function Get-PfaVolumes
Export-ModuleMember -function Get-PfaPendingVolumes
Export-ModuleMember -function Get-PfaPendingOnlyVolumes
Export-ModuleMember -function Get-PfaSnapshots
Export-ModuleMember -Function Get-PfaVolumesSpace
Export-ModuleMember -function Get-PfaProtectionGroups
Export-ModuleMember -function Get-PfaProtectionGroupsPending
Export-ModuleMember -function Get-PfaProtectionGroupsPendingOnly
Export-ModuleMember -function Get-PfaProtectionGroupsSchedule
Export-ModuleMember -function Get-PfaProtectionGroupsRetentionPolicy
Export-ModuleMember -function Get-PfaProtectionGroupsTransferStatisics
Export-ModuleMember -Function Get-PfaProtectionGroupsSnapshotSpace
Export-ModuleMember -function Get-PfaProtectionGroupsSpace
Export-ModuleMember -function Get-PfaProtectionGroup
Export-ModuleMember -function Get-PfaProtectionGroupPending
Export-ModuleMember -function Get-PfaProtectionGroupPendingOnly
Export-ModuleMember -function Get-PfaProtectionGroupSchedule
Export-ModuleMember -function Get-PfaProtectionGroupRetentionPolicy
Export-ModuleMember -function Get-PfaProtectionGroupTransferStatisics
Export-ModuleMember -Function Get-PfaProtectionGroupSnapshotSpace
Export-ModuleMember -function Get-PfaProtectionGroupSpace
Export-ModuleMember -function New-PfaProtectionGroupSnapshot
Export-ModuleMember -function New-PfaProtectionGroup
Export-ModuleMember -function Remove-PfaProtectionGroup
Export-ModuleMember -function Eradicate-PfaProtectionGroup
Export-ModuleMember -function Recover-PfaProtectionGroup
Export-ModuleMember -function Rename-PfaProtectionGroup
Export-ModuleMember -function Enable-PfaProtectionGroupReplication
Export-ModuleMember -function Disable-PfaProtectionGroupReplication
Export-ModuleMember -function Enable-PfaProtectionGroupSnapshots
Export-ModuleMember -function Disable-PfaProtectionGroupSnapshots
Export-ModuleMember -function Add-PfaProtectionGroupMembers
Export-ModuleMember -function Remove-PfaProtectionGroupMembers
Export-ModuleMember -function Update-PfaProtectionGroupReplication
Export-ModuleMember -Function Set-PfaProtectionGroupReplicationBlackout
Export-ModuleMember -Function Watch-PfaVolumePerformance
Export-ModuleMember -Function Get-PfaVolumeSnapshots
Export-ModuleMember -Function Get-PfaVolume
Export-ModuleMember -Function Get-PfaHistoricalVolumePerformance
Export-ModuleMember -Function Get-PfaVolumeSpace
Export-ModuleMember -Function Get-PfaVolumeSharedConnections
Export-ModuleMember -Function Get-PfaVolumePrivateConnections
Export-ModuleMember -Function Get-PfaVolumeDiff
Export-ModuleMember -function New-PfaVolume
Export-ModuleMember -function Refresh-PfaVolume
Export-ModuleMember -function New-PfaSnapshot
Export-ModuleMember -function Remove-PfaVolume
Export-ModuleMember -function Remove-PfaSnapshot
Export-ModuleMember -Function Eradicate-PfaVolume
Export-ModuleMember -function Rename-PfaVolume
Export-ModuleMember -function Resize-PfaVolume
Export-ModuleMember -function Recover-PfaVolume
Export-ModuleMember -function Recover-PfaSnapshot
Export-ModuleMember -function Get-PfaHosts
Export-ModuleMember -function Get-PfaHost
Export-ModuleMember -function New-PfaHost
Export-ModuleMember -function Connect-PfaHost
Export-ModuleMember -function Remove-PfaHost
Export-ModuleMember -Function Connect-PfaVolume 
Export-ModuleMember -function Disconnect-PfaVolume
Export-ModuleMember -function Get-PfaHostGroups
Export-ModuleMember -function Get-PfaHostGroupVolumes
Export-ModuleMember -function New-PfaHostGroup
Export-ModuleMember -function Connect-PfaHostGroup
Export-ModuleMember -Function Add-PfaHostGroupHosts
Export-ModuleMember -Function Remove-PfaHostGroupHosts
Export-ModuleMember -Function Rename-PfaHostGroup
Export-ModuleMember -Function Update-PfaHostGroupHosts
Export-ModuleMember -function Remove-PfaHostGroup
Export-ModuleMember -function Disconnect-PfaHostGroupVolume
Export-ModuleMember -Function New-PfaProtectionGroupSnapshot
Export-ModuleMember -function Get-PfaPorts
Export-ModuleMember -function Get-PfaInitiators
Export-ModuleMember -function Enable-PfaPorts
Export-ModuleMember -function Disable-PfaPorts
Export-ModuleMember -function Get-PfaAlerts
Export-ModuleMember -function Get-PfaAlertRecipient
Export-ModuleMember -function Test-PfaAlertRecipient
Export-ModuleMember -function Enable-PfaAlertRecipient
Export-ModuleMember -function Disable-PfaAlertRecipient
Export-ModuleMember -function Remove-PfaAlertRecipient
Export-ModuleMember -function New-PfaAlertRecipient
Export-ModuleMember -function Get-PfaMessages
Export-ModuleMember -function Hide-PfaMessage
Export-ModuleMember -function Show-PfaMessage
Export-ModuleMember -function Get-PfaSnmp
Export-ModuleMember -function Get-PfaSnmpManager
Export-ModuleMember -function New-PfaSnmpv3Manager
Export-ModuleMember -function New-PfaSnmpv2cManager
Export-ModuleMember -function Update-PfaSnmpManager
Export-ModuleMember -function Remove-PfaSnmpManager
Export-ModuleMember -function Test-PfaSnmpManager
Export-ModuleMember -function Get-PfaSslCert
Export-ModuleMember -function Export-PfaSslCert 
Export-ModuleMember -function Get-PfaDns
Export-ModuleMember -function Set-PfaDns
Export-ModuleMember -function Get-PfaNetwork
Export-ModuleMember -function Get-PfaNetworkInterface
Export-ModuleMember -function Get-PfaHardware
Export-ModuleMember -function Get-PfaHardwareComponent
Export-ModuleMember -function Show-PfaHardwareLed
Export-ModuleMember -function Get-PfaDrives
Export-ModuleMember -function Get-PfaDrive
Export-ModuleMember -function Get-PfaUsers
Export-ModuleMember -function Get-PfaUser
Export-ModuleMember -function New-PfaApiToken
Export-ModuleMember -function Clear-PfaPermissionCache
Export-ModuleMember -function Set-PfaUserPassword
Export-ModuleMember -function Set-PfaUserPublicKey
Export-ModuleMember -function Remove-PfaApiToken
Export-ModuleMember -function Get-PfaDirectoryService
Export-ModuleMember -function Get-PfaDirectoryServiceGroups
Export-ModuleMember -function Get-PfaDirectoryServiceCertificate
Export-ModuleMember -function Test-PfaDirectoryService
Export-ModuleMember -function Disable-PfaDirectoryService
Export-ModuleMember -function Enable-PfaDirectoryService
Export-ModuleMember -function Update-PfaDirectoryService
Export-ModuleMember -function Get-HostBusAdapter
#Export-ModuleMember -function Initialize-DiskRescan
#Export-ModuleMember -function Get-QuickFixEngineering
#Export-ModuleMember -function Test-Configuration