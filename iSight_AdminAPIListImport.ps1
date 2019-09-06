Param(
	$publicKey,
	$privateKey,
	$LRAPIToken,
	
	# List prefix & postfix
	# Example: 
	#	listFilePrefix = "iSight"
	# 	listFilePostfix = "Threat-All"
	# 	File name -> "iSight-ip-Threat-All.txt"
	$listPrefix = "iSight : ",
	$listPostfix = "Threat : All",

	# Log File (filename or full path)
	$logFile = "iSight_logs.txt",

	# Indicator Types
	# Supported: See https://docs.fireeye.com/docs/docs_en/IS/sw/Current/API/index.html#/iocs Section "Valid values for indicators"
	$indicatorTypes = ("ip", "fileName", "url"),

	# Number of days of iSight data to get each call
	$numberOfDays = 7
)

# Mask errors
$ErrorActionPreference= 'silentlycontinue' 

function get-iSightQuery
{
	param(
		[string] $publicKey,
		[string] $privateKey,
		[int] $numberOfDays = 7,
		[string[]] $indicatorTypes
	)

	# RFC 822 Date format
	$date = [DateTime]::UtcNow.ToString('r')

	# Go back in time $numberOfDays days
	$start = [Math]::Floor([decimal](Get-Date(Get-Date).AddDays(-$numberOfDays).ToUniversalTime()-uformat "%s"))
	# End with the most recent data
	$end = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
	
	# iSight API URI
	$uri = "https://api.isightpartners.com"

	# iSight endpoint
	# IOCs between our start & end dates with the specified types
	$endpoint = "/view/iocs?startDate=$start&endDate=$end&indicatorTypes=" + ($indicatorTypes -join ",")

	# Version of iSight API to use
	$acceptVersion = "2.5"
	# Content to accept from iSight API (we expect json response)
	$accept = "application/json"

	# iSight Auth
	# Take the endpoint you're requesting, API version, content type, and RFC822 date
	$queryToHash = $endpoint + $acceptVersion + $accept + $date

	# Hash that string using SHA256; the key is the iSight "Secret" API key
	$StringBuilder = New-Object System.Text.StringBuilder 64
	$hmacsha = New-Object System.Security.Cryptography.HMACSHA256
	$hmacsha.key = [Text.Encoding]::ASCII.GetBytes($privateKey)
	$signature = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($queryToHash)) | % { [void] $StringBuilder.Append($_.ToString("x2")) }
	$hash = $StringBuilder.ToString()

	$headers = @{
		"Accept" = $accept;
		"Accept-Version" = $acceptVersion;
		"X-Auth" = $publicKey;
		"X-Auth-Hash" = $hash;
		"X-App-Name" = "LogRhythm-TIS-PS";
		"Date" = $date
	}

	[hashtable] $query = @{} 
	$query.Uri = $uri
	$query.Endpoint = $endpoint
	$query.Headers = $headers

	return $query
}

function get-iSightIocs
{
	param
	(
		[hashtable] $headers,
		[string] $uri,
		[string] $endpoint,
		[string[]] $indicatorTypes
	)

	# RFC 822 Date format
	$date = [DateTime]::UtcNow.ToString('r')

	try 
	{
		# Ignore cert errors
		add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
return true;
}
}
"@
		[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	}
	catch 
	{
		write-host $error
	}

	try {
		# iSight is returning bad headers. Ugh.

		$netAssembly = [Reflection.Assembly]::GetAssembly([System.Net.Configuration.SettingsSection])

		if($netAssembly)
		{		
			$bindingFlags = [Reflection.BindingFlags] "Static,GetProperty,NonPublic"
			$settingsType = $netAssembly.GetType("System.Net.Configuration.SettingsSectionInternal")

			$instance = $settingsType.InvokeMember("Section", $bindingFlags, $null, $null, @())

			if($instance)
			{
				$bindingFlags = "NonPublic","Instance"
				$useUnsafeHeaderParsingField = $settingsType.GetField("useUnsafeHeaderParsing", $bindingFlags)

				if($useUnsafeHeaderParsingField)
				{
					$useUnsafeHeaderParsingField.SetValue($instance, $true)
				}
			}
		}
	}
	catch 
	{
		write-host $error
	}
	try 
	{
		# Call iSight's API
		$resp = Invoke-RestMethod -Method GET -Uri ($uri + $endpoint) -Header $headers

		write-host $resp

		# Convert response to JSON
		$json = ($resp | ConvertTo-Json) | ConvertFrom-Json

		# Output of indicators
		# E.g. $indicators.ip = ["127.0.0.1", "127.0.0.2"]
		$indicators = @{}

		# Initialize each indicator type
		foreach ($type in $indicatorTypes)
		{
			$indicators[$type] = @()
		}

		# Look at every report iSight provides
		foreach ($report in $json.message) 
		{
			# Look at each indicator we care about
			foreach ($type in $indicatorTypes)
			{
				# If it's in the report, add it to the list
				if (($report.$type -ne $null) -and ($report.$type -ne "UNAVAILABLE")) {
					$indicators[$type] += $report.$type
				}
			}
		}

		return $indicators
	}
	catch {	
		# If there's an error along the way, log it 
		($date + " Error getting results from iSight: " + $error[0]) | out-file $logFile -append
		write-host ("Error getting results from iSight: " + $error[0])
	}

	# If we error out, return null
	return $null
}

function update-iSightIocs
{
	param
	(
		[hashtable] $indicators,
		[hashtable] $listImportConfig,
		[string[]] $indicatorTypes
	)

	# RFC 822 Date format
	$date = [DateTime]::UtcNow.ToString('r')

	try 
	{
		$outputStrings = @()
		# Output each indicator to a list-import file
		foreach ($type in $indicatorTypes)
		{
			# Remove Duplicates
			$indicators[$type] = $indicators[$type] | select -uniq
			$outputStrings += ([string] $indicators[$type].length) + " " + $type
			$indicators[$type] | out-file ($listImportConfig.Folder + "/" + $listImportConfig.Prefix + "-" + $type + "-" + $listImportConfig.Postfix + ".txt")
		}

		$output = "Successfully downloaded iSight feeds (" + ($outputStrings -join ", ") + ")"
		($date + " " + $output) | out-file $logFile -append
		write-host $output
	}
	catch 
	{	
		# If there's an error along the way, log it 
		($date + " Error writing results to file: " + $error[0]) | out-file $logFile -append
		write-host ("Error writing results to file: " + $eror[0])	
	}
}

function Create-ListJSON
{
	param(
		[ValidateSet("Application","Classification","CommonEvent","Host","Location","MsgSource","MsgSourceType","MPERule","Network","User","GeneralValue","Entity","RootEntity","IP" "IPRange","Identity")]
		[string]$listType,
		[ValidateSet()]
		[string[]]$useContext
	)
	$list = @()
	$list += [pscustomobject]{
		{
    "name" = "<string>"
    "listType" = $listType
    "autoImportOption": {
        "enabled": "<boolean>",
        "usePatterns": "<boolean>",
        "replaceExisting": "<boolean>"
    },
    "readAccess": "<string>",
    "writeAccess": "<string>",
    "entityName": "<string>",
    "restrictedRead": "<boolean>",
    "needToNotify": "<boolean>",
    "doesExpire": "<boolean>",
    "status": "<string>",
    "shortDescription": "<string>",
    "longDescription": "<string>",
    "useContext": [
        "<string>",
        "<string>"
    ],
    "importFileName": "<string>",
    "id": "<integer>",
    "guid": "<string>",
    "dateCreated": "<dateTime>",
    "dateUpdated": "<dateTime>",
    "revisitDate": "<dateTime>",
    "entryCount": "<integer>",
    "timeToLiveSeconds": "<integer>",
    "owner": "<integer>"
}
	}
}

$listImportConfig = @{"Folder"=$listImportFolder; "Prefix"=$listFilePrefix; "Postfix"=$listFilePostfix}

$query = get-iSightQuery -publicKey $publicKey -privateKey $privateKey -numberOfDays $numberOfDays -indicatorTypes $indicatorTypes

$indicators = get-iSightIocs -headers $query.Headers -uri $query.Uri -endpoint $query.Endpoint -indicatorTypes $indicatorTypes

if ($indicators -ne $null)
{
	write-iSightIocs -indicators $indicators -listImportConfig $listImportConfig -indicatorTypes $indicatorTypes
}