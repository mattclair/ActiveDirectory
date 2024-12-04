<#
This script will pull unique KDC event 39 entries from the event log. 
This log will be used to compile the correct AltSecuritiesIdentities attribute to set for each user. 
By default this script will only log accounts that need to be updated. The log will output to the users desktop ~\desktop\StrongBinding.json
Configure line 9 if you want the script to write the AltSecuritiesIdentities attribute to the users account
#>

$Global:days = -10 #how many days back to search
[bool]$Global:writeAttribute = 0 #set 1 to fix, 0 to just log

function Reverse-CertificateSerialNumber{
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $CertSerialNumber)

     #Split the string into two characters to represent the byte encoding
     $splitresults = $CertSerialNumber  -split '(..)' -ne ''

     #Take the byte split serial number and reverse the digits to get the correct cert formatting
     $splitresults[-1..-$splitresults.Length] -join ''
}


function Reverse-CertificateIssuer{
    Param(
        [Parameter(Position=0,mandatory=$true)]
        [string] $CertIssuer)

    $paths = [Regex]::Replace($CertIssuer, ',\s*(CN=|OU=|O=|DC=|C=)', '!$1') -split "!"
    $issuer = ""
    # Reverse the path and save as $issuer
	    for ($i = $paths.count -1; $i -ge 0; $i--) {
		    $issuer += $paths[$i]
		    if ($i -ne 0) {
			    $issuer += ","
		    }
	    }
    return $issuer
}

Function getUser ($message){
    $match = select-string "User: (.*)" -InputObject $message
    $match = $match.Matches.groups[1].value
    return $match
}

Function getCertSN ($message){
    $match = select-string "Certificate Serial Number: (.*)" -InputObject $message
    $match = $match.Matches.groups[1].value
    return $match
}

Function getIssuer ($message){
    $match = select-string "Certificate Issuer: (.*)" -InputObject $message
    $match = $match.Matches.groups[1].value
    $match = Reverse-CertificateIssuer $match
    return "C=US,O=U.S. Government,OU=DoD,OU=PKI,CN=$match"
}

function ClearWhiteSpace ($Text) {
    "$($Text -replace "(`t|`n|`r)"," " -replace "\s+"," ")".Trim()
}

#check System eventlog for event 39
$eventLogData = Get-EventLog -LogName System -Source KDC -After (Get-Date).AddDays($Global:days)| Where-Object {$_.EventID -eq 39} | Select-Object -Property Source, EventID, InstanceId, Message

#write-host $actionNeeded[0].message

#pull required data from logs and store in custom an array
$wrapper = @()

forEach($eventLog in $eventLogData) {
    $user = getUser $eventLog
    $certSN = getCertSN $eventLog
    $formatedCertSN = Reverse-CertificateSerialNumber $certSN
    $issuer = getIssuer $eventLog
    $altsecurityidentities = "X509:<I>$issuer<SR>$formatedCertSN"
    #store individual record as psCustomObject
    $item = [PSCustomObject]@{
        User = ClearWhiteSpace $user
        Cert_SN = ClearWhiteSpace $certSN
        Cert_SN_Formatted = ClearWhiteSpace $formatedCertSN
        Issuer = ClearWhiteSpace $issuer
        AltSecuritiesIdentities = ClearWhiteSpace $altsecurityidentities
    }
    #write each individual record into the wrapper array
    $wrapper += $item
}


#Pull out only unique records from the wrapper, sort them, and save in a json file on the desktop
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$jsonList = $wrapper | 
    Group-Object 'User', 'Cert_SN', 'Cert_SN_Formatted', 'Issuer', 'AltSecuritiesIdentities' | 
    %{ $_.Group | Select 'User', 'Cert_SN', 'Cert_SN_Formatted', 'Issuer', 'AltSecuritiesIdentities' -First 1} | 
    Sort 'User', 'Cert_SN', 'Cert_SN_Formatted', 'Issuer', 'AltSecuritiesIdentities'
$jsonList | ConvertTo-Json | % { [System.Text.RegularExpressions.Regex]::Unescape($_) } | Set-Content -Path "$DesktopPath\StrongBinding.json"
forEach ($adUser in $jsonList){
    #write-host $adUser.User
    #write-host $adUser.AltSecuritiesIdentities
    try {
       if($Global:writeAttribute){
         #write-host "write attribute is enabled"
         $usr = $adUser.User.Trim()
         $cer = $aduser.Cert_SN_Formatted.Trim()
         $issu = $adUser.Issuer.Trim()
         Set-ADUser -Identity $usr -Add @{'altSecurityIdentities'="X509:<I>$issu<SR>$cer"}
       }       
    }
    catch {
       "An error occured configuing $usr with altSecurityIdentities"
    }   
}
