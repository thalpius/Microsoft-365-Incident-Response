<#
 
.SYNOPSIS
  This script can be used for an incident reponse within Microsoft 365.
 
.DESCRIPTION
 
  This script will extract security related information within the tenant and saves the information
  in JSON format. The JSON output can be used for filtering using your favorite programming language.

  For this script you will need an app registration using the Microsoft Graph with the following application permissions:
    Directory.Read.All
    Directory.ReadWrite.All
    IdentityRiskyUser.Read.All
    Policy.Read.All
    SecurityEvents.Read.All
    DelegatedPermissionGrant.ReadWrite.All
    AuditLog.Read.All
    Mail.Read
    MailboxSettings.Read

  For more information about the Microsoft Graph see https://docs.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta
 
.PARAMETER
 
  Parameters depends per function.
 
.INPUTS
 
  None
 
.OUTPUTS
 
  Output will be saved to a JSON file using the RR-OutputArray function.
 
.NOTES
 
  Version:        0.2
  Author:         R. Roethof
  Creation Date:  9/20/2020
  Website:        https://thalpius.com
  Purpose/Change: Initial script development
  
 
#>
 
#-------------------------------------------[Declarations]-----------------------------------------

$array = @{ }

#--------------------------------------------[Functions]-------------------------------------------

function RR-GetAccessToken {
    Param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the application ID")]
        [ValidateNotNullOrEmpty()]
        [string]$appId,
        [parameter(Mandatory = $true, HelpMessage = "Specify the application secret")]
        [ValidateNotNullOrEmpty()]
        [string]$appSecret,
        [parameter(Mandatory = $true, HelpMessage = "Specify the tenant name")]
        [ValidateNotNullOrEmpty()]
        [string]$tenantName
    )
    begin {
        Write-Host "Getting Access Token..."
    }
    process {
        try {
            Add-Type -AssemblyName System.Web
            $body = @{
                client_id     = $appId
                client_secret = $appSecret
                scope         = "https://graph.microsoft.com/.default"
                grant_type    = 'client_credentials'
            }
            $postSplat = @{
                contentType = 'application/x-www-form-urlencoded'
                method      = 'POST'
                body        = $body
                uri         = "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token"
            }
            $request = Invoke-RestMethod @postSplat
            $script:header = @{
                authorization = "$($request.token_type) $($request.access_token)"
            }
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting Access Token completed successfully..."
        }
    }
}
function RR-GetSkus {
    param()
    begin {
        Write-Host "Getting Subscribed Skus..."
    }
    process {
        try {
            $queryResults = @()
            $Uri = "https://graph.microsoft.com/beta/subscribedSkus"
            do {
                $skus = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $skus.value
                $uri = $skus.'@odata.nextlink'
            } until (!($uri))
            $array.Add("skus", $queryResults)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting Subscribed Skus completed successfully..."
        }
    }
}
function RR-GetAcceptedDomains {
    param()
    begin {
        Write-Host "Getting Accepted Domains..."
    }
    process {
        try {
            $queryResults = @()
            $Uri = "https://graph.microsoft.com/beta/domains"
            do {
                $domains = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $domains.value
                $uri = $domains.'@odata.nextlink'
            } until (!($uri))
            $array.Add("Accepted Domains", $queryResults)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting Accepted Domains completed successfully..."
        }
    }
}
function RR-GetAcceptedDomainsTxtRecords {
    param()
    begin {
        Write-Host "Getting Accepted Domains..."
    }
    process {
        try {
            $queryResults = @()
            $result = @()
            $Uri = "https://graph.microsoft.com/beta/domains"
            do {
                $domains = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $domains.value
                $uri = $domains.'@odata.nextlink'
            } until (!($uri))
            $acceptedDomains = $queryResults.id
            foreach ($domain in $acceptedDomains) {
                $resultDomain = Resolve-DnsName -Name $domain -Type txt
                $result += $resultDomain
            }
            $array.Add("Domain TXT Records", $result)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting Accepted Domains completed successfully..."
        }
    }
}
function RR-GetInboxRules {
    param(
        [parameter(Mandatory = $false, HelpMessage = "Enter a username")]
        [ValidateNotNullOrEmpty()]
        [string]$userPrincipalName
    )
    begin {
        Write-Host "Getting all inbox rules..."
    }
    process {
        try {
            $queryResults = @()
            $rule = @()
            if ($userPrincipalName) {
                $Uri = "https://graph.microsoft.com/beta/users?&`$filter=userPrincipalName eq '$userPrincipalName'"
                $allInboxRules = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $allInboxRules.value
            }
            else {
                $Uri = 'https://graph.microsoft.com/beta/users?$select=userPrincipalName'
                do {
                    $allInboxRules = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                    $queryResults += $allInboxRules.value
                    $uri = $allInboxRules.'@odata.nextlink'
                } until (!($uri))
            }
            foreach ($user in $queryResults) {
                try {
                    $url = "https://graph.microsoft.com/beta/users/$($user.userPrincipalName)/mailFolders/inbox/messagerules"
                    $inboxRules = Invoke-RestMethod -Uri $url -Headers $Header -Method Get -ContentType "application/json"
                    if ($inboxRules.Value -ne "") {
                        $rule += $user.userPrincipalName
                        $rule += $inboxRules.Value
                    }
                }
                catch {
                    $incorrectRequest++
                }
            }
            $array.Add("Inbox Rules", $rule)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting all inbox rules completed successfully..."
        }
    }
}
function RR-GetSignins {
    param(
        [parameter(Mandatory = $false, HelpMessage = "Enter a username")]
        [ValidateNotNullOrEmpty()]
        [string]$userPrincipalName
    )
    begin {
        Write-Host "Getting all sign-ins..."
    }
    process {
        try {
            $queryResults = @()
            if ($userPrincipalName) {
                $Uri = "https://graph.microsoft.com/beta/auditLogs/signIns?&`$filter=userPrincipalName eq '$userPrincipalName'"
            }
            else {
                $uri = 'https://graph.microsoft.com/beta/auditLogs/signIns'
            }
            do {
                $allSignins = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $allSignins.value
                $uri = $allSignins.'@odata.nextlink'
            } until (!($uri))
            $array.Add("Sign-ins", $queryResults)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting all sign-ins completed successfully..."
        }
    }
}
function RR-GetAuditLogs {
    param(
        [parameter(Mandatory = $false, HelpMessage = "Enter a username")]
        [ValidateNotNullOrEmpty()]
        [string]$userPrincipalName
    )
    begin {
        Write-Host "Getting all audit logs..."
    }
    process {
        try {
            $queryResults = @()
            if ($userPrincipalName) {
                $Uri = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?&`$filter=initiatedBy/user/userPrincipalName eq '$userPrincipalName'"
            }
            else {
                $Uri = 'https://graph.microsoft.com/beta/auditLogs/directoryAudits'
            }
            do {
                $allAuditLogs = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $allAuditLogs.value
                $uri = $allAuditLogs.'@odata.nextlink'
            } until (!($uri))
            $array.Add("Audit Logs", $queryResults)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting all audit logs completed successfully..."
        }
    }
}
function RR-GetEmailBySubject {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify a subject to search for")]
        [ValidateNotNullOrEmpty()]
        [string]$subject
    )
    begin {
        Write-Host "Getting all e-mail with a subject..."
    }
    process {
        try {
            $queryResults = @()
            $allMessages = @()
            $Uri = 'https://graph.microsoft.com/beta/users'
            do {
                $companyUsers = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $companyUsers.value
                $uri = $companyUsers.'@odata.nextlink'
            } until (!($uri))
            foreach ($user in $queryResults) {
                $uri = "https://graph.microsoft.com/beta/users/$($user.id)/messages?$select=subject"
                do {
                    $companyUser = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                    $allMessages += $companyUser.value
                    $uri = $companyUser.'@odata.nextlink'
                } until (!($uri))
                if ($allMessages.Subject -eq $subject) {
                    $user.userPrincipalName
                }
                $allMessages = $null
            }
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting all e-mail with a subject completed successfully..."
        }
    }
}
function RR-GetEmailByBody {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Specify the keyword in the body to search for")]
        [ValidateNotNullOrEmpty()]
        [string]$bodyKeyword
    )
    Begin {
        Write-Host "Getting all e-mail with a body text..."
    }
    process {
        try {
            $queryResults = @()
            $allMessages = @()
            $Uri = 'https://graph.microsoft.com/beta/users'
            do {
                $companyUsers = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $companyUsers.value
                $uri = $companyUsers.'@odata.nextlink'
            } until (!($uri))
            foreach ($user in $queryResults) {
                $uri = "https://graph.microsoft.com/beta/users/$($user.id)/messages"
                do {
                    try {
                        $companyUser = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                    }
                    catch {
                        $incorrectRequest++
                    }
                    $allMessages += $companyUser.value
                    $uri = $companyUser.'@odata.nextlink'
                } until (!($uri)) 
                if ($allMessages.Body -match $bodyKeyword) {
                    $user.userPrincipalName
                }
                $allMessages = $null
            }
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting all e-mail with a body text completed successfully..."
        }
    }
}
function RR-GetAttachments {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Enter a username")]
        [ValidateNotNullOrEmpty()]
        [string]$userPrincipalName,
        [parameter(Mandatory = $false, HelpMessage = "Enter an extension")]
        [ValidateNotNullOrEmpty()]
        [string]$extension,
        [parameter(Mandatory = $false, HelpMessage = "Enter an attachment ID")]
        [ValidateNotNullOrEmpty()]
        [string]$attachmentId
    )
    begin {
        Write-Host "Getting all attachments..."
    }
    process {
        try {
            $allAttachments = @()
            $uri = "https://graph.microsoft.com/beta/users/$($userPrincipalName)/messages"
            do {
                $companyUser = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $allMessages += $companyUser.value
                $uri = $companyUser.'@odata.nextlink'
            } until (!($uri))
            foreach ($message in $allMessages) {
                $uri = "https://graph.microsoft.com/beta/users/$($userPrincipalName)/messages/$($message.id)/attachments"
                $attachment = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                if ($attachmentId) {
                    if ($attachment.value.id -eq $attachmentId) {
                        $allAttachments += $attachment.value
                    }
                }
                else {
                    if ($null -ne $attachment.value.name) {
                        if ($extension) {
                            if ($attachment.value.name -match "$extension$") {
                                $allAttachments += ($attachment.value | Select-Object name, id)
                            }
                        }
                        else {
                            $allAttachments += ($attachment.value | Select-Object name, id)
                        }
                    }
                }
            }
            $array.Add("Attachments for $userPrincipalName", $allAttachments)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting all attachments completed successfully..."
        }
    }
}
function RR-GetAllAppRegistrations {
    param(
    )
    begin {
        Write-Host "Getting all app registrations..."
    }
    process {
        try {
            $queryResults = @()
            $appRegistrationAll = @()
            $Uri = "https://graph.microsoft.com/beta/applications"
            do {
                $appRegistrations = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $queryResults += $appRegistrations.value
                $uri = $appRegistrations.'@odata.nextlink'
            } until (!($uri))
            foreach ($appReg in $queryResults) {
                $uri = "https://graph.microsoft.com/beta/applications/$($appReg.id)/owners"
                $appRegistration = Invoke-RestMethod -Uri $Uri -Headers $Header -Method Get -ContentType "application/json"
                $appRegistrationAll += $appRegistration.value.userPrincipalName
                $appRegistrationAll += $appReg
            }
            $array.Add("App registrations", $appRegistrationAll)
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            Write-host "Getting all app registrations completed successfully..."
        }
    }
}
function RR-OutputArray {
    param(
        [parameter(Mandatory = $true, HelpMessage = "Enter a location for the output")]
        [ValidateNotNullOrEmpty()]
        [string]$outputLocation
    )
    begin {
        Write-Host "Start output array..."
    }
    process {
        try {
            $array | ConvertTo-Json -Depth 100 | Out-File -FilePath $outputLocation
        }
        catch {
            Write-Host $_.Exception
            exit
        }
    }
    end {
        if ($?) {
            $array.Clear()
            Write-host "Start output array completed successfully..."
        }
    }
}
