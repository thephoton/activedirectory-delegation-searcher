$filter = "(|(objectClass=domain)(objectClass=organizationalUnit)(objectClass=group)(sAMAccountType=805306368)(objectCategory=Computer))" #Search common delegation targets
#$filter = "(|(objectClass=organizationalUnit)(objectClass=group))" #Search just OUs and Groups
#More filters can be found here: http://www.ldapexplorer.com/en/manual/109050000-famous-filters.htm

#$bSearch = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DOMAINCONTROLLER/LDAP"), "USERNAME", "PASSWORD") #connect to DOMAINCONTROLLER using LDAP path, USERNAME and PASSWORD
$bSearch = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DOMAINCONTROLLER/LDAP") #connect to DOMAINCONTROLLER using LDAP path

$dSearch = New-Object System.DirectoryServices.DirectorySearcher($bSearch)
$dSearch.SearchRoot = $bSearch
$dSearch.PageSize = 1000
$dSearch.Filter = $filter #comment out to look at all object types
$dSearch.SearchScope = "Subtree"

$extPerms = ` #List of extended permissions available here: https://technet.microsoft.com/en-us/library/ff405676.aspx
        '00299570-246d-11d0-a768-00aa006e0529', #reset password
        'ab721a54-1e2f-11d0-9819-00aa0040529b', #send as
        '0'

$results = @()

foreach ($objResult in $dSearch.FindAll())
{
    $obj = $objResult.GetDirectoryEntry()

    Write-Host "Searching... " $obj.distinguishedName

    $permissions = $obj.PsBase.ObjectSecurity.GetAccessRules($true,$false,[Security.Principal.NTAccount])
    
    $results += $permissions | Where-Object { `
            $_.AccessControlType -eq 'Allow' -and ($_.ObjectType -in $extPerms) -and $_.IdentityReference -notin ('NT AUTHORITY\SELF', 'NT AUTHORITY\SYSTEM', 'S-1-5-32-548') `
            } | Select-Object `
        @{n='Object'; e={$obj.distinguishedName}}, 
        @{n='Account'; e={$_.IdentityReference}},
        @{n='Permission'; e={$_.ActiveDirectoryRights}}

}

$results | Out-GridView