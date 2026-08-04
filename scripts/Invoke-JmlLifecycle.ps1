#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    JML (Joiner / Mover / Leaver) identity lifecycle automation for hybrid
    Active Directory and Microsoft Entra ID.

.DESCRIPTION
    Provisions, modifies, and deprovisions user accounts across the identity
    lifecycle. On-premises actions run against Active Directory; cloud actions
    run against Microsoft Entra ID via Microsoft Graph using app-only
    authentication.

    All actions are written to a JSON-lines audit log.

    Joiner  Creates a user, generates a random password with change-at-logon,
            places the account in the configured OU, sets the manager, and
            adds role-based group memberships.

    Mover   Updates department, title, and manager, grants new-role groups,
            and removes old-role groups to prevent privilege creep.

    Leaver  Disables the account, resets the password to a random value,
            strips group memberships, timestamps the description, moves the
            object to a disabled-users OU, then revokes cloud sign-in
            sessions and disables the cloud object.

.NOTES
    Requires the Microsoft.Graph module and an Entra ID app registration with
    admin-consented application permissions: User.ReadWrite.All and
    User.RevokeSessions.All.

    Store the client ID and secret before first run:

        $cred = Get-Credential -UserName "<client-id>"
        $cred | Export-Clixml -Path C:\secure\jml-graph.xml

    Export-Clixml encrypts with DPAPI, scoped to the creating user and
    machine. No credential is stored in this script.

.EXAMPLE
    .\Invoke-JmlLifecycle.ps1 -Action Joiner -FirstName Jane -LastName Smith `
        -Department IT -Title "Support Analyst" -Groups "IT-Staff","VPN-Users"

.EXAMPLE
    .\Invoke-JmlLifecycle.ps1 -Action Mover -SamAccountName jane.smith `
        -NewDepartment Finance -NewTitle "Financial Analyst" `
        -AddGroups "Finance-Staff" -RemoveGroups "IT-Staff"

.EXAMPLE
    .\Invoke-JmlLifecycle.ps1 -Action Leaver -SamAccountName jane.smith -WhatIf
#>

# SupportsShouldProcess gives every action -WhatIf and -Confirm. Nothing that
# modifies the directory runs outside a ShouldProcess block, so a dry run is
# genuinely read-only.
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Joiner', 'Mover', 'Leaver')]
    [string]$Action,

    # Joiner identity. Mover and Leaver locate the user by SamAccountName.
    [string]$FirstName,
    [string]$LastName,
    [string]$SamAccountName,

    # Joiner attributes
    [string]$Department,
    [string]$Title,
    [string]$Manager,                 # SamAccountName of the manager
    [string[]]$Groups,                # Role-based groups granted on join

    # Mover attributes
    [string]$NewDepartment,
    [string]$NewTitle,
    [string]$NewManager,
    [string[]]$AddGroups,
    [string[]]$RemoveGroups,

    # Run the on-premises half only. Useful when the cloud is unreachable.
    [switch]$SkipGraph
)

# ---------------------------------------------------------------------------
# Environment-specific values live here rather than being scattered through
# the script. Moving this to a new domain means editing one block.
# ---------------------------------------------------------------------------
$Config = @{
    Domain          = 'lab.local'
    UpnSuffix       = 'lab.local'
    JoinerOU        = 'OU=LabUsers,DC=lab,DC=local'
    DisabledOU      = 'OU=Disabled Users,DC=lab,DC=local'
    LogPath         = "$PSScriptRoot\jml-audit.log"   # log lands beside the script
    PasswordLength  = 16

    # Graph / Entra ID
    TenantId        = '1bb5053b-3fdd-4532-a2d7-dc59ce7d1ed4'
    GraphCredPath   = 'C:\secure\jml-graph.xml'
}


# =========================== Audit logging ================================

function Write-JmlLog {
    <#
        Appends one self-contained JSON object per line (JSONL). A SIEM can
        parse this directly with no custom regex, unlike free-form text.
    #>
    param(
        [string]$Action,
        [string]$Target,
        [ValidateSet('Info','Success','Failure')]
        [string]$Status,
        [string]$Detail
    )

    # [ordered] preserves key sequence. A plain hashtable would emit fields in
    # arbitrary order, making the log unreadable to a human scanning it.
    #
    # timestamp and runBy are generated here rather than accepted as
    # parameters. An audit log should not let its caller claim a different
    # time or a different operator.
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString('o')
        action    = $Action
        target    = $Target
        status    = $Status
        detail    = $Detail
        runBy     = $env:USERNAME
    }

    $entry | ConvertTo-Json -Compress | Add-Content -Path $Config.LogPath
}


# ============================== Helpers ===================================

function Resolve-SamAccountName {
    <#
        Enforces the first.last naming convention. Deriving this rather than
        accepting it as input is what keeps naming consistent regardless of
        who runs the script.
    #>
    param(
        [Parameter(Mandatory)][string]$First,
        [Parameter(Mandatory)][string]$Last
    )

    return ("{0}.{1}" -f $First, $Last).ToLower() -replace '\s',''
}


function New-RandomPassword {
    param([int]$Length = 16)

    # Ambiguous characters (0/O, 1/l/I) are excluded so a password read aloud
    # or typed from a screen is less error-prone.
    $upper   = 'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = 'abcdefghijkmnpqrstuvwxyz'
    $digits  = '23456789'
    $special = '!@#$%^&*-_='
    $all     = $upper + $lower + $digits + $special

    # Seed one character from each class so AD complexity requirements always
    # pass rather than relying on chance.
    $pwChars = @(
        $upper[(Get-Random -Maximum $upper.Length)]
        $lower[(Get-Random -Maximum $lower.Length)]
        $digits[(Get-Random -Maximum $digits.Length)]
        $special[(Get-Random -Maximum $special.Length)]
    )

    for ($i = $pwChars.Count; $i -lt $Length; $i++) {
        $pwChars += $all[(Get-Random -Maximum $all.Length)]
    }

    # Shuffle so the four seeded classes are not always in positions 0-3,
    # which would otherwise be a predictable pattern.
    -join ($pwChars | Sort-Object { Get-Random })
}


# ============================ Graph / Entra ID =============================

function Connect-JmlGraph {
    <#
        App-only authentication. The script runs unattended with no signed-in
        user, so it authenticates as an application identity rather than
        inheriting a user's privileges.

        Returns a boolean instead of throwing. A cloud failure should not
        abort a Leaver run that has already completed its on-premises work --
        a half-finished offboarding is worse than a logged cloud error.
    #>
    if ($SkipGraph) {
        Write-JmlLog -Action 'Graph' -Target 'connect' -Status 'Info' -Detail 'Skipped (-SkipGraph).'
        return $false
    }

    if (-not (Test-Path $Config.GraphCredPath)) {
        Write-JmlLog -Action 'Graph' -Target 'connect' -Status 'Failure' `
            -Detail "Credential file not found at $($Config.GraphCredPath)."
        return $false
    }

    try {
        # Export-Clixml encrypted this with DPAPI, scoped to the user account
        # and machine that created it. Copied elsewhere, the file is useless.
        $graphCred = Import-Clixml -Path $Config.GraphCredPath

        Connect-MgGraph -TenantId $Config.TenantId `
                        -ClientSecretCredential $graphCred `
                        -NoWelcome -ErrorAction Stop

        Write-JmlLog -Action 'Graph' -Target 'connect' -Status 'Success' -Detail 'Connected app-only.'
        return $true
    }
    catch {
        Write-JmlLog -Action 'Graph' -Target 'connect' -Status 'Failure' -Detail $_.Exception.Message
        return $false
    }
}


function Resolve-CloudUser {
    <#
        Matches on the on-premises SamAccountName rather than UPN.

        A non-routable domain such as lab.local can never be verified in
        Entra ID, so synced users receive .onmicrosoft.com UPNs and the
        on-premises UPN has no cloud equivalent. Entra Connect stamps
        onPremisesSamAccountName onto every synced object, which makes it a
        reliable join key.

        Any organization that built AD on a .local domain hits this when
        moving to hybrid.
    #>
    param([Parameter(Mandatory)][string]$Sam)

    try {
        # -ConsistencyLevel eventual is required for advanced Graph queries.
        $cloudUser = Get-MgUser -Filter "onPremisesSamAccountName eq '$Sam'" `
                                -ConsistencyLevel eventual -CountVariable c -ErrorAction Stop

        if (-not $cloudUser) {
            Write-JmlLog -Action 'Graph' -Target $Sam -Status 'Failure' `
                -Detail 'No matching cloud object (may not have synced yet).'
            return $null
        }

        return $cloudUser | Select-Object -First 1
    }
    catch {
        Write-JmlLog -Action 'Graph' -Target $Sam -Status 'Failure' -Detail $_.Exception.Message
        return $null
    }
}


# ================================ JOINER ==================================

function Invoke-Joiner {
    if (-not $FirstName -or -not $LastName) {
        throw "Joiner requires -FirstName and -LastName."
    }

    # Two typed values produce three derived ones. The operator never supplies
    # a SamAccountName or UPN, which is what enforces the convention.
    $sam         = Resolve-SamAccountName -First $FirstName -Last $LastName
    $upn         = "$sam@$($Config.UpnSuffix)"
    $displayName = "$FirstName $LastName"

    if (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue) {
        Write-JmlLog -Action 'Joiner' -Target $sam -Status 'Failure' -Detail 'Account already exists.'
        throw "User '$sam' already exists."
    }

    $plainPw  = New-RandomPassword -Length $Config.PasswordLength
    $securePw = ConvertTo-SecureString $plainPw -AsPlainText -Force

    # Built as a hashtable and splatted rather than passed as a long parameter
    # list, so optional attributes can be added conditionally below.
    $newUserParams = @{
        Name                  = $displayName
        GivenName             = $FirstName
        Surname               = $LastName
        SamAccountName        = $sam
        UserPrincipalName     = $upn
        DisplayName           = $displayName
        Path                  = $Config.JoinerOU
        AccountPassword       = $securePw
        ChangePasswordAtLogon = $true
        Enabled               = $true
    }

    # Only add these if supplied. Passing an empty string would write a blank
    # attribute rather than leaving it unset.
    if ($Department) { $newUserParams.Department = $Department }
    if ($Title)      { $newUserParams.Title      = $Title }

    if ($PSCmdlet.ShouldProcess($sam, "Create AD user")) {

        # @ not $ — splatting expands the hashtable into named parameters.
        New-ADUser @newUserParams -ErrorAction Stop
        Write-JmlLog -Action 'Joiner' -Target $sam -Status 'Success' `
            -Detail "Created in $($Config.JoinerOU); pwd change required at logon."

        if ($Manager) {
            try {
                # AD stores manager as a distinguished name, so the friendly
                # username the operator typed has to be resolved first.
                $mgr = Get-ADUser -Identity $Manager -ErrorAction Stop
                Set-ADUser -Identity $sam -Manager $mgr.DistinguishedName
                Write-JmlLog -Action 'Joiner' -Target $sam -Status 'Info' -Detail "Manager set to $Manager."
            }
            catch {
                Write-JmlLog -Action 'Joiner' -Target $sam -Status 'Failure' -Detail "Manager '$Manager' not found."
            }
        }

        # Each group is attempted independently. One bad group name should not
        # prevent the rest from being applied.
        foreach ($g in $Groups) {
            try {
                Add-ADGroupMember -Identity $g -Members $sam -ErrorAction Stop
                Write-JmlLog -Action 'Joiner' -Target $sam -Status 'Info' -Detail "Added to group '$g'."
            }
            catch {
                Write-JmlLog -Action 'Joiner' -Target $sam -Status 'Failure' `
                    -Detail "Could not add to group '$g': $($_.Exception.Message)"
            }
        }

        # Write-Host is deliberate, not a habit. It writes only to the console
        # and cannot be captured, piped, or redirected -- so the temporary
        # password cannot end up in the audit log or a transcript.
        Write-Host "`nTEMP PASSWORD for $sam : $plainPw" -ForegroundColor Yellow
        Write-Host "Deliver out-of-band. Not written to the audit log.`n"
    }
}


# ================================= MOVER ==================================

function Invoke-Mover {
    if (-not $SamAccountName) { throw "Mover requires -SamAccountName." }

    $user = Get-ADUser -Identity $SamAccountName -Properties MemberOf -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess($SamAccountName, "Update attributes / groups")) {

        # --- 1. Attribute updates ---------------------------------------
        $setParams = @{ Identity = $SamAccountName }
        if ($NewDepartment) { $setParams.Department = $NewDepartment }
        if ($NewTitle)      { $setParams.Title      = $NewTitle }

        # Count > 1 because Identity is always present. Only call Set-ADUser
        # if something beyond the identity was actually supplied.
        if ($setParams.Count -gt 1) {
            Set-ADUser @setParams
            Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Info' -Detail 'Department/Title updated.'
        }

        if ($NewManager) {
            try {
                $mgr = Get-ADUser -Identity $NewManager -ErrorAction Stop
                Set-ADUser -Identity $SamAccountName -Manager $mgr.DistinguishedName
                Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Info' -Detail "Manager updated to $NewManager."
            }
            catch {
                Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Failure' -Detail "Manager '$NewManager' not found."
            }
        }

        # --- 2. Grant new-role access -----------------------------------
        foreach ($g in $AddGroups) {
            try {
                Add-ADGroupMember -Identity $g -Members $SamAccountName -ErrorAction Stop
                Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Info' -Detail "Added to group '$g'."
            }
            catch {
                Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Failure' `
                    -Detail "Could not add to '$g': $($_.Exception.Message)"
            }
        }

        # --- 3. Revoke prior-role access --------------------------------
        #
        # This is the point of the Mover action. Most organizations grant on
        # role change and forget to remove, so access accumulates across every
        # role a person has ever held. That is privilege creep, and this step
        # is what prevents it.
        foreach ($g in $RemoveGroups) {
            try {
                # -Confirm:$false suppresses the cmdlet's own prompt. The
                # script's ShouldProcess block already gated this action.
                Remove-ADGroupMember -Identity $g -Members $SamAccountName -Confirm:$false -ErrorAction Stop
                Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Info' -Detail "Removed from group '$g'."
            }
            catch {
                Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Failure' `
                    -Detail "Could not remove from '$g': $($_.Exception.Message)"
            }
        }

        Write-JmlLog -Action 'Mover' -Target $SamAccountName -Status 'Success' -Detail 'Mover actions completed.'
    }
}


# ================================ LEAVER ==================================

function Invoke-Leaver {
    if (-not $SamAccountName) { throw "Leaver requires -SamAccountName." }

    # Memberships are captured before any changes, because the loop below is
    # about to empty this collection. The operator supplies one identifier and
    # AD supplies the rest -- an offboarding tool that required manual
    # enumeration of access would fail at the thing it exists to prevent.
    $user = Get-ADUser -Identity $SamAccountName -Properties MemberOf -ErrorAction Stop

    if ($PSCmdlet.ShouldProcess($SamAccountName, "Disable, strip access, revoke cloud sessions")) {

        # ------------------------- On-premises -------------------------

        Disable-ADAccount -Identity $SamAccountName
        Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Info' -Detail 'AD account disabled.'

        # Scrambled and never displayed. If the account is re-enabled later,
        # the departed user's known password no longer works.
        $deadPw = ConvertTo-SecureString (New-RandomPassword -Length 24) -AsPlainText -Force
        Set-ADAccountPassword -Identity $SamAccountName -NewPassword $deadPw -Reset
        Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Info' -Detail 'Password reset to random value.'

        foreach ($groupDn in $user.MemberOf) {
            # Extract the CN from the distinguished name for a readable log
            # entry: "CN=IT-Staff,OU=Groups,DC=lab,DC=local" becomes "IT-Staff".
            $groupName = ($groupDn -split ',')[0] -replace '^CN='

            try {
                Remove-ADGroupMember -Identity $groupDn -Members $SamAccountName -Confirm:$false -ErrorAction Stop
                Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Info' -Detail "Removed from group '$groupName'."
            }
            catch {
                # Domain Users is the primary group and cannot be removed this
                # way. That failure is expected and is logged rather than
                # allowed to halt the run.
                Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Failure' `
                    -Detail "Could not remove from '$groupName': $($_.Exception.Message)"
            }
        }

        # Stamps the object so a later audit can tell when and by whom the
        # account was deprovisioned without reading the log file.
        $stamp = "Disabled (Leaver) $(Get-Date -Format 'yyyy-MM-dd') by $env:USERNAME"
        Set-ADUser -Identity $SamAccountName -Description $stamp

        try {
            $dn = (Get-ADUser -Identity $SamAccountName).DistinguishedName
            Move-ADObject -Identity $dn -TargetPath $Config.DisabledOU -ErrorAction Stop
            Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Info' -Detail "Moved to $($Config.DisabledOU)."
        }
        catch {
            Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Failure' -Detail "Could not move OU: $($_.Exception.Message)"
        }

        # ---------------------------- Cloud ----------------------------
        #
        # Disabling in AD does not invalidate tokens that have already been
        # issued. Access and refresh tokens stay valid until they expire, so a
        # departed user can keep reaching Microsoft 365 for up to an hour
        # after being "offboarded".
        #
        # Revoking sessions closes that window. Disabling the cloud object
        # directly avoids waiting on the next 30-minute sync cycle.

        if (Connect-JmlGraph) {

            $cloudUser = Resolve-CloudUser -Sam $SamAccountName

            if ($cloudUser) {
                try {
                    # Graph identifies users by object ID, not UPN.
                    Revoke-MgUserSignInSession -UserId $cloudUser.Id -ErrorAction Stop
                    Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Success' `
                        -Detail "Revoked cloud sign-in sessions (objectId $($cloudUser.Id))."
                }
                catch {
                    Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Failure' `
                        -Detail "Session revoke failed: $($_.Exception.Message)"
                }

                try {
                    Update-MgUser -UserId $cloudUser.Id -AccountEnabled:$false -ErrorAction Stop
                    Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Info' -Detail 'Cloud account disabled directly.'
                }
                catch {
                    Write-JmlLog -Action 'Leaver' -Target $SamAccountName -Status 'Failure' `
                        -Detail "Cloud disable failed: $($_.Exception.Message)"
                }
            }

            # Out-Null discards the cmdlet's output so it does not leak into
            # the function's return value.
            Disconnect-MgGraph | Out-Null
        }
    }
}


# =============================== Dispatch =================================

# Joiner has no SamAccountName yet, so the log target falls back to the name.
# Written as if/else rather than the ?? null-coalescing operator, which is
# PowerShell 7+ only and fails on Windows PowerShell 5.1 -- the version that
# ships with Windows Server.
if ($SamAccountName) {
    $runTarget = $SamAccountName
} else {
    $runTarget = "$FirstName $LastName"
}

try {
    Write-JmlLog -Action $Action -Target $runTarget -Status 'Info' -Detail 'Run started.'

    switch ($Action) {
        'Joiner' { Invoke-Joiner }
        'Mover'  { Invoke-Mover }
        'Leaver' { Invoke-Leaver }
    }

    Write-JmlLog -Action $Action -Target $runTarget -Status 'Info' -Detail 'Run completed.'
}
catch {
    Write-JmlLog -Action $Action -Target $runTarget -Status 'Failure' -Detail $_.Exception.Message
    Write-Error $_.Exception.Message

    # Non-zero exit so a scheduler or pipeline can detect the failure.
    exit 1
}
