# JML Identity Lifecycle Automation

A PowerShell automation that handles the Joiner / Mover / Leaver identity
lifecycle across on-premises Active Directory and Microsoft Entra ID.

Built to understand how identity actually moves through an organization --
provisioning, role changes, and deprovisioning -- and where each stage tends
to go wrong.

---

## The problem it solves

Manual identity management fails in predictable ways:

- **Joiners** get inconsistent access depending on who set them up. Naming
  conventions drift, OU placement varies, group membership gets missed.
- **Movers** accumulate access. Someone moves from IT to Finance, gains the
  Finance groups, and keeps the IT ones. Repeat across a career and you get
  privilege creep -- a user whose access reflects every role they have ever
  held rather than the one they hold now.
- **Leavers** are offboarded incompletely. The account gets disabled, but
  group memberships stay, and cloud sessions stay alive.

Each action in this script targets one of those failures.

---

## Usage

**Joiner**

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Joiner -FirstName Jane -LastName Smith `
    -Department IT -Title "Support Analyst" -Manager bob.jones `
    -Groups "IT-Staff","VPN-Users"
```

Derives the SamAccountName and UPN from the name, generates a complex random
password with change-at-logon set, places the account in the configured OU,
resolves the manager to a distinguished name, and adds role-based groups.

**Mover**

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Mover -SamAccountName jane.smith `
    -NewDepartment Finance -NewTitle "Financial Analyst" `
    -AddGroups "Finance-Staff" -RemoveGroups "IT-Staff"
```

Updates attributes, grants new-role access, and **removes old-role access**.
That last step is the point of the action.

**Leaver**

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Leaver -SamAccountName jane.smith -WhatIf
```

You supply one identifier. The script reads every group membership from AD
itself -- an offboarding tool that made you enumerate access by hand would
fail at exactly the thing it exists to prevent.

---

## Design decisions

### Cloud session revocation

Disabling an account in AD does not invalidate tokens that have already been
issued. Access and refresh tokens stay valid until they expire, so a leaver
can keep reaching Microsoft 365 for up to an hour after being "offboarded".

The Leaver action calls `Revoke-MgUserSignInSession` through Microsoft Graph
to close that window, then disables the cloud object directly rather than
waiting on the next 30-minute sync cycle.

### Matching cloud users by on-prem SamAccountName

The lab domain is `lab.local`, which is non-routable and can never be a
verified domain in Entra ID. Synced users therefore receive
`.onmicrosoft.com` UPNs, and the on-prem UPN does not exist in the cloud at
all.

Lookups match on `onPremisesSamAccountName`, which Entra Connect stamps onto
every synced object. This is a real hybrid identity problem -- any
organization that built AD on a `.local` domain hits it when moving to
hybrid.

### App-only authentication with no secret in the script

Graph calls authenticate as an application, not a user, because the script
runs unattended with nobody signed in. Application permissions have no
user-privilege ceiling, so the credential deserves care.

The client ID and secret live in a DPAPI-encrypted file created with
`Export-Clixml`, tied to the Windows account and machine that created it.
Copied elsewhere, the file is useless. The script reads it at runtime and
contains no credential itself.

Certificate-based authentication would be stronger still, since there is no
secret string to leak. That is the natural next step.

### ShouldProcess for dry runs

`[CmdletBinding(SupportsShouldProcess = $true)]` gives every action `-WhatIf`
and `-Confirm` for free. Nothing that modifies the directory runs outside a
`ShouldProcess` block, so a dry run is genuinely read-only.

### JSON-lines audit logging

Every action appends one self-contained JSON object per line. Each entry
records the timestamp, action, target, status, detail, and the operator who
ran it.

The timestamp and operator are generated inside the logging function rather
than passed as parameters -- an audit log should not let its caller claim a
different time or a different user.

JSONL rather than free text because a SIEM can parse it directly with no
custom regex.

**Sample output:**

```json
{"timestamp":"2026-08-02T14:22:01.4471820-04:00","action":"Leaver","target":"jane.smith","status":"Info","detail":"AD account disabled.","runBy":"administrator"}
{"timestamp":"2026-08-02T14:22:01.6193044-04:00","action":"Leaver","target":"jane.smith","status":"Info","detail":"Removed from group 'IT-Staff'.","runBy":"administrator"}
{"timestamp":"2026-08-02T14:22:02.1027733-04:00","action":"Leaver","target":"jane.smith","status":"Success","detail":"Revoked cloud sign-in sessions.","runBy":"administrator"}
```

### Temp passwords are never logged

The generated password goes to the console with `Write-Host`, which writes
only to the screen and cannot be captured, piped, or redirected. It is
delivered out of band and never touches the audit log.

---

## Setup

**Requirements**

- Windows PowerShell 5.1 or later (no PowerShell 7 dependency)
- RSAT ActiveDirectory module
- `Microsoft.Graph` module: `Install-Module Microsoft.Graph -Scope CurrentUser`

**1. Configure**

Edit the `$Config` hashtable at the top of the script with your domain, OUs,
and tenant ID.

**2. Register an application in Entra ID**

Application permissions, admin consent granted:

| Permission | Used for |
|---|---|
| `User.ReadWrite.All` | Disabling the cloud account |
| `User.RevokeSessions.All` | Revoking active sign-in sessions |

`.All` is broader than this script strictly needs. In production these would
be scoped with an administrative unit rather than granted tenant-wide.

**3. Store the credential**

Run once, interactively, on the machine that will execute the script:

```powershell
New-Item C:\secure -ItemType Directory -Force
$cred = Get-Credential -UserName "<client-id>" -Message "Paste the client secret as the password"
$cred | Export-Clixml -Path C:\secure\jml-graph.xml
```

**4. Test**

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Leaver -SamAccountName testuser -WhatIf
```

---

## Known limitations

- **One user per run.** No CSV or bulk input yet.
- **Mover is not idempotent.** Running it twice re-attempts the same group
  changes rather than checking current state first.
- **`-WhatIf` does not isolate the cloud half.** The Graph calls sit inside
  the same `ShouldProcess` block as the AD actions, so a dry run skips both.
  Use `-SkipGraph` to exercise the on-premises path alone.
- **Domain Users cannot be removed** on Leaver. It is the primary group and
  AD rejects the removal. The failure is logged rather than treated as an
  error.

---

## Environment

Developed against a Hyper-V lab: a Windows Server domain controller
synchronized to Microsoft Entra ID via Entra Connect, with a Windows client
joined to the domain. Lab build documented in
[ad-homelab](https://github.com/mccree5/ad-homelab).
