# AD Home Lab

A self-hosted hybrid identity environment: a Windows domain on Hyper-V
synchronized to Microsoft Entra ID, with endpoint telemetry forwarded to a
SIEM, and a PowerShell automation that manages the full user lifecycle across
both directories.

Built to understand how identity actually moves through an organization, and
where each stage tends to break.

---

## Architecture

```
                    Microsoft Entra ID (cloud tenant)
                              ^        ^
                              |        |
                  Entra Connect        Microsoft Graph
                   (sync, 30min)       (app-only, on demand)
                              |        |
    +-------------------------+--------+------------------+
    |                                                     |
  MCCREEDC01                                    Invoke-JmlLifecycle.ps1
  Windows Server DC                             (Joiner / Mover / Leaver)
  lab.local
    |
    +-- CLIENT01 (domain-joined, Sysmon)
    |
    +-- WAZUH01 (Ubuntu, SIEM)
```

| Host | Role |
|---|---|
| `MCCREEDC01` | Domain controller, DNS, Entra Connect |
| `CLIENT01` | Domain-joined workstation, Sysmon |
| `WAZUH01` | Wazuh manager and OpenSearch on Ubuntu |

Advanced Audit Policy is applied through Group Policy to capture
authentication and account management events. Logging was validated with
controlled test activity: failed logons, account lockouts, and group
membership changes.

---

## The main artifact

[`scripts/Invoke-JmlLifecycle.ps1`](scripts/Invoke-JmlLifecycle.ps1) —
Joiner, Mover, and Leaver automation across Active Directory and Entra ID.
Verified end to end against this environment.

**Joiner**

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Joiner -FirstName Test -LastName User `
    -Department IT -Title "Support Analyst" `
    -Groups "All-Staff","VPN-Users","IT-Staff"
```

Two typed values produce the SamAccountName, UPN, and display name, so
naming stays consistent regardless of who provisions. The password is seeded
with one character from each complexity class and shuffled, satisfying domain
policy by construction rather than by chance. It is printed with
`Write-Host`, which cannot be piped or captured, so it never reaches the log.

**Mover**

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Mover -SamAccountName test.user `
    -NewDepartment HR -NewTitle "HR Coordinator" `
    -AddGroups "HR" -RemoveGroups "IT-Staff"
```

Granting new access on a role change is the half most manual processes get
right. Removing the old access is what prevents privilege creep, and it gets
skipped because nothing breaks when you forget. Baseline groups are excluded
from removal, so being an employee and holding a role stay separate concerns.

**Leaver**

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Leaver -SamAccountName test.user -WhatIf
```

One identifier in; every group membership read from the directory itself. An
offboarding tool that made you enumerate access by hand would fail at exactly
the thing it exists to prevent.

---

## Why the Leaver calls Graph

Disabling an account in Active Directory does not invalidate tokens that have
already been issued. Access and refresh tokens stay valid until they expire,
so someone just offboarded can keep reaching Microsoft 365 for up to an hour.

Directory sync does not close this either. It propagates the disabled state,
but does nothing to sessions already in flight.

So the Leaver calls `Revoke-MgUserSignInSession` through Microsoft Graph,
then disables the cloud object directly rather than waiting on the next sync
cycle.

**Authentication.** Graph calls authenticate as an application, not a user,
because the script runs unattended. Application permissions have no
user-privilege ceiling, so the credential deserves care: the client ID and
secret live in a DPAPI-encrypted file scoped to the account and machine that
created it. Copied elsewhere, the file is inert. The script contains no
credential.

**Finding the cloud object.** `lab.local` is non-routable and can never be a
verified domain in Entra ID, so synced users get `.onmicrosoft.com` UPNs and
the on-premises UPN has no cloud equivalent. Lookups match on
`onPremisesSamAccountName`, which Entra Connect stamps onto every synced
object. Any organization that built AD on a `.local` domain hits this when
moving to hybrid.

---

## Audit logging

Every action appends one self-contained JSON object per line. JSONL rather
than free text, because a SIEM can parse it directly with no custom regex.

```json
{"timestamp":"2026-08-04T13:26:28.9130838-07:00","action":"Leaver","target":"test.user","status":"Info","detail":"AD account disabled.","runBy":"Administrator"}
{"timestamp":"2026-08-04T13:26:28.9599112-07:00","action":"Leaver","target":"test.user","status":"Info","detail":"Removed from group 'HR'.","runBy":"Administrator"}
{"timestamp":"2026-08-04T13:26:38.0607638-07:00","action":"Leaver","target":"test.user","status":"Success","detail":"Revoked cloud sign-in sessions.","runBy":"Administrator"}
```

The timestamp and operator are generated inside the logging function rather
than passed as parameters. An audit log should not let its caller claim a
different time or a different user.

---

## What testing surfaced

Three things only appeared once the script ran against a live directory.

**`powershell.exe -File` does not parse arrays.** Arguments are passed as
literal strings, so `-Groups "A","B","C"` arrived as a single group named
`A,B,C` and the assignment failed. This is the same failure mode that breaks
scheduled tasks, which almost always invoke with `-File`. Dot-sourcing in an
existing session fixes it.

**Dry runs write no audit entry.** `-WhatIf` cascades to any cmdlet
supporting `ShouldProcess`, including the `Add-Content` call inside the
logging function. Arguably wrong — a previewed offboarding is worth
recording — and `-WhatIf:$false` on that line would force it. Documented
rather than changed, since a genuinely read-only dry run is also defensible.

**Domain Users never appears in the Leaver's removal loop.** Primary group
membership is not stored in the `memberOf` attribute at all, so the loop
never sees it. Worth knowing in the other direction too: any access audit
built on `memberOf` alone silently misses primary group membership.

---

## Setup

**Requirements:** Windows PowerShell 5.1+, RSAT ActiveDirectory module,
`Install-Module Microsoft.Graph`.

**1.** Edit the `$Config` hashtable at the top of the script with your domain,
OUs, and tenant ID.

**2.** Register an application in Entra ID with admin-consented application
permissions: `User.ReadWrite.All` and `User.RevokeSessions.All`.

**3.** Store the credential once, on the machine that will run the script:

```powershell
New-Item C:\secure -ItemType Directory -Force
$cred = Get-Credential -UserName "<application-client-id>" `
    -Message "Paste the client secret VALUE as the password"
$cred | Export-Clixml -Path C:\secure\jml-graph.xml
```

The **Value** column, not the Secret ID. They sit next to each other in the
portal and the Secret ID looks more like a credential, which is a reliable
way to spend twenty minutes on an authentication error.

**4.** Dry run before anything real:

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Leaver -SamAccountName testuser -WhatIf
```

---

## Known limitations

**Permissions are broader than necessary.** The application grant is
tenant-wide. The production fix is an administrative unit scoping the role to
only the accounts in scope — I built the AU, but assigning a scoped role to a
service principal requires Entra ID P1 and this tenant is free tier. The same
principle underlies Microsoft's GDAP model for MSPs: narrow the blast radius
so one compromised identity cannot reach past its actual job.

**Separation of duties is documented, not enforced.** The
[access matrix](docs/rbac-matrix.md) defines conflicting group pairs, but the
script will happily create one. Validating `-AddGroups` against that table
before executing is the next improvement.

**Other gaps.** One user per run, no bulk input. The Mover is not idempotent.
And because the Graph calls share a `ShouldProcess` block with the
on-premises actions, a dry run cannot exercise the cloud path independently.

---

## Repo contents

| Path | What it is |
|---|---|
| `scripts/Invoke-JmlLifecycle.ps1` | The lifecycle automation |
| `docs/rbac-matrix.md` | Role-to-group access model the script enforces |
| `docs/sysmon-setup.md` | Sysmon deployment on the client |
| `docs/entra-connect-setup.md` | Directory sync configuration |
| `docs/screenshots/` | Run captures from the verification pass |

Alert triage on top of the Wazuh side lives in
[wazuh-alert-pipeline](https://github.com/mccree5/wazuh-alert-pipeline).
