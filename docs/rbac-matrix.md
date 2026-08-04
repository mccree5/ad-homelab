# RBAC Access Matrix

The access model the [JML automation](../Invoke-JmlLifecycle.ps1) enforces.

Automating provisioning without first defining what access *should* look like
just makes inconsistent access happen faster. This matrix is the governance
layer: it decides who gets what, and the script executes it.

> Adjust the departments, roles, and group names to match your own directory.
> The structure is the transferable part.

---

## Principles

**Role-based, not person-based.** Access is granted to a role and inherited by
whoever holds it. Nobody is granted access individually, because individual
grants are invisible to review and never get removed.

**Groups, never direct permissions.** Users are placed in security groups;
groups are granted permissions on resources. A user is never granted access to
a resource directly. This keeps entitlement review a matter of reading group
membership rather than auditing every share and application.

**Baseline plus role.** Everyone receives a baseline set that reflects being
an employee at all. Role groups stack on top. This avoids repeating common
access in every row.

**Least privilege by default.** A role receives what it needs to function and
nothing anticipatory. Anything beyond baseline plus role requires an exception.

**One role at a time.** When someone changes roles, the previous role's groups
are removed rather than left in place. Access should reflect the job held now,
not every job ever held.

---

## Baseline (all employees)

Granted at Joiner regardless of department.

| Group | Grants |
|---|---|
| `All-Staff` | Intranet, company-wide distribution, shared policies |
| `VPN-Users` | Remote network access |
| `Printers-General` | Standard office printing |

---

## Role assignments

Applied in addition to baseline.

| Department | Role | Groups | Notes |
|---|---|---|---|
| IT | Support Analyst | `IT-Staff`, `Helpdesk-Tools`, `Workstation-Admins` | Local admin on workstations only, never on servers |
| IT | Systems Administrator | `IT-Staff`, `Helpdesk-Tools`, `Server-Admins` | Requires exception approval |
| IT | Security Analyst | `IT-Staff`, `SIEM-Readers`, `Security-Tools` | Read access to logs; no directory write |
| Finance | Financial Analyst | `Finance-Staff`, `Finance-Reports` | Read-only to the accounting system |
| Finance | Controller | `Finance-Staff`, `Finance-Reports`, `Finance-Approvers` | Approval rights; conflicts with `AP-Processors` |
| HR | HR Generalist | `HR-Staff`, `HRIS-Users` | Access to personnel records |
| HR | HR Director | `HR-Staff`, `HRIS-Users`, `HR-Compensation` | Compensation data restricted to this role |
| Sales | Account Executive | `Sales-Staff`, `CRM-Users` | |
| Sales | Sales Manager | `Sales-Staff`, `CRM-Users`, `CRM-Managers` | Team pipeline visibility |
| Operations | Coordinator | `Ops-Staff`, `Scheduling-Tools` | |

---

## Separation of duties

Pairs that must not be held simultaneously. These are the combinations where
one person could both perform an action and approve it.

| Group A | Group B | Why |
|---|---|---|
| `AP-Processors` | `Finance-Approvers` | Creating and approving the same payment |
| `Server-Admins` | `SIEM-Readers` (write) | An administrator should not be able to alter the logs recording their own actions |
| `HR-Compensation` | `Finance-Approvers` | Setting compensation and approving its payment |

The current script does not enforce these automatically. A Mover run that
would produce a conflicting combination is caught at review, not at execution.
Enforcing it in code is a known gap.

---

## Privileged access

Groups requiring approval beyond the standard Joiner or Mover request.

| Group | Approver | Review cadence |
|---|---|---|
| `Server-Admins` | IT Director | Quarterly |
| `Domain-Admins` | IT Director + CISO | Monthly |
| `Finance-Approvers` | CFO | Quarterly |
| `HR-Compensation` | HR Director | Quarterly |

Privileged access uses separate administrative accounts rather than being
added to a daily-use account.

---

## Lifecycle mapping

How the matrix drives each action.

**Joiner** — baseline groups plus the role row for the stated department and
title. Anything outside the matrix is an exception and is not granted at
provisioning time.

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Joiner -FirstName Jane -LastName Smith `
    -Department IT -Title "Support Analyst" `
    -Groups "All-Staff","VPN-Users","Printers-General","IT-Staff","Helpdesk-Tools","Workstation-Admins"
```

**Mover** — the delta between the old row and the new row. Groups in both
rows stay; groups only in the old row are removed; groups only in the new row
are added. Baseline is unaffected.

```powershell
.\Invoke-JmlLifecycle.ps1 -Action Mover -SamAccountName jane.smith `
    -NewDepartment Finance -NewTitle "Financial Analyst" `
    -AddGroups "Finance-Staff","Finance-Reports" `
    -RemoveGroups "IT-Staff","Helpdesk-Tools","Workstation-Admins"
```

**Leaver** — every group, baseline included. The script reads current
membership from the directory rather than consulting this matrix, because the
actual state may have drifted from the intended state, and offboarding has to
remove what is actually there.

---

## Review

| What | Cadence | Owner |
|---|---|---|
| Privileged group membership | Quarterly | IT Director |
| Standard role groups | Annually | Department managers |
| Separation of duties conflicts | Quarterly | Security |
| Matrix itself vs. actual roles | Annually | IT + HR |

Review compares actual group membership against this matrix. Anything present
in the directory but absent from the matrix is either an undocumented
exception or leftover access, and both need resolving.

---

## Known gaps

- **Separation of duties is not enforced in code.** The script will happily
  create a conflicting combination. Validating `-AddGroups` against the
  conflict table before executing is the next improvement.
- **The matrix is a document, not a data source.** Group assignments are
  passed as parameters rather than looked up. A CSV or JSON version the script
  reads directly would remove the possibility of the two drifting apart.
- **No time-bound access.** Temporary elevation has to be granted and revoked
  as two separate manual actions.
