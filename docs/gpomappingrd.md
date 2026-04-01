### Session Update — CLIENT01 Domain Join + Share Access Validation
**Completed**
- Built and domain-joined `CLIENT01` to `lab.local` (DNS pointed to `10.10.10.10`).
- Verified name resolution to the domain controller (`mccreedc01.lab.local` → `10.10.10.10`).
- Validated group-based access control by signing into `CLIENT01` with test domain users and confirming:
  - HR users can access `\\mccreedc01\HR`
  - Helpdesk users can access the Helpdesk/IT share
  - Access is enforced through AD security group membership (RBAC)

- Move `CLIENT01` computer object into the `Workstations` OU 
- Create a GPO to automatically map the appropriate network drive(s) for each group.
- Create a checkpoint: `Part1-Working`

Session Update — GPO Drive Mapping (Validated)
**Completed**
- Created a GPO to automate network drive mappings using **Group Policy Preferences** (User Configuration → Drive Maps).
- Configured role-based drive mappings:
  - HR users receive a mapped drive to `\\mccreedc01\HR`
  - Helpdesk users receive a mapped drive to the Helpdesk share
- Used AD security group membership (RBAC) to scope which users receive each mapping.
- Verified on `CLIENT01` by logging in as test domain users and confirming drives mapped successfully after policy refresh/logon.
