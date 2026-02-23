## Build Notes / Progress Log

### Session 1 — Hyper-V Networking + DC VM Foundation
**Goal:** Start an isolated Hyper-V lab network and prepare the Domain Controller VM.

#### Completed
- Created a Hyper-V **Internal** virtual switch for the lab network:
  - Switch name: `ad-lab-vSwitch`
- Configured the Windows host virtual adapter for the lab network:
  - Adapter: `vEthernet (ad-lab-vSwitch)`
  - Host IP: `10.10.10.1`
  - Subnet mask: `255.255.255.0`
  - Default gateway: (blank)
- Created the first VM for the lab (future Domain Controller):
  - VM name: `mccreedc01`
  - Connected VM network adapter to: `ad-lab-vSwitch`
- Verified host ↔ VM connectivity:
  - From the VM, `ping 10.10.10.1` initially timed out.
  - Fixed by allowing ICMP (ping) through the Windows firewall on the host.
  - After the firewall change, VM ↔ host ping succeeded.

#### Notes / Observations
- Confirmed the lab network is isolated and functioning (host and VM can communicate over the internal switch).
- Ran name resolution tests:
  - `nslookup mccreedc01.lab.local` returned `10.10.10.10` (some DNS timeouts appeared when the system tried `::1` first).

#### Next Steps
- Finish Windows Server installation/configuration on `mccreedc01`.
- Set a static IP on `mccreedc01`:
  - IP: `10.10.10.10/24`
  - DNS: `10.10.10.10`
- Install roles: **Active Directory Domain Services (AD DS)** + **DNS Server**.
- Promote `mccreedc01` to a Domain Controller and create the domain:
  - Domain: `lab.local`
- Create a Hyper-V checkpoint after AD promotion 
  - Name `Base-Network-Checkpoint`
