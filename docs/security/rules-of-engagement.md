# ParallelF — Rules of Engagement

These rules govern all security-related work in this repository: NetGuard discovery and monitoring, and every Security Lab activity. They are enforced technically where possible (signed scopes, isolated lab networks, read-only AI) and procedurally everywhere else.

## 1. Authorized targets only

- **Networks:** only networks created by ParallelF (Cloud networks, the VPN tunnel network) and the owner's home LAN segments that are explicitly registered as a NetGuard scope with an authorization note. No public IP ranges. No neighbours' networks, school or employer networks, public Wi-Fi, or cloud provider ranges other than the owner's own AWS demo VPC.
- **Software:** only software written by the project owner (ParallelF Arena, the `lab/targets/*` programs) or published explicitly as an intentionally vulnerable training target under a licence that permits this use.
- **People:** household members whose traffic might be observed on the home LAN are told about monitoring before LAN monitoring is enabled. Retention for LAN telemetry stays short.

## 2. Prohibited activities

- Developing, testing or documenting bypasses for any commercial anti-cheat, DRM or anti-tamper system.
- Interacting with third-party games, game servers, or online services as a research target.
- Building stealth, persistence, privilege-escalation-for-hiding, kernel drivers, or evasion capabilities.
- Moving any lab artifact, exploit-check, or modified build outside the lab environment, except source code and write-ups in this repository.
- Running real-world malware samples. The lab is for educational, self-authored vulnerable code.
- Active scanning of anything outside a valid, signed NetGuard scope.

## 3. Required practices

- Every experiment is recorded in `pf-labd` (hypothesis, method, result) and ends in a finding with a mitigation and a verification (test or detection signal).
- Exploit-checks prove a condition (crash, sanitizer report, assertion) and are not weaponized payloads.
- Lab environments run only inside `lab` networks with a healthy sensor, and are destroyed at TTL.
- Isolation checks run at every environment start. Any isolation failure halts lab work until the root cause is fixed and documented.
- Write-ups in `docs/lab-writeups/` focus on the defensive lesson and the fix.

## 4. Incident in the lab

If a lab workload shows unexpected outbound behaviour, if `ng.lab_egress_attempt` fires, or if the isolation check fails:

1. Destroy the environment (`pfctl lab env destroy <id> --now`).
2. Preserve NetGuard evidence for the time window.
3. Open an incident and document the root cause before re-enabling the lab profile.
