## Daily Journal – June 21, 2025

### General Status:

Lighter day but still solid progress. Focused on wrapping up the Escalate My Privileges box, refining recon tooling, and doing foundational enumeration review. Gained better comfort with shell stability and started building out tools that will support future ops.

---

### Completed Tasks

Red Team Target — Escalate My Privileges: 1
* Box completed and report finalized
* Incorporated enumeration steps and shell stabilization techniques into workflow
* Validated importance of TTY management and `socat`-based upgrades

Python – Chapter 9: Regex
* Created:
  - A basic recon `.sh` wrapper
  - A Python parser to clean and extract useful results from Nmap/Gobuster
* Made recon output far more readable and actionable
* Plan to continue with more Python reading tomorrow

Cisco Ethical Hacker – Module 3: Information Gathering and Vulnerability Scanning
* Completed entire module including:
  - OSINT, active vs. passive recon, footprinting techniques
  - Vulnerability scanning methodologies, tools, and scan types
  - Considerations for compliance, stealth, and prioritization
* Reflected on importance of identifying vulnerabilities early in the kill chain

Reflection Prompts:
- **Attack vector wasn’t hidden** — the box gave it away immediately
- **Method felt too easy** — this was a beginner box by design, but useful
- **Regex parser improved recon flow** — simplified scan outputs and focused attention

---

### Additional Notes

- Enumeration logic reaffirmed: each VM = new opportunity depending on exposed services
- Noted that Linux and Windows run services differently (e.g., `svchost.exe` vs. user-owned daemons)
- Ran `enum4linux` and `nikto` despite no indicators — good habit forming
- Built tools that will carry forward: shell stabilization, regex parsing, scan wrappers

---