# Ethics, legality, and scope

This repo demonstrates multi-agent security automation. Anyone using or evaluating
it should understand exactly what it does and does not do.

## What this repo is

- A research playground for orchestrating security tooling via the phantom-mesh
  multi-agent runtime.
- A demonstration of how XDR-style cross-source correlation maps to a multi-agent
  architecture.
- A teaching artifact for talking about red/blue team workflows in interviews,
  technical discussions, and educational settings.

## What this repo is not

- Not a production penetration-testing tool.
- Not a 0-day weapon. No proprietary exploits, no privilege-escalation chains,
  no novel CVE research.
- Not a service. Nothing here phones home. Nothing here scans on your behalf.
- Not authorized to be used against any system you do not own or do not have
  written permission to test.

## Legal targets only

The Docker compose lab pulls only **legally distributed, intentionally
vulnerable** applications:

| Target | Source | License |
|---|---|---|
| OWASP Juice Shop | https://github.com/juice-shop/juice-shop | MIT |
| DVWA | https://github.com/digininja/DVWA | GPL-3.0 |
| Metasploitable 3 | https://github.com/rapid7/metasploitable3 | BSD-3-Clause |

These projects exist *specifically* to be attacked, in private labs, by people
learning security testing. They are the security-industry equivalent of
laboratory-grade chemicals.

## Network isolation

The compose file binds all targets to a private docker network with no host port
exposure by default. The intent is that attack traffic never leaves the docker
bridge. If you need to reach a target from your host (e.g., to view Juice Shop's
admin UI in a browser), you must edit the compose file explicitly to publish
ports — there is no implicit exposure.

## Tools

All tools used by the agents are publicly available, widely deployed in
defensive security research:

- **Nmap** — network scanner, used by every blue team in the world for asset
  inventory.
- **Nuclei** — template-based vulnerability scanner, used by Project Discovery,
  pentesters, and bug bounty hunters.
- **Nikto** — legacy web vuln scanner, GPL-licensed.
- **dnsrecon, subfinder** — DNS enumeration, OSINT-only data sources.

None of these are "hacking tools" — they are reconnaissance and assessment tools
used by every modern security team.

## Exploit Suggester scope

The exploit-suggester agent matches CVE identifiers against scan output and
generates a **prose description** of how the vulnerability would be exploited
in principle. It does not:

- Generate runnable exploit code.
- Generate shellcode.
- Chain vulnerabilities into attack paths automatically.
- Exfiltrate data.

If a CVE has public POC code (e.g., on Exploit-DB), the agent can include a
**reference** to that resource — but the agent itself does not execute the POC,
and the POC is not bundled in this repo.

This is the same scope a pentester's written report would have.

## Responsible use

If you fork this and intend to scan real systems:

1. Get **written authorization** from the system owner before any scan.
2. Stay within the scope defined in that authorization.
3. Disclose findings responsibly via the system owner's channel — not publicly.
4. Be aware of your local laws (Taiwan: 刑法第 358-363 條 / Computer Fraud and
   Abuse Act in the US / Computer Misuse Act in the UK / equivalent elsewhere).

If you are unsure whether something you want to do with this repo is legal,
**don't do it.** Ask a lawyer or your local CERT.

## Reporting concerns

If you believe a component of this repo crosses an ethical line or could be
misused in a way that wasn't anticipated, please open an issue or contact the
maintainer directly. The intent is to keep this useful for legitimate research
and education.
