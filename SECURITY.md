# Security policy

## Supported versions

Security fixes are applied to the latest commit on `main` while the project is
pre-1.0.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub's
private vulnerability reporting for this repository: open the **Security** tab,
choose **Advisories**, then **Report a vulnerability**.

Include the affected version or commit, setup, reproduction steps, impact, and
any suggested mitigation. Remove real credentials, personal data, and private
agent transcripts from the report. You should receive an acknowledgement
within seven days. A fix and disclosure timeline will be coordinated according
to severity.

## Security boundaries

The firewall reduces risk; it is not a sandbox. Run agent tools with operating
system least privilege. Bind the service to loopback, set
`AGENT_FIREWALL_TOKEN`, protect `.env` and the audit database, and do not expose
the API directly to an untrusted network.
