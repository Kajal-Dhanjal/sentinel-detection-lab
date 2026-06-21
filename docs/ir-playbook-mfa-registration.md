# Incident Response Playbook
## Suspicious MFA / Security-Info Registration Following Sign-In from an Untrusted IP

**Associated detection:** `Suspicious MFA Registration Following Sign-In from Untrusted IP`
**MITRE ATT&CK:** T1556.006 — Modify Authentication Process: Multi-Factor Authentication
**Tactic:** Persistence
**Severity:** High
**Platform:** Microsoft Sentinel (Entra ID `AuditLogs` + `SigninLogs`)

---

## 1. Purpose & Threat Context

An attacker who has compromised a set of valid credentials (via phishing, password spray, token theft, or an info-stealer) frequently moves to establish **durable persistence** before the legitimate user or the SOC notices. One of the cleanest ways to do this in an Entra ID environment is to **register their own MFA method** — an authenticator app, phone number, or FIDO key — on the compromised account.

Once the attacker controls an enrolled factor, they can satisfy MFA challenges on their own terms. Even a later password reset by the victim does not necessarily evict them, because the attacker-controlled factor survives the reset. This makes MFA-registration persistence both high-impact and easy to overlook.

This detection flags the **behavioural signature** of that activity: a security-info registration event occurring shortly after a sign-in from an IP address that is **not** on the organisation's trusted list. The pairing of "unfamiliar source" + "self-service security change" is the anomaly — either event alone is routine.

---

## 2. Detection Logic (Summary)

The analytics rule correlates two Entra ID signals within a short time window:

1. A `SigninLogs` event where `IPAddress` is **not** in the trusted-IP list.
2. An `AuditLogs` event `ActivityDisplayName == "User started security info registration"` for the **same user**, occurring within **30 minutes** of that sign-in.

It excludes known-good infrastructure via a trusted-IP list, deduplicates multiple sign-in records belonging to the same session, and surfaces the time delta between sign-in and registration (`TimeToRegistration`) as a triage signal — a very short delta is more suspicious, consistent with scripted or hands-on-keyboard attacker behaviour rather than an ordinary user setting up a new phone.

> **Scope note.** This lab version defines "untrusted" via a static IP exclusion list. A production deployment would baseline each user's historical sign-in locations (per-user novelty) — the signal Entra ID Identity Protection provides natively with a P2 licence. This is a deliberate, documented design choice, not a gap in the logic.

---

## 3. Triage (First 10 Minutes)

The goal of triage is to answer one question quickly: **is this a real account takeover, or a benign user who travelled / used a VPN / set up a new device?**

**Step 1 — Open the incident and read the entities.**
Note the `UserPrincipalName`, the source `IPAddress`, the `Location`, the sign-in time, and the `TimeToRegistration` delta.

**Step 2 — Assess the source.**
- Is the IP/location plausible for this user? (Do they travel? Work remotely? Use a corporate VPN whose egress isn't yet on the trusted list?)
- Is the IP a known hosting/VPN/anonymiser range? Hosting-provider ASNs are a strong escalation signal — ordinary users rarely sign in from a datacentre.

**Step 3 — Pull the surrounding sign-in history for the user.**

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "<UPN_FROM_INCIDENT>"
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResultType, ResultDescription
| order by TimeGenerated desc
```

Look for: a recent baseline of sign-ins from the user's normal location, then an abrupt shift to the flagged IP. A clean break in location/IP immediately before the registration is the takeover pattern.

**Step 4 — Confirm what was actually registered.**

```kql
AuditLogs
| where TimeGenerated > ago(1d)
| where TargetResources has "<UPN_FROM_INCIDENT>"
| where ActivityDisplayName has "security info" or ActivityDisplayName has "authentication method"
| project TimeGenerated, ActivityDisplayName, Result, InitiatedBy, TargetResources
| order by TimeGenerated asc
```

Look at the full sequence. A pattern of **delete existing method → register new method** from an untrusted IP is especially suspicious — it suggests the attacker is replacing the victim's factor with their own, not merely adding one.

**Triage decision:**
- **Benign** (recognised travel/VPN, user confirms the action) → close as false positive, and consider adding the egress IP to the trusted list to suppress recurrence.
- **Suspicious or unconfirmed** → proceed to Containment immediately. Do not wait for the user to respond if the source looks like hosting/anonymiser infrastructure.

---

## 4. Containment

**Primary action: revoke active sessions and force re-authentication.**

For this threat, revoking sessions is the correct first move rather than outright disabling the account. It immediately invalidates the attacker's stolen tokens and refresh tokens, forcing re-authentication on the next request — which cuts their active access without the broader business disruption of a full account disable. It also directly counters the persistence attempt: the attacker's session dies, and the subsequent investigation can strip the factor they planted.

**Steps:**

1. **Revoke the user's sessions / refresh tokens.**
   - Entra portal: *Users → [user] → Revoke sessions*, **or**
   - PowerShell: `Revoke-MgUserSignInSession -UserId "<UPN>"`
   This invalidates issued tokens and forces re-auth across the user's sessions.

2. **Remove the attacker-registered MFA method.**
   Identify the method from the AuditLogs query in Step 4 above, then remove it via *Users → [user] → Authentication methods*. This is the step that actually evicts the persistence — revoking sessions alone leaves the planted factor in place for the attacker to reuse.

3. **Force a password reset** on the account, since the credentials should be assumed compromised.

4. **Re-enrol the legitimate user** on a known-good factor through a verified, out-of-band channel (not via any contact detail that may have been altered during the compromise).

> **Sequencing matters:** revoke sessions *first* (kills active access), then remove the rogue factor and reset the password (prevents re-entry). Doing it in the reverse order risks the attacker re-establishing a session before you've cut them off.

---

## 5. Eradication & Recovery

- Confirm only legitimate, expected authentication methods remain on the account.
- Review what the compromised account could access during the exposure window (mailbox rules, OAuth app consents, group memberships, privileged roles). Token theft is frequently a stepping stone — check for **inbox forwarding rules** and **newly consented enterprise applications**, both common follow-on persistence techniques.
- Confirm the legitimate user has regained sole control before closing.

---

## 6. Post-Incident Actions

- **Tune the trusted-IP list** based on what triage revealed (add confirmed-good corporate VPN egress ranges; never add hosting/anonymiser ranges).
- **Hunt for the same pattern across other users** — an attacker who found one valid credential set often has more:

```kql
let TrustedIPs = dynamic(["<your_trusted_ips>"]);
AuditLogs
| where TimeGenerated > ago(14d)
| where ActivityDisplayName == "User started security info registration"
| extend UPN = tostring(TargetResources[0].userPrincipalName)
| join kind=inner (
    SigninLogs
    | where IPAddress !in (TrustedIPs)
    | project SigninTime = TimeGenerated, UPN = UserPrincipalName, IPAddress, Location
) on UPN
| where TimeGenerated between (SigninTime .. (SigninTime + 30m))
| summarize Registrations = count() by UPN, IPAddress, Location
| order by Registrations desc
```

- **Document indicators** (attacker IP, ASN, timing) and feed them into watchlists / threat-intel.
- **Consider Conditional Access hardening** — e.g. requiring a compliant/managed device or a trusted location for security-info registration, which removes the attacker's ability to perform this action at all.

---

## 7. Escalation & Ownership

This playbook assumes a **solo analyst / small-team** model in which the responder owns the incident end-to-end. Escalation here means broadening involvement when scope exceeds a single account:

- **Single user, contained quickly** → handle end-to-end; document and close.
- **Multiple users affected, or a privileged/admin account involved** → escalate scope: this is no longer a single-account event and may indicate a broader credential compromise. Treat as a potential wider intrusion, widen the hunt (Section 6), and bring in additional support/management as available.
- **Evidence of data access or exfiltration during the exposure window** → trigger the organisation's broader incident process and preserve evidence before further remediation.

---

## 8. References

- MITRE ATT&CK — T1556.006, Modify Authentication Process: Multi-Factor Authentication
- Microsoft Entra ID — sign-in and audit log schema (`SigninLogs`, `AuditLogs`)
- Microsoft Sentinel — scheduled analytics rules and entity mapping
