# IR Playbook: Suspicious MFA Registration Following Sign-In from Untrusted IP

> **Note:** This is a reconstruction based on the design decisions described during the build (revoke-sessions-first containment, solo-analyst framing). If you already have your original playbook file from today's session, use that instead — this is a placeholder so the repo structure is complete and the detection doc's link doesn't 404.

**Detection:** [05-suspicious-mfa-registration.md](../detections/05-suspicious-mfa-registration.md)
**MITRE:** T1556.006 — Persistence
**Severity:** High
**Audience:** Solo analyst (no handoff tier — every step assumes you are the only responder)

## Why containment comes before investigation here

Standard IR sequencing often investigates before containing. For this detection, that order is reversed: if the alert is a true positive, the attacker may already have a working MFA method registered. Every minute spent investigating first is a minute the attacker keeps a persistence mechanism that survives a password reset. Revoke first, investigate second.

## Step 1 — Revoke active sessions (do this first, before anything else)

- Entra ID → Users → [affected user] → **Revoke sessions**
- This invalidates existing refresh tokens immediately, forcing re-authentication everywhere.
- Do this even if you haven't yet confirmed the alert is a true positive. A false positive costs the user one re-login. A missed true positive costs persistent attacker access.

## Step 2 — Reset the password

- Entra ID → Users → [affected user] → **Reset password**
- Force a temporary password and require change at next sign-in.

## Step 3 — Remove the suspicious MFA method

- Entra ID → Users → [affected user] → **Authentication methods**
- Identify the method registered around the alert timestamp (cross-reference `RegTime` from the incident).
- Delete that specific method. Do not remove methods the legitimate user registered earlier — confirm timestamps against the incident before deleting anything.

## Step 4 — Confirm the registration timeline with the account owner

- Contact the user (out of band — not over email if email may be compromised) and confirm: did you sign in from [IP/location in the incident] and register a new MFA method around [timestamp]?
- If yes → likely false positive (legitimate device change). Document and close.
- If no / unreachable / unsure → treat as true positive and continue.

## Step 5 — Scope the blast radius

- Check `SignInLogs` for the same `IPAddress` against other UserPrincipalNames in the tenant — is this IP touching other accounts?
- Check `AuditLogs` for other actions taken by this user account in the same session (mailbox rule changes, app consents, role assignments) — MFA registration is rarely the only thing an attacker does once in.

## Step 6 — Document and close

- Add incident comments capturing: timestamp of containment actions, account-owner confirmation outcome, any other accounts/IPs found in scoping.
- Set incident classification (True Positive / False Positive / Benign Positive) based on Step 4.
- Close the incident.

## Notes on the automated first step

The Logic App (`pb-mfa-registration-response`) automatically posts a comment recommending Step 1 the moment the incident is created — but it does not perform the revocation itself. That action requires analyst judgment (confirming this isn't, for example, the account owner's own travel) before taking an action that will lock the user out. Automating the *recommendation* but not the *action* was a deliberate choice for this detection, not a limitation to fix later.
