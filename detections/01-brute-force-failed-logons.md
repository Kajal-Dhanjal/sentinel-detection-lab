# Detection 1 — Brute-Force Failed Logons

**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
**Tactic:** Credential Access
**Data source:** Windows Security log (Event ID 4625)
**Severity:** Medium

## The threat

An attacker repeatedly attempts to log in with guessed credentials. Each failure writes a Windows **Event ID 4625** (failed logon). A burst of these against one host in a short window is a strong brute-force signal.

## The detection

```kql
Event
| where EventLog == "Security"
| where EventID == 4625
| extend TargetAccount = extract(@"Account For Which Logon Failed:[\s\S]*?Account Name:\s+(\S+)", 1, RenderedDescription)
| where isnotempty(TargetAccount) and TargetAccount != "-"
| summarize FailedAttempts = count(), TargetedAccounts = make_set(TargetAccount) by Computer, bin(TimeGenerated, 5m)
| where FailedAttempts >= 5
```

**Logic:** filter to failed logons → extract the *attacked* account from the event text → count failures per host in 5-minute windows → flag windows with 5+ failures.

## Validation

Simulated a brute-force burst on the lab VM:

```powershell
runas /user:attacker1 cmd   # wrong password
runas /user:attacker2 cmd   # repeated for attacker3..N
```

The detection returned a single row: 25 failed attempts in one 5-minute window, with the attacker usernames captured in `TargetedAccounts`. The scheduled rule then raised an incident automatically (Credential Access category).

## Tuning notes / lessons

- **No clean username column.** The target account lives inside the `RenderedDescription` text blob, not a dedicated field, so it has to be extracted with regex.
- **The first regex match was the wrong account.** A 4625 event contains *two* "Account Name:" lines — the Subject (the process owner) and "Account For Which Logon Failed" (the attacked account). The naive regex grabbed the Subject, reporting the legitimate user instead of the attacker. Fixed by anchoring on "Account For Which Logon Failed:" first.
- **Threshold reflects real attack tempo, not test tempo.** Manual testing produced sparse, slow attempts that didn't trip a tight window. The `>= 5` threshold is correct for a real bot (dozens/min); slow manual tests are a testing artifact, not a reason to lower it.

## Possible improvements

- Group by individual `TargetAccount` to distinguish single-account brute force from password spray.
- Add a follow-on rule: failed-burst *followed by* a successful logon (4624) from the same source — a likely-successful brute force.
