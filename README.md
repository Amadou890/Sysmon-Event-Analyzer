# 🔎 Sysmon Event Analyzer

A small browser tool that explains suspicious Windows (Sysmon) events in plain English. Paste in an event and it returns severity-rated findings, the matching MITRE ATT&CK technique, and a Splunk query to investigate further.

Companion project to my [Splunk Threat Hunting Lab](https://github.com/Amadou890/Splunk-Threat-Hunting-Lab).

**Live demo:** _[add your GitHub Pages link here after enabling Pages]_

---

## Why I built it

Raw Sysmon events are dense. A Tier-1 analyst has to read a long command line, work out whether it is suspicious, decode anything hidden (like Base64 PowerShell), and decide what to search next. This tool automates that first read so the reasoning is faster and consistent.

## How it works

1. **Paste** an event (Event Viewer text, JSON, or Splunk `key="value"` pairs).
2. **Parse** it into fields: `Image`, `CommandLine`, `ParentImage`, `DestinationIp`, `TargetObject`, and so on.
3. **Check** the fields against a set of detection rules (listed below).
4. **Report** each match with a severity, a plain-English reason, the ATT&CK technique, and a copyable Splunk query. Suggested pivot queries are built from the event's own host, program, and IP.

Everything runs in your browser. No data is sent anywhere, and there are no dependencies.

## Example

Input (synthetic): Microsoft Word starts PowerShell with a hidden window and an encoded command.

Output:
- **High:** Base64-encoded PowerShell, with the decoded script shown
- **High:** Office application spawned a shell or script host (T1204.002)
- **Medium:** PowerShell launched with a hidden window (T1059.001)
- **Low:** PowerShell started without a profile
- Each finding includes a Splunk query to hunt for the same behavior

## What it detects

| Event | Checks |
|:--|:--|
| Sysmon 1 (process creation) | Encoded PowerShell (decoded for you), hidden window, execution policy bypass, download or in-memory execution; Office apps spawning shells; WMI-spawned shells; certutil, bitsadmin, mshta, regsvr32, rundll32, and WMIC abuse; scheduled task creation; `wevtutil` log clearing; shadow copy deletion; local account creation; Run key added with `reg.exe`; common discovery commands; programs run from Temp, AppData, Downloads, or Public |
| Sysmon 3 (network connection) | Suspicious ports (4444, 1337, 31337, 5555, 9001); scripting or download tools connecting to external IPs; internal connections on SMB, RDP, and WinRM ports |
| Sysmon 13 (registry value set) | Run and RunOnce keys; Image File Execution Options changes; Winlogon Shell and Userinit changes |
| Windows 1102 / 104 | Event log cleared |

## How to use it

- **Online:** open the live demo link above.
- **Locally:** download `index.html` and open it in any browser.
- **Try it:** use the sample buttons, or copy an event from `synthetic_samples.txt`. To use real events, run a search in Splunk, view a result as Raw or JSON, and paste one event in.

## Limitations

- **Pattern matching, not a verdict.** A finding is a lead to verify with parent processes, user context, and timing. Legitimate admin activity can trigger rules, and real attackers can avoid them.
- **No match does not mean safe.** It only means none of the built-in checks fired.
- **One event at a time.** It does not scan whole log files.
- **Limited coverage.** Only the event types and patterns listed above.
- **No live lookups.** It does not connect to Splunk or look up IP and domain reputation.
- **Thresholds and patterns are starting points** to tune against your own environment.
- **Splunk queries assume `index=wineventlog`** and standard Sysmon field names. Adjust them for your setup.

## Status

> **Tested on synthetic samples only so far.** _[Update this line after you test with real events, for example: "Also tested on N events from <source>. Findings and fixes noted below."]_

## Samples

`synthetic_samples.txt` contains made-up events for testing. They are not real incidents. IP addresses use the documentation range (203.0.113.0/24) and the domain `example.invalid`.

## Tech

A single HTML file with vanilla JavaScript. No frameworks, no build step, no network requests.

## License

MIT. See `LICENSE`.
