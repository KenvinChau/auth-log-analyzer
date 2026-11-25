# Auth Log Analyzer: write-up

## Goal

I wanted a small, standalone project that is visual, useful beyond security, and quick to explore: a tool that reads an SSH `auth.log` and shows an analyst what happened. It also had to be independent of my other projects, run entirely in the browser, and be easy for someone to try from a link.

## What I built

A React and TypeScript app that parses SSH authentication logs, runs four detection rules (brute-force burst, slow persistent guessing, distributed attack on one account, login after repeated failures), and shows the results as a dashboard. Findings carry a severity and a MITRE ATT&CK technique. A seeded Python script generates the sample log, so every attack in it is planted on purpose and I can check that the tool finds exactly those.

## Design decisions

- **Pure logic, thin UI.** Parsing, detection and statistics are plain functions in `src/lib/` with no React in them, and the components only display data. That is what made the logic easy to test, and I wrote the tests before the code (red, then green).
- **Synthetic data on purpose.** A real log contains real addresses and is not reproducible. A seeded generator gives me a fixed story to test against and no privacy problem.
- **Count attempts once.** An attempt on an unknown user writes two log lines, so the detection rules only count `Failed password` events. Counting both would have doubled every number.
- **Thresholds in one config object.** No rule contains a bare number, so tuning is one edit and the trade-offs are visible.
- **Honest labels.** The card says "IPs with failures", not "attackers", because a legitimate user who mistypes a password also appears there.

## Detection engineering notes

- A test shows that the burst rule misses the slow attacker (one attempt every 5 to 20 minutes). That is why there is a second rule based on volume over time. The test documents the limitation instead of hiding it.
- A legitimate user in the sample mistypes a password 20 minutes before the attack starts. The last test asserts that no finding involves the legitimate IPs, which guards against thresholds that are too loose.
- The thresholds were tuned on synthetic data. On real traffic, shared IPs (NAT) and noisy scanners would need different values, and that is the first thing I would revisit.
- Findings overlap: the slow attacker also shows up in the distributed finding because it tried `root` in the same 30-minute window. The result is correct, but an analyst would want findings grouped per IP.

## Security considerations

Log content is attacker-controlled, so I treated it as untrusted input. The app never injects log text as HTML, a unit test pins down that a hostile username stays plain data, and I checked by hand that `<svg/onload=alert(1)>` renders as text. The deployment also sets a Content-Security-Policy and other headers; the policy allows inline styles because the chart library needs them, which I chose to accept and document.

## Problems I ran into

- **CI failed on its first run.** `npm ci` on Linux stopped with `Missing: @emnapi/core ... from lock file`. My lockfile had been generated on Windows and was missing optional platform packages. `npm install` hides this by repairing the lockfile; `npm ci` is strict on purpose. I regenerated the lockfile and verified it in a clean Node 22 Linux container before pushing.
- **A control that looked broken.** Syslog timestamps have no year, so the app needs one. Changing the year selector appeared to do nothing, because the year was never displayed. I now show the year in the findings and default it from an uploaded file's last-modified date.

## What I would do next

- Group findings per IP so one attacker is one story.
- Move parsing into a web worker so large files do not freeze the page.
- Parse more of the log (`sudo`, PAM) and test IPv6 addresses.
- Validate the thresholds against real, anonymised logs.

## Skills this project exercised

Log parsing with regular expressions, detection engineering and ATT&CK mapping, test-driven development, secure handling of untrusted input, a CI pipeline, and deployment with security headers.
