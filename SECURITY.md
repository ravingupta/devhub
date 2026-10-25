# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through GitHub: go to the repository's **Security** tab →
**Report a vulnerability** ([direct link](https://github.com/ravingupta/devhub/security/advisories/new)).
Include what you found, how to reproduce it, and the impact you expect.

You can expect an acknowledgement within a few days. Once a fix is ready, it is released
and the advisory is published with credit to you (unless you'd rather stay anonymous).

## Supported versions

devhub is developed on the `main` branch; fixes land there. Please make sure you can
reproduce the problem on the latest `main` before reporting.

## Handling your own secrets

devhub never needs your credentials committed to the repository. If you accidentally
commit a key, rotate it immediately; removing it from history is not enough.
