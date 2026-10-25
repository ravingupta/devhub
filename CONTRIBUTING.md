# Contributing to devhub

Thanks for your interest! Bug reports, ideas, docs fixes and code are all welcome.

## Ground rules

- Be kind. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Security problems go through [private reporting](SECURITY.md), not public issues.
- Never include API keys, tokens, certificates or private paths in issues, screenshots or commits.

## Ways to help

- **Report a bug** or **suggest a feature** with the [issue templates](../../issues/new/choose).
- Look for issues labelled [`good first issue`](../../labels/good%20first%20issue) or
  [`help wanted`](../../labels/help%20wanted).
- Improve project discovery: it recognises a fixed list of frameworks (`NODE_FRAMEWORKS`,
  `PY_FRAMEWORKS` and `detect_python()` in `devhub.py`). Support for more stacks (Rails, Go, Rust, Bun,
  Deno, PHP...) is a great first contribution.
- Linux support: scanning uses `lsof`, `ps` and macOS `sysctl` for process arguments. A `/proc`
  backend would make devhub work on Linux.

## Development setup

devhub is a single Python file with no dependencies (Python 3.10+, macOS).

```sh
git clone https://github.com/ravingupta/devhub && cd devhub

# run a throwaway instance next to (or instead of) the installed one
mkdir -p /tmp/devhub-dev
echo '{"port": 8899, "roots": ["~/Documents", "~/Developer"]}' > /tmp/devhub-dev/config.json
DEVHUB_HOME=/tmp/devhub-dev python3 devhub.py serve
# → http://localhost:8899

DEVHUB_HOME=/tmp/devhub-dev python3 devhub.py discover   # dry run of discovery
```

`dashboard.html` is read from disk on every request, so UI changes show up on reload.

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Fork the repo and create a branch: `git checkout -b fix/short-description`.
3. Keep the style of the surrounding code: standard library only, small functions, comments that
   explain *why*.
4. Check it works:
   - `python3 -m py_compile devhub.py`
   - run a dev instance (above) and try the change in a browser, including at phone width
   - for proxy changes, test at least one Vite or Next.js app through both `/<name>/` and the subdomain
5. Commit with a clear message (`fix: proxy drops websocket on 101 without headers`) and open a pull
   request using the template. CI runs a smoke test on macOS.

## Releases

`main` is always the latest version. Notable changes are listed in the release notes on GitHub.

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
