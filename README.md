# pincheck

Supply-chain gate for `requirements.txt`. Stdlib only, zero dependencies.

For every pinned package (`name==version`) it checks:

1. **Vulnerabilities** — advisories on [OSV.dev](https://osv.dev) for that exact version.
2. **Malware** — OSV `MAL-*` advisories (OpenSSF malicious-packages feed).
3. **Cooldown** — fails if the release is younger than N hours (default 48), so you never install
   something the community hasn't had time to analyse.
4. **Yanked** releases.

```
pip install pincheck
pincheck requirements.txt
pincheck requirements.txt --hours 72 --json
pincheck base.txt dev.txt --ignore GHSA-xxxx-xxxx-xxxx
pip freeze | pincheck -
```

## Exit codes

| code | meaning |
|---|---|
| 0 | clean |
| 1 | malware **or** release younger than cooldown |
| 2 | known vulnerabilities, yanked, or unverifiable release |
| 3 | usage / network error |

## CI

```yaml
- run: pip install pincheck && pincheck requirements.txt --hours 72
```

## Limits

- Only exact pins (`==`) are checked; unpinned lines are listed, not silently passed.
  Check a fully resolved file (`pip-compile`, `uv pip compile`, `pip freeze`) to cover transitive deps.
- A clean OSV result on a brand-new release proves nothing: OSV lags. That is what the cooldown is for.
- It checks the release you pin, not whether your index/mirror serves the same bytes. Use `--require-hashes` for that.
- PyPI only.

MIT licensed.
