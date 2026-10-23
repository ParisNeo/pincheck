# pincheck

A supply-chain **counsellor** for `requirements.txt`. Stdlib only, zero dependencies.

It doesn't just say "bad". For every requirement it tells you what's wrong, which release fixes it, and what to pin.

```
$ pincheck requirements.txt
[VULN] requests==2.19.0  released 3055d ago
    - GHSA-9wx4-h78v-vm56 [MODERATE]: ...  -> fixed in 2.32.0
    - PYSEC-2018-28: ...                   -> fixed in 2.20.0
    advice: Advisories list 2.32.0 as the fix, but that release is yanked... Upgrade to 2.32.2, the next usable release.
[RANGE] click>=8.0  (latest match: 8.5.0)
    note: '>=8.0' doesn't fix a version ... anyone who installed earlier may be running an older version.
    advice: Pin it: click==8.5.0 (the latest release; clean and past the cooldown).

Suggested pins:
    requests==2.32.2
    click==8.5.0
```

## What it checks

| check | source |
|---|---|
| known vulnerabilities, with the **fixed-in version** | [OSV.dev](https://osv.dev) |
| malware (`MAL-*` advisories) | OSV / OpenSSF malicious-packages |
| **cooldown**: release younger than N hours (default 48) | PyPI Simple API (PEP 700 upload time) |
| yanked releases, quarantined projects | PyPI Simple API (PEP 792 project status) |

## Pins vs ranges

- `pkg==1.2.3` is checked exactly. If it's a problem you get the **smallest release that fixes every advisory**
  (skipping yanked, still-vulnerable and too-new releases) plus the newest clean release.
- `pkg>=1.2`, `~=`, `<`, bare names: pincheck assumes the **latest matching release**, checks that, and warns that
  people who installed earlier may be running an older version. It also checks the range's lower bound
  (`>=1.2` allows 1.2 itself) and tells you to raise it if it is vulnerable. It suggests pinning.

## Usage

```
pip install pincheck
pincheck requirements.txt
pincheck base.txt dev.txt --hours 72 --json
pincheck requirements.txt --ignore GHSA-xxxx-xxxx-xxxx
pincheck requirements.txt --strict      # unpinned ranges fail too
pip freeze | pincheck -
```

## Exit codes

| code | meaning |
|---|---|
| 0 | clean (ranges only warn, unless `--strict`) |
| 1 | malware, quarantined project, or release inside the cooldown |
| 2 | vulnerabilities, vulnerable range floor, yanked, unverifiable (or a range with `--strict`) |
| 3 | usage / network error |

## Limits

- A clean OSV result on a brand-new release proves nothing: OSV lags. That is what the cooldown is for.
- "Fixed in" comes from the advisory's version ranges; a fix recorded only as a git commit can't be resolved to a release.
- It checks releases, not the bytes your mirror serves. Use `--require-hashes` for that.
- Direct URL / VCS / editable lines are skipped and listed. PyPI only.

MIT licensed.
