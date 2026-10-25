# CVE targets

CVE ground truth is not written by hand. For each CVE the manifest pins the
upstream fix commit, and `vulnscan.groundtruth` derives two entries from
`git diff --unified=0 <fix>^ <fix>`:

- `<cve>@vuln` (vulnerable): the lines the fix removed or changed, in the
  version before the fix. A finding of the CVE's CWE family on one of those
  lines counts as a detection.
- `<cve>@fixed` (safe): the lines the fix added or changed, in the patched
  version. A finding of the same family there is a false positive on patched
  code.

CVE ground truth only knows the fixed lines, so it is marked non-exhaustive:
other findings in the same files are reported as unlabelled, not as false
positives.

## Selection

Candidates came from the GitHub Advisory Database (`gh api /advisories`),
filtered to reviewed PHP (composer) and Python (pip) advisories for CWE-78,
CWE-89 and CWE-22 that link a fix commit. From those, we kept fixes that touch
one or two files of an application, so that `scan_paths` can stay narrow.

| Target | CVE | CWE | Fix commit | Fix size | Notes |
| --- | --- | --- | --- | --- | --- |
| pheditor | CVE-2026-48030 | CWE-78 | 62b43df | 1 line in `pheditor.php` | `$dir` was concatenated into `shell_exec`; the fix wraps it in `escapeshellarg`. `$command` still reaches the same call by design (it is a web terminal), so the patched line stays tainted. |
| yeswiki | CVE-2026-52775 | CWE-89 | 90ca54f | 1 line in `includes/services/ReactionManager.php` | user, reaction and id values concatenated into a `LIKE` clause; the fix escapes them. The values arrive as method parameters, so intra-procedural taint cannot see the source. |
| raspap | CVE-2026-24788 | CWE-78 | f514f5a | `includes/locale.php` rewritten (57+/89-) | `Accept-Language` and `$_POST['locale']` reached `putenv("LANG=...")`; the fix allowlists locales. `putenv` is not a sink in any rule set used here. |
| wsgidav | CVE-2026-55509 | CWE-89 | 6f35776 | `wsgidav/samples/mysql_dav_provider.py` (44+/96-) | table and key names from WebDAV paths concatenated into MySQL queries. The values come from the DAV provider API, not a web-framework request object. |
