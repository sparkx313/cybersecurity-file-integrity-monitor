# File Integrity Monitor

A snapshot-based file integrity monitor that records SHA-256 hashes and later reports added, removed, or modified files. It uses only Python's standard library.

## Create a baseline

~~~sh
python file_integrity_sensor.py baseline --directory ./important-files --manifest ./integrity-baseline.json
~~~

## Verify against it

~~~sh
python file_integrity_sensor.py verify --directory ./important-files --manifest ./integrity-baseline.json --report ./verification.json
~~~

Verification exits with status 0 when all scanned files match, status 1 when regular files or skipped-entry types changed, and status 2 on errors or when symlinks/special files make coverage incomplete. The manifest stores relative paths, file sizes, SHA-256 digests, and its creation time.

The baseline is the trust anchor. Keep it outside the monitored directory or protect it separately; an attacker who can rewrite both the files and the baseline can defeat the comparison. This tool compares snapshots and does not watch filesystem events continuously. Symbolic links and special files are recorded by path and type but are not hashed; a verification with any such entries is marked incomplete.