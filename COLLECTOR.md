# Technician package collector

The collector is a separate Windows executable with a local Turkish browser
interface. Technicians search the official VS Code Marketplace, inspect package
identity and the Verified publisher badge, choose a folder, and download.
Dependencies and extension-pack members are resolved automatically. It does not
install extensions or change the offline marketplace's admission policy.

```powershell
go build -trimpath -ldflags "-s -w -H=windowsgui" -o bin/CodeMarketplace-Toplayici.exe ./cmd/collector
```

Double-click the executable. It starts an HTTP server bound to a free loopback
port and opens the default browser. Use **Programı kapat** to stop it. No Node.js,
Python, Java, Docker, administrator privileges, or package-manager installation
is needed to run the collector. Internet access to Marketplace and its official
asset hosts is needed for searching and collection.

Each download creates a new child folder under the chosen destination:

- `incoming/`: original VSIX, matching `.sigzip`, signed `.publisher.json`.
- `batch-report.json`: exact selections, automatic dependencies, failures, and
  resolved package identities, hashes, platform, publisher and validity.
- `publisher-policy-allowlist.json`: public collector key and observed publishers.
- `extensions.yaml`: exact version/platform selection for recollection.
- `SHA256SUMS` and `README.txt`: transfer integrity and operator instructions.

The default is the latest stable Windows x64 release, with universal fallback.
Built-in `vscode.*` extensions are provided by the editor. Cycles and repeated
dependencies are deduplicated; a batch is limited to 250 packages. Only one job
runs at a time. Cancellation and partial failure preserve completed packages.
Known old Pivotal identifiers add VMware counterparts and retain an explicit
report warning, since original signed extension packs cannot be rewritten.

Verified is the Marketplace publisher's domain-verification badge, not a malware
scan. Collection checks package identity, VSIX structure, signature archive and
digest matching. It does not perform cryptographic certificate trust validation
or a sandbox scan; installation and offline admission retain their own checks.

## Workstation configuration

Technicians do not see signing-key, dependency, platform, or policy controls.
Administrator flags are available for managed deployment:

```powershell
bin/CodeMarketplace-Toplayici.exe --signing-key C:/secure/collector-private.pem --key-id collector-2026 --output-dir C:/packages
```

With no supplied key, a persistent Ed25519 collector key is created in
`os.UserConfigDir()/CodeMarketplaceCollector` (normally `%APPDATA%` on Windows).
The dedicated directory receives a protected Windows ACL for the current account
and SYSTEM; inherited shared-folder permissions are removed. `--data-dir` must
therefore name a dedicated application configuration folder, never a general
shared, home, or download directory. External `--signing-key` files must already
be protected by their administrator. Exports contain only the public key. Provision the
public key into the offline importer's trusted policy once per workstation, or
pre-provision the organization's existing trusted collector key. Publisher
observations are valid for seven days. Existing publisher allowlists and sandbox
policy remain independently enforced; a successful download does not guarantee
production admission. See [PUBLISHERS.md](PUBLISHERS.md) and [SANDBOX.md](SANDBOX.md).

Other administrator flags: `--data-dir`, `--target-platform`, `--address`, and
`--no-open`. Binding to non-loopback interfaces is rejected. Every API request,
including session reads, needs a random per-launch bearer capability. The EXE
opens a URL fragment, clears it from the current history entry, and retains it in
the tab's session storage so refresh works. The public page does not contain it.
`current-url.txt` is saved only inside the protected configuration directory;
treat it as a credential and do not share it. Browser writes additionally need
the exact same Origin and a separate CSRF token. Host checks, cross-site request
rejection, CSP, and frame restrictions remain enforced. Keys and credentials are
never exported in transfer packages. The API contract is
[collector.yaml](postman/specs/collector.yaml).

Marketplace assets and redirects require HTTPS on the default TLS port and an
official Marketplace/CDN hostname. Download and metadata sizes are bounded;
packages are never executed or extracted onto the workstation. Output writes use
directory-confined staging and no-replace publication for package files. On
Windows the final rename operates on the open file handle, including on disks
without hard-link support. A private configuration directory on a filesystem
that cannot enforce its ACL is rejected.

## Verification

```powershell
go test ./...
postman collection lint "postman/collections/Collector Smoke"
postman collection run "postman/collections/Collector Smoke" -e <private-local-session-environment.json> --no-report-events
go run golang.org/x/vuln/cmd/govulncheck@latest ./cmd/collector
```

The smoke collection targets `http://127.0.0.1:38117`; use `--address
127.0.0.1:38117 --no-open` during testing or override its `baseUrl` variable. Supply
`accessToken` through an uncommitted private environment from that launch's URL
fragment; never put a token in a collection or a command-line argument. The smoke
run checks that unauthenticated session reads return 401 before authenticated
reads, invalid selections and unknown-job behavior. The toolchain directive pins
Go 1.27.4 for this release; vulnerability checks must be repeated for future builds.

Windows E2E on 2026-11-05 covered a native selection with spaces and Turkish
characters, cancellation preserving the previous choice, a real Docker download
with automatic Container Tools collection into that folder, opening the output
in Explorer, and retaining the destination after a process restart and browser
refresh. Hidden-process launch also opens a visible folder picker.

To exercise the actual collector against a local Marketplace stand-in:

```powershell
postman simulation run postman/simulations/collector-marketplace.sim.yaml --port 38118 --no-history --output ndjson
```

In another shell, run the test to load the synthetic fixtures into the mock:

```powershell
$env:COLLECTOR_SIMULATION_URL = 'http://127.0.0.1:38118/marketplace'
go test ./collector -run TestCollectorAgainstPostmanSimulation -v
```

Tests cover search, recursive collection with duplicate/cyclic dependencies,
offline importer compatibility, invalid signatures, upstream failure, cancellation,
CSRF/Origin/Host restrictions, and persistent keys. Simulation signatures are
synthetic test fixtures, not trusted Microsoft signatures. The HTTP transport
rewrite exists only in the Go test and does not add an arbitrary upstream option
to the shipped executable. A live Docker/Container Tools collection additionally
checks the real Marketplace path.
