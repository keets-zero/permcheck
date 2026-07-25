# Permission Justifications — PermCheck v0.5.0

| Permission | Why | Feature |
|---|---|---|
| management | Read the list of installed extensions and their permissions (`permissions`, `hostPermissions`, `installType`) to audit them. Read-only (`getAll`, `getSelf`). Never `setEnabled`/`uninstall`. | The entire audit |
| storage | Store a local snapshot of each extension's permissions so the next scan can flag *changes* — a trusted extension that silently gained new access via an update. `chrome.storage.local` only, on-device, never synced or sent anywhere. | Change watch |

Used but requiring NO permission:
- **chrome.tabs.create** — opens Chrome's own `chrome://extensions/?id=<id>` page for one extension (the "Manage in Chrome" button). `create()` needs no permission; we never read tab URLs/titles, so the `tabs` permission is deliberately NOT requested. The extension id is validated (`/^[a-p]{32}$/`) before building the URL.

Considered and deliberately rejected:
- **host_permissions**: none. PermCheck never touches page content.
- **tabs / scripting / activeTab**: none. We don't read tabs or inject code.
- **Network / fetch**: none. No data leaves the computer — the change watch is entirely local, which is the whole point.

Transparency note: `management` is itself a sensitive permission — the same kind PermCheck warns about. That's why it's read-only, there are no network calls, and the source is open for line-by-line review. Stated in the popup footer.
