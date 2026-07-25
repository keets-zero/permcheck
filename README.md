# PermCheck

A small Chrome extension auditor. Open the popup and it tells you, in plain English,
which of your installed extensions have high access to what you do online —
**verdict first, details on click.**

Built by keets (Baseline Security). Only reads. Sends nothing. Open source.

## What it does

- Lists all installed extensions via `chrome.management` (read-only).
- Gives each extension a verdict — **High / Some / Low access** — and a plain-language
  reason: *"can read and change everything you do on all websites"*, *"can read your
  cookies"*, *"installed in developer mode — not via the Chrome Web Store"*, etc.
- Sorts highest access to the top so the riskiest is visible first.
- Headline verdict up top: *"X of your Y active extensions can read everything you do online."*
- Counts reflect **active** extensions only; disabled ones sit in a muted, collapsible section.

## What it does NOT do

- No network calls. No telemetry. No data leaves your computer.
- Never touches page content, tabs, or files.
- Never changes other extensions — it only reads, never enables/uninstalls.

## The verdict = access level, not "malicious"

An extension can have high access for entirely legitimate reasons (an ad blocker *must*
be able to see all traffic). "High access" means: **this requires trusting the
developer.** PermCheck makes hidden access visible — it doesn't accuse.

## The risk model (short)

Score is built from three things:
1. **Site access** — broad (`<all_urls>`) weighs heavily; specific sites lightly.
2. **Permissions** — critical (`debugger`, `proxy`, `nativeMessaging`) weigh most;
   sensitive (`cookies`, `webRequest`, `history`, `management`, …) weigh more in
   combination with broad site access.
3. **Install type** — sideloaded / developer-installed / installed by another program
   is flagged.

`>=5 -> High`, `2-4 -> Some`, `<2 -> Low`. The model is deliberately conservative so it
doesn't cry wolf. Tune the weights in `popup.js` (`assess`).

## Install (developer mode)

1. `chrome://extensions`
2. Turn on **Developer mode** (top right).
3. **Load unpacked** -> select this folder.
4. Pin PermCheck and click the icon.

## Security

Follows the extension-security standard: MV3, least privilege (the only permission is
`management`), zero dependencies, zero `innerHTML` with dynamic data (extension names
render via `textContent`), no secrets, no remote resources. Fonts (Michroma,
IBM Plex Mono) are SIL OFL-licensed and bundled locally — see `fonts/`.

## License

Code: your choice (MIT recommended for openness). Fonts: SIL OFL, see
`fonts/*-OFL.txt`.
