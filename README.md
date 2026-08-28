<p align="center">
  <img width="400" alt="openclaw-nextcloud logo" src="https://github.com/user-attachments/assets/c337351e-4000-4521-b0d5-776f55b95772" />
</p>

# OpenClaw Nextcloud Skill

A Node.js CLI tool for interacting with Nextcloud services including notes, files, calendars, tasks, contacts, and Deck Kanban boards.

## Features

- **Notes** - Create, read, update, and delete notes
- **Files** - Upload, download, list, search, and delete files via WebDAV
- **Calendar** - Manage calendar events via CalDAV
- **Tasks** - Create and manage tasks/todos
- **Contacts** - Full contact management via CardDAV
- **Deck** - Manage Kanban boards, stacks, cards, labels, and comments via the Deck API

## Prerequisites

- Node.js 24 or higher
- A Nextcloud instance with API access
- An app password for your Nextcloud account

## Installation

### OpenClaw

Install the skill from the repository:

```bash
openclaw skills install git:keithvassallomt/openclaw-nextcloud@main
```

The skill also declares `metadata.openclaw.skillKey: openclaw-nextcloud`.
This keeps the configuration and runtime credential-injection key stable
regardless of the source slug or install directory.

### Source checkout

```bash
git clone https://github.com/keithvassallomt/openclaw-nextcloud.git
cd openclaw-nextcloud
```

The skill is pre-bundled with all dependencies in `scripts/nextcloud.js` - no npm install required.

## Upgrading to 0.4.0

**0.4.0 contains a breaking change.** Eleven irreversible operations now refuse
to run unless the command includes a matching `--confirm <command>:<subcommand>`
token:

- `notes delete` → `--confirm notes:delete`
- `files delete` → `--confirm files:delete`
- `tasks delete` → `--confirm tasks:delete`
- `calendar delete` → `--confirm calendar:delete`
- `contacts delete` → `--confirm contacts:delete`
- `boards delete` → `--confirm boards:delete`
- `stacks delete` → `--confirm stacks:delete`
- `cards delete` → `--confirm cards:delete`
- `labels delete` → `--confirm labels:delete`
- `shares delete` → `--confirm shares:delete`
- `shares create-link` → `--confirm shares:create-link`

```bash
# 0.3.0
node scripts/nextcloud.js notes delete --id 123

# 0.4.0
node scripts/nextcloud.js notes delete --id 123 --confirm notes:delete
```

Everything else is unchanged — all reads, all creates, and every `edit`, plus
`files upload`, `cards move` and `cards comment-delete`, work exactly as before.

Agents pick this up automatically, since `SKILL.md` ships alongside the bundle
and is read on invocation. **Shell scripts and cron jobs that call the eleven
commands above will break until the token is added**, as they never re-read
`SKILL.md`.

Also in 0.4.0: text and secrets can be supplied from a file instead of the
command line (`--content-file`, `--description-file`, `--note-file`,
`--message-file`, `--password-file`), keeping them out of the process argument
list where `ps` can read them. Prefer `--password-file` for share passwords.

## Development

The project uses a bundled architecture:

- **`index.js`** - Source code (edit this)
- **`scripts/nextcloud.js`** - Bundled output with all dependencies (run this)

To make changes:

```bash
npm install              # Install dev dependencies (first time only)
# Edit index.js
npm run build            # Bundle into scripts/nextcloud.js
```

Both files should be committed - the bundle allows users/agents to run the skill without npm install.

With [Nix](https://nixos.org/), a `flake.nix` provides the toolchain (Node.js + esbuild):

```bash
nix shell .#default --command npm install
nix shell .#default --command npm run build
```

### Packaging a submission

`npm run package` collects the six files a ClawHub submission needs —
`SKILL.md`, `README.md`, `index.js`, `package.json`, `package-lock.json` and
`scripts/nextcloud.js` — into `~/Downloads/openclaw-nextcloud`, leaving the
tests, CI config, flake and git metadata behind.

```bash
npm run package                     # -> ~/Downloads/openclaw-nextcloud
npm run package -- --out /tmp       # -> /tmp/openclaw-nextcloud
npm run package -- --force          # replace an existing folder
```

It refuses to run if `scripts/nextcloud.js` does not match a fresh build of
`index.js`, so a stale bundle cannot reach a submission; `--skip-verify`
overrides that.

## Configuration

For an OpenClaw installation, configure the non-secret values under the
canonical skill key:

```bash
openclaw config set \
  skills.entries.openclaw-nextcloud.env.NEXTCLOUD_URL \
  https://your-nextcloud-instance.com
openclaw config set \
  skills.entries.openclaw-nextcloud.env.NEXTCLOUD_USER \
  your_username
```

Save the app password through **Control UI → Skills → openclaw-nextcloud →
Save key**. OpenClaw stores it as the skill's `apiKey` and injects it as
`NEXTCLOUD_TOKEN` only for agent runs. Prefer a supported OpenClaw SecretRef
when managing credentials outside the Control UI. Do not put the app password
in prompts, shell history, examples, or logs.

For direct CLI use outside OpenClaw, provide the same values as environment
variables:

```env
NEXTCLOUD_URL=https://your-nextcloud-instance.com
NEXTCLOUD_USER=your_username
NEXTCLOUD_TOKEN=your_app_password
NEXTCLOUD_EMAIL=you@example.com   # optional, see below
```

`NEXTCLOUD_EMAIL` is optional. When set, `calendar create` marks the account as
the event's organiser and as an attendee who has already accepted, so clients
show the event as confirmed rather than as an invitation awaiting a reply. Left
unset, events are written exactly as they were before the option existed.

**Generating an App Password:**
1. Log into your Nextcloud instance
2. Go to Settings → Security
3. Under "Devices & sessions", enter a name for the app and click "Create new app password"
4. Save the generated password as described above

### Verify runtime injection

First confirm that OpenClaw considers the skill ready:

```bash
openclaw skills info openclaw-nextcloud
```

Then perform a read-only agent check. The check should inspect presence only,
must not read configuration files, and must never print credential values:

```bash
openclaw agent --agent main --message \
  "Without reading config files or printing values, report whether NEXTCLOUD_URL, NEXTCLOUD_USER, and NEXTCLOUD_TOKEN are present. If all are present, use the Nextcloud skill to list calendars only. Make no changes."
```

If readiness succeeds but the agent reports missing variables, verify that the
installed skill resolves to `skillKey: openclaw-nextcloud` and that the config
entry uses `skills.entries.openclaw-nextcloud`.

## Usage

```bash
node scripts/nextcloud.js <command> <subcommand> [options]
```

Irreversible deletes and public-share operations require an action-specific
confirmation token such as `--confirm notes:delete`. Add that token only after
confirming the exact operation and target with the user.

Sensitive or multiline values can be read from files so they do not appear in
the process argument list. Use `--content-file`, `--description-file`,
`--note-file`, `--message-file`, or `--password-file` in place of the matching
inline flag. Each inline/file pair is mutually exclusive.

### Notes

```bash
# List all notes
node scripts/nextcloud.js notes list

# Create a note
node scripts/nextcloud.js notes create --title "My Note" --content "Note content" --category "Personal"

# Get a specific note
node scripts/nextcloud.js notes get --id 123

# Update a note with inline content
node scripts/nextcloud.js notes edit --id 123 --title "Updated Title" \
  --content "Updated note content"

# Or read the content from a file
node scripts/nextcloud.js notes edit --id 123 \
  --content-file "/secure/input/note.txt"

# Delete a note
node scripts/nextcloud.js notes delete --id 123 --confirm notes:delete
```

### Files

```bash
# List files in a directory
node scripts/nextcloud.js files list --path "Documents/"

# Upload inline content (parent directories are created automatically if missing)
node scripts/nextcloud.js files upload --path "Documents/Reports/test.txt" \
  --content "Report contents"

# Or read the content from a file
node scripts/nextcloud.js files upload --path "Documents/Reports/test.txt" \
  --content-file "/secure/input/test.txt"

# Download a file
node scripts/nextcloud.js files get --path "Documents/test.txt"

# Search for files
node scripts/nextcloud.js files search --query "report"

# Delete a file
node scripts/nextcloud.js files delete --path "Documents/test.txt" \
  --confirm files:delete
```

`files list` and `files search` results include a `fileId` (when the server returns one) and a synthesized `internalLink` like `<NEXTCLOUD_URL>/index.php/f/<fileId>` that opens the file directly in the Nextcloud web UI.

### Shares (public links)

```bash
# Create a public link share for a file or folder
node scripts/nextcloud.js shares create-link --path "/Documents/Reports" \
  --permissions read \
  --password "share-password" \
  --expire "2026-04-15" \
  --confirm shares:create-link

# Or keep the password out of the process argument list
node scripts/nextcloud.js shares create-link --path "/Documents/Reports" \
  --password-file "/secure/input/share-password" \
  --confirm shares:create-link

# List all shares
node scripts/nextcloud.js shares list

# List shares for a specific path
node scripts/nextcloud.js shares list --path "/Documents/Reports"

# Delete a share by ID
node scripts/nextcloud.js shares delete --id 29 --confirm shares:delete
```

`--permissions read` (default) is read-only; `--permissions edit` grants create/read/update/delete on the shared resource. `--password`, `--password-file`, and `--expire` are optional. Prefer `--password-file`; a single final newline is removed before the password is sent.

### Calendar

```bash
# List available calendars
node scripts/nextcloud.js calendars list

# List events in a date range
node scripts/nextcloud.js calendar list --from "2026-02-01T00:00:00Z" --to "2026-02-28T23:59:59Z"

# Create an event (with optional location)
node scripts/nextcloud.js calendar create --summary "Team Meeting" --start "2026-02-05T10:00:00Z" --end "2026-02-05T11:00:00Z" --location "Conference Room B"

# Update an event
node scripts/nextcloud.js calendar edit --uid event-uid \
  --summary "Updated Meeting" \
  --location "Zoom"

# Delete an event
node scripts/nextcloud.js calendar delete --uid event-uid \
  --confirm calendar:delete
```

`--calendar` and `--addressbook` accept the display name (case-insensitive),
the URL slug, or the full collection URL — so all of `Personal`, `personal`,
and `/remote.php/dav/calendars/<user>/personal/` resolve to the same calendar.
Date inputs accept either ISO 8601 (`2026-02-05T10:00:00Z`) or the compact
CalDAV form (`20260205T100000Z`). For tasks, a date with no time of day
(`2026-02-05`) means all day; a task's `--start` and `--due` must both be
all-day dates or both carry a time.

### Tasks

```bash
# List all tasks
node scripts/nextcloud.js tasks list

# Create a task with all optional metadata
node scripts/nextcloud.js tasks create --title "Buy groceries" \
  --due "2026-02-05T17:00:00Z" --priority 1 \
  --start "2026-02-04T09:00:00Z" --location "Supermarket" \
  --url "https://example.com" --class PRIVATE --tags "errands,shopping"

# Update a task, including status and percent-complete
node scripts/nextcloud.js tasks edit --uid task-uid --status IN-PROCESS --percent-complete 50

# Clear a task's metadata by passing an empty value
node scripts/nextcloud.js tasks edit --uid task-uid --tags "" --location "" --url ""

# Complete a task
node scripts/nextcloud.js tasks complete --uid task-uid

# Delete a task
node scripts/nextcloud.js tasks delete --uid task-uid --confirm tasks:delete
```

### Contacts

```bash
# List address books
node scripts/nextcloud.js addressbooks list

# List all contacts
node scripts/nextcloud.js contacts list

# Search contacts
node scripts/nextcloud.js contacts search --query "john"

# Create a contact
node scripts/nextcloud.js contacts create --name "John Doe" --email "john@example.com" --phone "+1234567890"

# Get a specific contact
node scripts/nextcloud.js contacts get --uid contact-uid

# Update a contact
node scripts/nextcloud.js contacts edit --uid contact-uid \
  --email "newemail@example.com"

# Delete a contact
node scripts/nextcloud.js contacts delete --uid contact-uid \
  --confirm contacts:delete
```

### Deck (Kanban)

```bash
# List boards
node scripts/nextcloud.js boards list

# Create a board
node scripts/nextcloud.js boards create --title "Sprint" --color 0082c9

# Show a board with its stacks and labels
node scripts/nextcloud.js boards get --board 6

# List stacks (columns) with their cards nested
node scripts/nextcloud.js stacks list --board 6

# Create a stack (column)
node scripts/nextcloud.js stacks create --board 6 --title "To do"

# Create a card
node scripts/nextcloud.js cards create --board 6 --stack 15 --title "Buy LED ring" --description "5.8cm - 8cm"

# List cards on a board (optionally within one stack)
node scripts/nextcloud.js cards list --board 6 --stack 15

# Edit a card (rename, set due date, mark done)
node scripts/nextcloud.js cards edit --board 6 --stack 15 --card 73 \
  --title "Buy LED ring (8cm)" \
  --done true

# Move a card to another stack
node scripts/nextcloud.js cards move --board 6 --stack 15 --card 73 \
  --to-stack 17

# Labels: create on a board, then assign/remove on a card
node scripts/nextcloud.js labels create --board 6 --title "Urgent" --color FF0000
node scripts/nextcloud.js cards assign-label --board 6 --stack 17 --card 73 --label 41
node scripts/nextcloud.js cards remove-label --board 6 --stack 17 --card 73 --label 41

# Card comments (card ids are globally unique)
node scripts/nextcloud.js cards comment-add --card 73 --message "Ordered today"
node scripts/nextcloud.js cards comment-list --card 73

# Delete a card
node scripts/nextcloud.js cards delete --board 6 --stack 17 --card 73 \
  --confirm cards:delete
```

Deleting a board (`boards delete --board <id>`) is a soft-delete on the Nextcloud side; the board stops appearing in `boards list` and is purged by the server.

## Output Format

All commands return JSON output:

```json
{
  "status": "success",
  "data": [...]
}
```

On error:

```json
{
  "status": "error",
  "message": "Error description"
}
```

## API Protocols

This tool uses the following Nextcloud APIs:

| Service | Protocol | Endpoint |
|---------|----------|----------|
| Notes | REST | `/index.php/apps/notes/api/v1/notes` |
| Files | WebDAV | `/remote.php/dav/files/` |
| Calendar/Tasks | CalDAV | `/remote.php/dav/calendars/` |
| Contacts | CardDAV | `/remote.php/dav/addressbooks/` |
| Shares | OCS | `/ocs/v2.php/apps/files_sharing/api/v1/shares` |
| Deck | REST | `/index.php/apps/deck/api/v1.1/` |

## Dependencies

- [fast-xml-parser](https://www.npmjs.com/package/fast-xml-parser) - XML parsing
- [date-fns](https://www.npmjs.com/package/date-fns) - Date formatting

HTTP requests use Node's built-in `fetch`; there is no HTTP client dependency.

## Security & Trust

This skill executes a bundled JavaScript file (`scripts/nextcloud.js`) on your machine and is given a credential for your Nextcloud account. Because that's a non-trivial trust ask, here's what the skill does and how you can verify it:

**What it can access**

- The Nextcloud instance at `NEXTCLOUD_URL` — no other endpoints. There is no telemetry, no analytics, no auto-update, no third-party calls. You can confirm this by `grep -E 'fetch\(|http[s]?://' scripts/nextcloud.js`; every URL is built from `CONFIG.url` (i.e. `NEXTCLOUD_URL`) or relative API paths.
- The environment variables `NEXTCLOUD_URL`, `NEXTCLOUD_USER`, `NEXTCLOUD_TOKEN`, and two optional ones: `NEXTCLOUD_EMAIL` (an address written into events you create, see [Configuration](#configuration)) and `OPENCLAW_ALLOW_HTTP` (the plaintext-HTTP opt-out). No other env vars are read; `grep -o 'process\.env\.[A-Z_]*' index.js` lists them.
- No filesystem access beyond the Node module loader and the standard `fs` for reading inputs you pass it.

**Credentials**

- Always use a Nextcloud **app password** (Settings → Security → "Devices & sessions"), not your account password. App passwords have account-level scope but can be revoked individually from the Nextcloud UI.
- The token is sent as a Basic Auth header to the configured Nextcloud instance. **The script enforces HTTPS for `NEXTCLOUD_URL`** at startup and refuses to run over plain `http://` (except `localhost`/`127.0.0.1`/`[::1]` for local development). The check can be overridden with `OPENCLAW_ALLOW_HTTP=1`, but this is strongly discouraged outside isolated dev environments.

**Static analysis**

A static analyser scanning this skill will likely flag rules in the family of `suspicious.env_credential_access` — code that reads an environment variable and then makes a network call. That signal is **expected**: every authenticated API client matches it, including this one. The pattern is constrained as follows, and these constraints are what to audit:

- The credential is read from `NEXTCLOUD_TOKEN` only. No other env var is consulted for credential material.
- The credential is sent only to URLs derived from `NEXTCLOUD_URL`. There are no hard-coded hosts in the source (`grep -E 'http[s]?://' index.js` returns nothing).
- HTTPS is enforced at startup (see above), so the credential cannot be sent in cleartext without an explicit opt-in.
- There is no telemetry, analytics, auto-update, or third-party callback. The script makes one outbound destination — your Nextcloud — and exits.

**Supply chain**

Automated skill scanners commonly report three findings against this repository. All three are accurate observations; here is what each one is actually pointing at.

- **Unpinned dependencies.** The two runtime dependencies and the one build dependency are now pinned to exact versions in `package.json`, with `package-lock.json` (lockfile v3) carrying an integrity hash for every resolved package. Note that none of this is in the install path for end users: the skill ships pre-bundled, so nothing is resolved or downloaded when you run it.
- **External script fetching.** No part of this skill fetches code. The source contains no `eval`, no `new Function`, no dynamic `import()`, no `child_process`, and no hard-coded hosts — every request is built from `NEXTCLOUD_URL`. What a scanner is seeing is `esbuild`'s `postinstall`, which downloads a platform binary from `registry.npmjs.org`. That is a *build* dependency: it never runs for end users, and CI installs with `npm ci --ignore-scripts` so it does not run there either. The bundle is byte-identical with the script suppressed.
- **Obfuscated code.** `scripts/nextcloud.js` is 19,000+ lines of ordinary formatted JavaScript, averaging under 40 characters per line, and is not minified, packed, or encoded. It is large because dependency source is vendored into it — that is what makes the no-install promise possible. Rather than take that on trust, verify it: the reproduction steps below rebuild it from source, and CI fails the build if the committed bundle differs from a fresh one.

**Auditing the bundle**

`scripts/nextcloud.js` is the output of running `esbuild` over `index.js` plus the two declared dependencies. To verify the bundle matches the source:

```bash
npm ci --ignore-scripts
npm run build
git diff scripts/nextcloud.js   # should report no changes
```

If the diff is non-empty, the committed bundle does not match the source — please open an issue.

**Reducing privilege**

- Run on a per-user basis; no `sudo` is required or appropriate.
- For first-time evaluation, point `NEXTCLOUD_URL` at a throwaway test account.
- Treat `NEXTCLOUD_TOKEN` like any other credential: don't commit it, don't paste it into shared chats, and rotate it on any suspicion of compromise.

## Contributors

Thanks to:

- [@schemann](https://github.com/schemann) — `fileId` / `internalLink` on file listings, auto-MKCOL on upload, public-link shares (`shares list` / `create-link` / `delete`).
- [@KssimiClaw](https://github.com/KssimiClaw) — fix for `files search` 501 by routing the WebDAV `SEARCH` request to the DAV root.
- [@makefu](https://github.com/makefu) — Kanban Boards support.
- [@bolinches](https://github.com/bolinches) — fix for secondary calendars advertising multiple component types being dropped from event/task operations, and vCard 3.0 group prefix handling (`item1.EMAIL`, `item2.TEL`) in the contact parser.
- [@sam2kb](https://github.com/sam2kb) — security review and the fixes behind 0.4.0: WebDAV path traversal, iCalendar/vCard value escaping and unescaping, `PRIORITY` injection, confirmation tokens for irreversible operations, file-backed text and secret inputs, `skillKey` config stability, and the project's first test suites.
- [@kens-agents](https://github.com/kens-agents) — fix for `tasks list` hiding tasks created in the Nextcloud Tasks web app, which omit `STATUS`: per RFC 4791 §3.6.4 the CalDAV `prop-filter` only matched VTODOs that declare the property; and fix for Deck `boards`/`stacks`/`cards`/`labels` `delete` returning 403 without a JSON content type on the request. Discovered and reproduced by [@kendawson-online](https://github.com/kendawson-online).

## License

MIT
