# OpenClaw Nextcloud Skill

A Node.js CLI tool for interacting with Nextcloud services including notes, files, calendars, tasks, contacts, and shares.

## Features

- **Notes** - Create, read, update, and delete notes
- **Files** - Upload, download, list, search, and delete files via WebDAV (including automatic creation of missing directories)
- **Shares** - Create, list, and delete public link shares via the OCS Share API
- **Calendar** - Manage calendar events via CalDAV
- **Tasks** - Create and manage tasks/todos
- **Contacts** - Full contact management via CardDAV

## Prerequisites

- Node.js 20 or higher
- A Nextcloud instance with API access
- An app password for your Nextcloud account

## Installation

```bash
git clone https://github.com/schemann/openclaw-nextcloud.git
cd openclaw-nextcloud
```

The skill is pre-bundled with all dependencies in `scripts/nextcloud.js` - no npm install required.

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

## Configuration

Store these values in environment variables, in `openclawd.json`, or in a `.env` file.

```env
NEXTCLOUD_URL=https://your-nextcloud-instance.com
NEXTCLOUD_USER=your_username
NEXTCLOUD_TOKEN=your_app_password
```

**Generating an App Password:**
1. Log into your Nextcloud instance
2. Go to Settings → Security
3. Under "Devices & sessions", enter a name for the app and click "Create new app password"
4. Copy the generated password to your `.env` file

## Usage

```bash
node scripts/nextcloud.js <command> <subcommand> [options]
```

### Notes

```bash
# List all notes
node scripts/nextcloud.js notes list

# Create a note
node scripts/nextcloud.js notes create --title "My Note" --content "Note content" --category "Personal"

# Get a specific note
node scripts/nextcloud.js notes get --id 123

# Update a note
node scripts/nextcloud.js notes edit --id 123 --title "Updated Title" --content "New content"

# Delete a note
node scripts/nextcloud.js notes delete --id 123
```

### Files

```bash
# List files in a directory
node scripts/nextcloud.js files list --path "Documents/Reports/"

# Upload a file (parent directories will be created automatically)
node scripts/nextcloud.js files upload --path "Documents/Reports/test.txt" --content "Hello World"

# Download a file
node scripts/nextcloud.js files get --path "Documents/Reports/test.txt"

# Search for files
node scripts/nextcloud.js files search --query "report"

# Delete a file
node scripts/nextcloud.js files delete --path "Documents/Reports/test.txt"
```

File listings and search results include the file name, path, type, a `fileId` (if provided by the server), and a locally computed `internalLink` in the format `NEXTCLOUD_URL/index.php/f/<fileId>`.

### Shares (OCS Share API)

```bash
# Create a public link share for a file or folder
node scripts/nextcloud.js shares create-link \
  --path "/Documents/Reports" \
  [--permissions read|edit] \
  [--password "Secret123"] \
  [--expire "2026-04-15"]

# List all shares for the current user
node scripts/nextcloud.js shares list

# List shares for a specific path
node scripts/nextcloud.js shares list --path "/Documents/Reports"

# Delete a share by ID
node scripts/nextcloud.js shares delete --id 29
```

- `--permissions`
  - `read` (default): Read-only access (permission value 1)
  - `edit`: Full access (Nextcloud permissions 15: create/update/delete/share)
- `--password`: Set a password on the link share
- `--expire`: Expiry date in `YYYY-MM-DD` format

The output of `shares create-link` includes:

```json
{
  "id": "29",
  "path": "/Documents/Reports",
  "shareType": 3,
  "permissions": 17,
  "token": "K8XafX9fgk4n3LD",
  "url": "https://cloud.example.com/index.php/s/K8XafX9fgk4n3LD",
  "expireDate": null,
  "passwordProtected": false
}
```

`shares list` returns a list of such objects; `shares delete` returns `{ id, status: 'deleted' }`.

### Calendar

```bash
# List available calendars
node scripts/nextcloud.js calendars list

# List events in a date range
node scripts/nextcloud.js calendar list --from "2026-02-01T00:00:00Z" --to "2026-02-28T23:59:59Z"

# Create an event
node scripts/nextcloud.js calendar create --summary "Team Meeting" --start "2026-02-05T10:00:00Z" --end "2026-02-05T11:00:00Z"

# Update an event
node scripts/nextcloud.js calendar edit --uid event-uid --summary "Updated Meeting"

# Delete an event
node scripts/nextcloud.js calendar delete --uid event-uid
```

### Tasks

```bash
# List all tasks
node scripts/nextcloud.js tasks list

# Create a task
node scripts/nextcloud.js tasks create --title "Buy groceries" --due "2026-02-05T17:00:00Z" --priority 1

# Complete a task
node scripts/nextcloud.js tasks complete --uid task-uid

# Delete a task
node scripts/nextcloud.js tasks delete --uid task-uid
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
node scripts/nextcloud.js contacts edit --uid contact-uid --email "newemail@example.com"

# Delete a contact
node scripts/nextcloud.js contacts delete --uid contact-uid
```

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
| Shares | OCS Share API | `/ocs/v2.php/apps/files_sharing/api/v1` |
| Calendar/Tasks | CalDAV | `/remote.php/dav/calendars/` |
| Contacts | CardDAV | `/remote.php/dav/addressbooks/` |

## Dependencies

- [node-fetch](https://www.npmjs.com/package/node-fetch) - HTTP client
- [fast-xml-parser](https://www.npmjs.com/package/fast-xml-parser) - XML parsing
- [date-fns](https://www.npmjs.com/package/date-fns) - Date formatting

## License

MIT
