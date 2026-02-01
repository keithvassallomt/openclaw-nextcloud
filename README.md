# OpenClaw Nextcloud Skill

A Node.js CLI tool for interacting with Nextcloud services including notes, files, calendars, tasks, and contacts.

## Features

- **Notes** - Create, read, update, and delete notes
- **Files** - Upload, download, list, search, and delete files via WebDAV
- **Calendar** - Manage calendar events via CalDAV
- **Tasks** - Create and manage tasks/todos
- **Contacts** - Full contact management via CardDAV

## Prerequisites

- Node.js 20 or higher
- A Nextcloud instance with API access
- An app password for your Nextcloud account

## Installation

```bash
git clone https://github.com/keithvassallomt/openclaw-nextcloud.git
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
Store these values in environment variables, or openclawd.json, or use a .env file.

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
node scripts/nextcloud.js files list --path "Documents/"

# Upload a file
node scripts/nextcloud.js files upload --path "Documents/test.txt" --content "Hello World"

# Download a file
node scripts/nextcloud.js files get --path "Documents/test.txt"

# Search for files
node scripts/nextcloud.js files search --query "report"

# Delete a file
node scripts/nextcloud.js files delete --path "Documents/test.txt"
```

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
| Calendar/Tasks | CalDAV | `/remote.php/dav/calendars/` |
| Contacts | CardDAV | `/remote.php/dav/addressbooks/` |

## Dependencies

- [node-fetch](https://www.npmjs.com/package/node-fetch) - HTTP client
- [fast-xml-parser](https://www.npmjs.com/package/fast-xml-parser) - XML parsing
- [date-fns](https://www.npmjs.com/package/date-fns) - Date formatting

## License

MIT
