import http from 'node:http';
import { spawn } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const bundle = join(repoRoot, 'scripts', 'nextcloud.js');
const requests = [];

const calendarDiscovery = `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Personal</d:displayname>
      <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
      <cal:supported-calendar-component-set>
        <cal:comp name="VEVENT"/><cal:comp name="VTODO"/>
      </cal:supported-calendar-component-set>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

const addressBookDiscovery = `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/remote.php/dav/addressbooks/users/tester/contacts/</d:href>
    <d:propstat><d:prop>
      <d:displayname>Contacts</d:displayname>
      <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

const groupedContactReport = `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/remote.php/dav/addressbooks/users/tester/contacts/grouped.vcf</d:href>
    <d:propstat><d:prop>
      <d:getetag>"grouped"</d:getetag>
      <card:address-data>BEGIN:VCARD
VERSION:3.0
UID:grouped
FN:Grouped\\, Contact
N:Smith\\;Jones;John;;;
item1.EMAIL;TYPE=work:grouped@example.com
item2.TEL:+15551234567
END:VCARD</card:address-data>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

const eventReport = `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/event.ics</d:href>
    <d:propstat><d:prop>
      <d:getetag>"event"</d:getetag>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:event-1
SUMMARY:Quarterly\\, Review
DESCRIPTION:Line one\\nLine two
LOCATION:Room\\; 2
DTSTART:20260728T120000Z
DTEND:20260728T130000Z
END:VEVENT
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

const todoReport = `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/task.ics</d:href>
    <d:propstat><d:prop>
      <d:getetag>"task"</d:getetag>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VTODO
UID:task-1
SUMMARY:Call Alice\\, Bob
DESCRIPTION:First line\\nSecond line
STATUS:NEEDS-ACTION
DUE:20260730T120000Z
PRIORITY:5
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/web.ics</d:href>
    <d:propstat><d:prop>
      <d:getetag>"web"</d:getetag>
      <cal:calendar-data>BEGIN:VCALENDAR
PRODID:-//Nextcloud Tasks v0.18.1
BEGIN:VTODO
UID:task-no-status
SUMMARY:Created in the web UI
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/done.ics</d:href>
    <d:propstat><d:prop>
      <d:getetag>"done"</d:getetag>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VTODO
UID:task-completed
SUMMARY:Already finished
STATUS:COMPLETED
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/mentions.ics</d:href>
    <d:propstat><d:prop>
      <d:getetag>"mentions"</d:getetag>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VTODO
UID:task-mentions-status
SUMMARY:Audit the tracker
DESCRIPTION:remember to set STATUS:COMPLETED
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/delegated.ics</d:href>
    <d:propstat><d:prop>
      <d:getetag>"delegated"</d:getetag>
      <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VTODO
UID:task-request-status
SUMMARY:Delegated and finished
REQUEST-STATUS:2.0;Success
STATUS:COMPLETED
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

// A task as the Nextcloud Tasks web UI stores it: local times pinned by a
// VTIMEZONE whose DST rules carry DTSTART lines of their own, and a VALARM with
// its own SUMMARY and DESCRIPTION, both ahead of the task's.
const timezoneTodo = `BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Nextcloud Tasks v0.18.1
BEGIN:VTIMEZONE
TZID:Europe/Malta
BEGIN:DAYLIGHT
TZOFFSETFROM:+0100
TZOFFSETTO:+0200
DTSTART:19700329T020000
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
END:DAYLIGHT
BEGIN:STANDARD
TZOFFSETFROM:+0200
TZOFFSETTO:+0100
DTSTART:19701025T030000
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
END:STANDARD
END:VTIMEZONE
BEGIN:VTODO
UID:task-timezone
BEGIN:VALARM
ACTION:DISPLAY
SUMMARY:Alarm summary
DESCRIPTION:Alarm description
TRIGGER:-PT15M
END:VALARM
SUMMARY:Timezoned task
STATUS:NEEDS-ACTION
DTSTART;TZID=Europe/Malta:20260901T090000
DUE;TZID=Europe/Malta:20260930T170000
END:VTODO
END:VCALENDAR`;

// An all-day task: DUE is a DATE, so a DTSTART beside it has to be one too.
const allDayTodo = `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VTODO
UID:task-allday
SUMMARY:All-day task
STATUS:NEEDS-ACTION
DUE;VALUE=DATE:20260828
END:VTODO
END:VCALENDAR`;

// Metadata to clear, including a URL folded across two lines the way a server
// returns one longer than 75 octets.
const metadataTodo = `BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VTODO
UID:task-metadata
SUMMARY:Task with metadata
STATUS:NEEDS-ACTION
LOCATION:Old office
URL:https://example.com/a/very/long/path/that/a/server/would/fold/across/two/
 lines?query=1
CATEGORIES:work,urgent
END:VTODO
END:VCALENDAR`;

function todoResponse(name, calendarData) {
  return `  <d:response>
    <d:href>/remote.php/dav/calendars/tester/personal/${name}.ics</d:href>
    <d:propstat><d:prop>
      <d:getetag>"${name}"</d:getetag>
      <cal:calendar-data>${calendarData}</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
`;
}

function todoMultistatus(body) {
  return `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
${body}</d:multistatus>`;
}

const timezoneTodoReport = todoMultistatus(todoResponse('timezone', timezoneTodo));
const allDayTodoReport = todoMultistatus(todoResponse('allday', allDayTodo));
const metadataTodoReport = todoMultistatus(todoResponse('metadata', metadataTodo));

// The timezoned task is in the list report too, so `tasks list` is exercised
// against a VCALENDAR that carries DTSTART lines outside the VTODO.
const todoListReport = todoReport.replace(
  '</d:multistatus>',
  `${todoResponse('timezone', timezoneTodo)}</d:multistatus>`
);

const server = http.createServer(async (req, res) => {
  let body = '';
  for await (const chunk of req) body += chunk;
  requests.push({ method: req.method, url: req.url, body });

  res.statusCode = 200;
  if (req.method === 'PROPFIND' &&
      /^\/remote\.php\/dav\/calendars\/[^/]+\/$/.test(req.url ?? '')) {
    res.setHeader('content-type', 'application/xml');
    res.end(calendarDiscovery);
  } else if (req.method === 'PROPFIND' &&
             req.url === '/remote.php/dav/addressbooks/users/tester/') {
    res.setHeader('content-type', 'application/xml');
    res.end(addressBookDiscovery);
  } else if (req.method === 'REPORT' &&
             req.url === '/remote.php/dav/addressbooks/users/tester/contacts/') {
    res.setHeader('content-type', 'application/xml');
    res.end(groupedContactReport);
  } else if (req.method === 'REPORT' &&
             req.url === '/remote.php/dav/calendars/tester/personal/') {
    res.setHeader('content-type', 'application/xml');
    // findTaskPath names the UID it is looking for in the query, so a fixture can
    // be aimed at one test without changing what `tasks list` sees.
    if (!body.includes('VTODO')) res.end(eventReport);
    else if (body.includes('task-timezone')) res.end(timezoneTodoReport);
    else if (body.includes('task-allday')) res.end(allDayTodoReport);
    else if (body.includes('task-metadata')) res.end(metadataTodoReport);
    else res.end(todoListReport);
  } else {
    res.setHeader('content-type', 'text/plain');
    res.end('ok');
  }
});

await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
const { port } = server.address();
const env = {
  ...process.env,
  NEXTCLOUD_URL: `http://127.0.0.1:${port}`,
  NEXTCLOUD_USER: 'tester',
  NEXTCLOUD_TOKEN: 'dummy-test-token'
};
// Optional, and read from the ambient environment — drop it so a developer who
// has it set does not get different results from CI.
delete env.NEXTCLOUD_EMAIL;

function run(args, extraEnv = {}) {
  return new Promise(resolveRun => {
    const child = spawn(process.execPath, [bundle, ...args], {
      env: { ...env, ...extraEnv }
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => stdout += chunk);
    child.stderr.on('data', chunk => stderr += chunk);
    child.on('close', code => resolveRun({ code, stdout, stderr }));
  });
}

const tests = [];
function record(name, passed, details = {}) {
  tests.push({ name, passed, ...details });
}

try {
for (const filePath of [
  '.',
  './',
  'folder/.',
  '%2e',
  'folder/%2e',
  '..',
  'folder/..',
  'folder/%2e%2e'
]) {
  const requestCount = requests.length;
  const pathResult = await run([
    'files', 'delete',
    '--path', filePath,
    '--confirm', 'files:delete'
  ]);
  record(
    `file path ${JSON.stringify(filePath)} is rejected before a DAV request`,
    pathResult.code !== 0 &&
      pathResult.stderr.includes('disallowed dot-segments') &&
      requests.length === requestCount,
    { result: pathResult }
  );
}

let before = requests.length;
let result = await run([
  'files', 'delete',
  '--path', 'reports../file.txt',
  '--confirm', 'files:delete'
]);
record(
  'non-segment double dots remain valid in file names',
  result.code === 0 &&
    requests.length === before + 1 &&
    requests.at(-1)?.method === 'DELETE' &&
    requests.at(-1)?.url ===
      '/remote.php/dav/files/tester/reports../file.txt',
  { request: requests.at(-1), result }
);

before = requests.length;
result = await run([
  'files', 'delete',
  '--path', 'reports/100% done.txt',
  '--confirm', 'files:delete'
]);
record(
  'literal percent signs are preserved and encoded in DAV paths',
  result.code === 0 &&
    requests.length === before + 1 &&
    requests.at(-1)?.url ===
      '/remote.php/dav/files/tester/reports/100%25%20done.txt',
  { request: requests.at(-1), result }
);

before = requests.length;
result = await run([
  'calendar', 'create',
  '--summary', 'Team\nATTENDEE:mailto:attacker@example.com',
  '--start', '2026-07-28T12:00:00Z',
  '--end', '2026-07-28T13:00:00Z',
  '--description', 'line one\nline two'
]);
const eventPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'calendar newlines are escaped once without property injection',
  result.code === 0 &&
    eventPut?.body.match(/^SUMMARY:.*$/m)?.[0] ===
      'SUMMARY:Team\\nATTENDEE:mailto:attacker@example.com' &&
    eventPut?.body.match(/^DESCRIPTION:.*$/m)?.[0] ===
      'DESCRIPTION:line one\\nline two' &&
    !eventPut.body.includes('\nATTENDEE:') &&
    !eventPut.body.includes('\rATTENDEE:'),
  { body: eventPut?.body ?? null, result }
);

result = await run([
  'calendar', 'list',
  '--from', '2026-07-28T00:00:00Z',
  '--to', '2026-07-29T00:00:00Z'
]);
let listedEvent = null;
try {
  listedEvent = JSON.parse(result.stdout)?.data?.[0] ?? null;
} catch {
  // The assertion below preserves the parse failure as test evidence.
}
record(
  'calendar text values are unescaped when read',
  result.code === 0 &&
    listedEvent?.summary === 'Quarterly, Review' &&
    listedEvent?.description === 'Line one\nLine two' &&
    listedEvent?.location === 'Room; 2',
  { listedEvent, result }
);

// NEXTCLOUD_EMAIL is optional: unset, events must be written exactly as they
// were before it existed.
before = requests.length;
result = await run([
  'calendar', 'create',
  '--summary', 'Plain event',
  '--start', '2026-09-01T10:00:00',
  '--end', '2026-09-01T11:00:00',
  '--calendar', 'Personal'
]);
const plainPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'events carry no organiser when NEXTCLOUD_EMAIL is unset',
  result.code === 0 &&
    !plainPut?.body.includes('ORGANIZER') &&
    !plainPut?.body.includes('ATTENDEE') &&
    !plainPut?.body.includes('STATUS:'),
  { body: plainPut?.body ?? null, result }
);

before = requests.length;
result = await run([
  'calendar', 'create',
  '--summary', 'Confirmed event',
  '--start', '2026-09-01T10:00:00',
  '--end', '2026-09-01T11:00:00',
  '--calendar', 'Personal'
], { NEXTCLOUD_EMAIL: 'tester@example.com' });
const organizerPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'NEXTCLOUD_EMAIL marks the account as a confirmed organiser and attendee',
  result.code === 0 &&
    organizerPut?.body.includes('STATUS:CONFIRMED') &&
    organizerPut?.body.includes('ORGANIZER;CN=tester:mailto:tester@example.com') &&
    organizerPut?.body.includes(
      'ATTENDEE;CN=tester;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:tester@example.com'
    ) &&
    // RSVP would ask for a reply PARTSTAT has already given, reinstating the
    // pending prompt this feature exists to avoid.
    !organizerPut?.body.includes('RSVP'),
  { body: organizerPut?.body ?? null, result }
);

// A parameter value is not a property value: RFC 5545 defines no backslash
// escape for it, so a comma has to be handled by quoting the whole value.
before = requests.length;
result = await run([
  'calendar', 'create',
  '--summary', 'Quoted CN',
  '--start', '2026-09-01T10:00:00',
  '--end', '2026-09-01T11:00:00',
  '--calendar', 'Personal'
], { NEXTCLOUD_USER: 'Doe, John', NEXTCLOUD_EMAIL: 'j@example.com' });
const quotedPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'a comma in the display name is quoted rather than backslash-escaped',
  result.code === 0 &&
    quotedPut?.body.includes('ORGANIZER;CN="Doe, John":mailto:j@example.com') &&
    !quotedPut?.body.includes('CN=Doe\\,'),
  { body: quotedPut?.body ?? null, result }
);

before = requests.length;
result = await run([
  'calendar', 'create',
  '--summary', 'Injection attempt',
  '--start', '2026-09-01T10:00:00',
  '--end', '2026-09-01T11:00:00',
  '--calendar', 'Personal'
], { NEXTCLOUD_EMAIL: 'a@x.com\nDESCRIPTION:injected' });
record(
  'a newline in NEXTCLOUD_EMAIL is rejected before any request',
  result.code !== 0 &&
    result.stderr.includes('NEXTCLOUD_EMAIL must be a plain email address') &&
    requests.length === before,
  { result }
);

result = await run(['tasks', 'list', '--calendar', 'Personal']);
let listedTasks = [];
let listedTask = null;
try {
  listedTasks = JSON.parse(result.stdout)?.data ?? [];
  listedTask = listedTasks[0] ?? null;
} catch {
  // The assertions below preserve the parse failure as test evidence.
}
record(
  'task text values are unescaped when read',
  result.code === 0 &&
    listedTask?.summary === 'Call Alice, Bob' &&
    listedTask?.description === 'First line\nSecond line',
  { listedTask, result }
);

const listedUids = listedTasks.map(task => task.uid);
record(
  'tasks without a STATUS property are listed as NEEDS-ACTION',
  listedTasks.find(task => task.uid === 'task-no-status')?.status === 'NEEDS-ACTION',
  { listedUids, result }
);
record(
  'completed tasks stay hidden from tasks list',
  !listedUids.includes('task-completed'),
  { listedUids, result }
);
record(
  'a description mentioning STATUS: does not hide an active task',
  listedTasks.find(task => task.uid === 'task-mentions-status')?.status === 'NEEDS-ACTION',
  { listedUids, result }
);
record(
  'REQUEST-STATUS does not mask a completed task',
  !listedUids.includes('task-request-status'),
  { listedUids, result }
);

before = requests.length;
result = await run([
  'calendar', 'edit',
  '--uid', 'event-1',
  '--calendar', 'Personal',
  '--summary', 'Budget $& $1'
]);
const updatedEventPut = requests
  .slice(before)
  .find(entry => entry.method === 'PUT');
record(
  'calendar edits preserve dollar replacement tokens literally',
  result.code === 0 &&
    updatedEventPut?.body.includes('SUMMARY:Budget $& $1'),
  { body: updatedEventPut?.body ?? null, result }
);

result = await run(['contacts', 'list']);
let groupedContact = null;
try {
  groupedContact = JSON.parse(result.stdout)?.data?.[0] ?? null;
} catch {
  // The assertion below preserves the parse failure as test evidence.
}
record(
  'grouped vCard EMAIL and TEL properties parse',
  result.code === 0 &&
    groupedContact?.fullName === 'Grouped, Contact' &&
    groupedContact?.emails?.[0] === 'grouped@example.com' &&
    groupedContact?.phones?.[0] === '+15551234567',
  { groupedContact, result }
);

record(
  'structured N components are split before unescaping',
  result.code === 0 &&
    // "Smith\;Jones" is one component containing a literal semicolon, not two
    groupedContact?.nameComponents?.last === 'Smith;Jones' &&
    groupedContact?.nameComponents?.first === 'John' &&
    groupedContact?.nameComponents?.middle === '' &&
    // A naive split of `name` cannot recover this, which is why the
    // components are exposed separately.
    groupedContact?.name === 'Smith;Jones;John;;;',
  { nameComponents: groupedContact?.nameComponents ?? null, result }
);

before = requests.length;
result = await run([
  'contacts', 'edit',
  '--uid', 'grouped',
  '--email', 'replacement@example.com'
]);
const contactPut = requests.slice(before).find(entry => entry.method === 'PUT');
const emailLines = contactPut?.body
  .split(/\r?\n/)
  .filter(line => /EMAIL/i.test(line)) ?? [];
record(
  'editing a grouped EMAIL preserves its group and parameters',
  result.code === 0 &&
    emailLines.length === 1 &&
    emailLines[0] === 'item1.EMAIL;TYPE=work:replacement@example.com',
  { emailLines, result }
);

before = requests.length;
result = await run([
  'contacts', 'edit',
  '--uid', 'grouped',
  '--note', 'Budget $& $1'
]);
const notePut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'inserted vCard fields preserve dollar replacement tokens literally',
  result.code === 0 &&
    notePut?.body.includes('NOTE:Budget $& $1\nEND:VCARD'),
  { body: notePut?.body ?? null, result }
);

for (const [subcommand, args] of [
  ['create', ['--title', 'Invalid priority', '--priority', '10']],
  ['edit', ['--uid', 'task-1', '--priority', '-1']]
]) {
  before = requests.length;
  result = await run(['tasks', subcommand, ...args]);
  record(
    `tasks ${subcommand} rejects priorities outside 0-9 before a request`,
    result.code !== 0 &&
      result.stderr.includes('Priority must be an integer from 0 to 9') &&
      requests.length === before,
    { result }
  );
}

// New task metadata options: status and percent-complete.
before = requests.length;
result = await run([
  'tasks', 'edit',
  '--uid', 'task-1',
  '--status', 'IN-PROCESS',
  '--percent-complete', '42'
]);
const metadataPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'tasks edit writes STATUS and PERCENT-COMPLETE',
  result.code === 0 &&
    metadataPut?.body.includes('STATUS:IN-PROCESS') &&
    metadataPut?.body.includes('PERCENT-COMPLETE:42'),
  { body: metadataPut?.body ?? null, result }
);

for (const [flag, value, expectedMsg] of [
  ['--status', 'INVALID', "Invalid status 'INVALID'"],
  ['--percent-complete', '101', 'Percent-complete must be between 0 and 100'],
  ['--percent-complete', 'abc', 'Percent-complete must be an integer']
]) {
  before = requests.length;
  result = await run(['tasks', 'edit', '--uid', 'task-1', flag, value]);
  record(
    `tasks edit rejects ${flag}=${value} before a request`,
    result.code !== 0 &&
      result.stderr.includes(expectedMsg) &&
      requests.length === before,
    { result }
  );
}

// Extended task metadata: start, location, url, class, tags.
before = requests.length;
result = await run([
  'tasks', 'create',
  '--title', 'Full metadata task',
  '--start', '2026-09-01T10:00:00Z',
  '--due', '2026-09-02T10:00:00Z',
  '--priority', '5',
  '--location', 'Home office',
  '--url', 'https://example.com',
  '--class', 'PRIVATE',
  '--tags', 'work,urgent'
]);
const createMetadataPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'tasks create writes start, location, url, class, and tags',
  result.code === 0 &&
    createMetadataPut?.body.includes('DTSTART:20260901') &&
    createMetadataPut?.body.includes('DUE:20260902') &&
    createMetadataPut?.body.includes('PRIORITY:5') &&
    createMetadataPut?.body.includes('LOCATION:Home office') &&
    createMetadataPut?.body.includes('URL:https://example.com') &&
    createMetadataPut?.body.includes('CLASS:PRIVATE') &&
    createMetadataPut?.body.includes('CATEGORIES:work,urgent'),
  { body: createMetadataPut?.body ?? null, result }
);

before = requests.length;
result = await run([
  'tasks', 'edit',
  '--uid', 'task-1',
  '--start', '2026-07-01T10:00:00Z',
  '--location', 'Updated office',
  '--url', 'https://updated.example.com',
  '--class', 'CONFIDENTIAL',
  '--tags', 'review,later'
]);
const editMetadataPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'tasks edit writes start, location, url, class, and tags',
  result.code === 0 &&
    editMetadataPut?.body.includes('DTSTART:20260701') &&
    editMetadataPut?.body.includes('LOCATION:Updated office') &&
    editMetadataPut?.body.includes('URL:https://updated.example.com') &&
    editMetadataPut?.body.includes('CLASS:CONFIDENTIAL') &&
    editMetadataPut?.body.includes('CATEGORIES:review,later'),
  { body: editMetadataPut?.body ?? null, result }
);

before = requests.length;
result = await run([
  'tasks', 'create',
  '--title', 'Inverted dates',
  '--start', '2026-09-02T10:00:00Z',
  '--due', '2026-09-01T10:00:00Z'
]);
record(
  'tasks create rejects start date after due date before a request',
  result.code !== 0 &&
    result.stderr.includes('Start date must be earlier than or equal to due date') &&
    requests.length === before,
  { result }
);

before = requests.length;
result = await run([
  'tasks', 'edit',
  '--uid', 'task-1',
  '--start', '2099-01-01T00:00:00Z'
]);
const editValidationPuts = requests.slice(before).filter(entry => entry.method === 'PUT');
record(
  'tasks edit rejects start date after existing due date before a PUT',
  result.code !== 0 &&
    result.stderr.includes('Start date must be earlier than or equal to due date') &&
    editValidationPuts.length === 0,
  { result }
);

for (const [flag, value, expectedMsg] of [
  ['--class', 'SECRET', "Invalid class 'SECRET'"],
  ['--class', 'public', ''] // valid, lowercase should normalize
]) {
  before = requests.length;
  result = await run(['tasks', 'edit', '--uid', 'task-1', flag, value]);
  if (expectedMsg === '') {
    record(
      'tasks edit accepts lowercase class values',
      result.code === 0,
      { result }
    );
  } else {
    record(
      `tasks edit rejects ${flag}=${value} before a request`,
      result.code !== 0 &&
        result.stderr.includes(expectedMsg) &&
        requests.length === before,
      { result }
    );
  }
}
// --- Properties are read from and written to the VTODO, not the VCALENDAR ---

before = requests.length;
result = await run([
  'tasks', 'edit',
  '--uid', 'task-timezone',
  '--start', '2026-09-02T10:00:00Z'
]);
const timezonePut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'editing a start leaves the VTIMEZONE DST rules alone',
  result.code === 0 &&
    /BEGIN:VTODO[\s\S]*DTSTART:20260902T100000Z[\s\S]*END:VTODO/.test(timezonePut?.body ?? '') &&
    timezonePut?.body.includes('DTSTART:19700329T020000') &&
    timezonePut?.body.includes('DTSTART:19701025T030000') &&
    !timezonePut?.body.includes('DTSTART;TZID=Europe/Malta:20260901T090000'),
  { body: timezonePut?.body ?? null, result }
);

before = requests.length;
result = await run(['tasks', 'edit', '--uid', 'task-timezone', '--title', 'Renamed']);
const alarmPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'editing a title leaves a VALARM subcomponent alone',
  result.code === 0 &&
    alarmPut?.body.includes('SUMMARY:Renamed') &&
    alarmPut?.body.includes('SUMMARY:Alarm summary') &&
    !alarmPut?.body.includes('SUMMARY:Timezoned task'),
  { body: alarmPut?.body ?? null, result }
);

result = await run(['tasks', 'list', '--calendar', 'Personal']);
let timezoneTask = null;
try {
  timezoneTask = (JSON.parse(result.stdout)?.data ?? [])
    .find(task => task.uid === 'task-timezone') ?? null;
} catch {
  // The assertion below preserves the parse failure as test evidence.
}
record(
  'tasks list reports the task start, not a VTIMEZONE DST rule',
  result.code === 0 && timezoneTask?.start === '20260901T090000',
  { timezoneTask, result }
);

// --- All-day tasks keep the DATE value type on both ends ---

before = requests.length;
result = await run(['tasks', 'edit', '--uid', 'task-allday', '--start', '2026-08-27']);
const allDayPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'a start added to an all-day task is written as a DATE',
  result.code === 0 &&
    allDayPut?.body.includes('DTSTART;VALUE=DATE:20260827') &&
    allDayPut?.body.includes('DUE;VALUE=DATE:20260828'),
  { body: allDayPut?.body ?? null, result }
);

before = requests.length;
result = await run(['tasks', 'edit', '--uid', 'task-allday', '--start', '2026-08-28T09:00:00Z']);
record(
  'a timed start on an all-day task is refused rather than written',
  result.code !== 0 &&
    result.stderr.includes('must both be all-day dates') &&
    requests.slice(before).filter(entry => entry.method === 'PUT').length === 0,
  { result }
);

before = requests.length;
result = await run(['tasks', 'create', '--title', 'All-day', '--due', '2026-09-02']);
const allDayCreatePut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'a due date with no time creates an all-day task',
  result.code === 0 && allDayCreatePut?.body.includes('DUE;VALUE=DATE:20260902'),
  { body: allDayCreatePut?.body ?? null, result }
);

// --- Clearing metadata, and replacing a folded value ---

before = requests.length;
result = await run([
  'tasks', 'edit',
  '--uid', 'task-metadata',
  '--location', '',
  '--url', '',
  '--tags', ''
]);
const clearPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'an empty value removes the property from the task',
  result.code === 0 &&
    !/^LOCATION[;:]/m.test(clearPut?.body ?? '') &&
    !/^URL[;:]/m.test(clearPut?.body ?? '') &&
    !/^CATEGORIES[;:]/m.test(clearPut?.body ?? '') &&
    !clearPut?.body.includes('lines?query=1'),
  { body: clearPut?.body ?? null, result }
);

before = requests.length;
result = await run([
  'tasks', 'edit',
  '--uid', 'task-metadata',
  '--url', 'https://example.com/short'
]);
const refoldPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'replacing a folded value takes its continuation lines with it',
  result.code === 0 &&
    refoldPut?.body.includes('URL:https://example.com/short') &&
    !refoldPut?.body.includes('lines?query=1'),
  { body: refoldPut?.body ?? null, result }
);

// --- URL is a URI, not escaped text ---

before = requests.length;
result = await run([
  'tasks', 'create',
  '--title', 'Linked task',
  '--url', 'https://example.com/search?a=1,b=2'
]);
const uriPut = requests.slice(before).find(entry => entry.method === 'PUT');
record(
  'a comma in a URL is written literally, not backslash-escaped',
  result.code === 0 &&
    uriPut?.body.includes('URL:https://example.com/search?a=1,b=2'),
  { body: uriPut?.body ?? null, result }
);

before = requests.length;
result = await run(['tasks', 'create', '--title', 'Bad link', '--url', 'not a uri']);
record(
  'a URL containing spaces is rejected before a request',
  result.code !== 0 &&
    result.stderr.includes('URL must be a single URI') &&
    requests.length === before,
  { result }
);

// --- Timestamps we generate are UTC ---

before = requests.length;
result = await run(['tasks', 'complete', '--uid', 'task-1']);
const completePut = requests.slice(before).find(entry => entry.method === 'PUT');
const completedStamp = (completePut?.body ?? '').match(/^COMPLETED:(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/m);
const completedAt = completedStamp
  ? Date.parse(`${completedStamp[1]}-${completedStamp[2]}-${completedStamp[3]}T${completedStamp[4]}:${completedStamp[5]}:${completedStamp[6]}Z`)
  : NaN;
record(
  'COMPLETED is stamped in UTC, as its Z suffix claims',
  result.code === 0 && Math.abs(Date.now() - completedAt) < 5 * 60 * 1000,
  { body: completePut?.body ?? null, result }
);
} finally {
  await new Promise(resolveClose => server.close(resolveClose));
}

for (const test of tests) {
  console.log(`${test.passed ? 'PASS' : 'FAIL'} ${test.name}`);
  if (!test.passed) {
    const diagnostic = { ...test };
    delete diagnostic.name;
    delete diagnostic.passed;
    console.log(JSON.stringify(diagnostic, null, 2));
  }
}

const passed = tests.filter(test => test.passed).length;
console.log(`\n${passed}/${tests.length} tests passed`);
process.exit(passed === tests.length ? 0 : 1);
