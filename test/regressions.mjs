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
PRIORITY:5
END:VTODO
END:VCALENDAR</cal:calendar-data>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>`;

const server = http.createServer(async (req, res) => {
  let body = '';
  for await (const chunk of req) body += chunk;
  requests.push({ method: req.method, url: req.url, body });

  res.statusCode = 200;
  if (req.method === 'PROPFIND' &&
      req.url === '/remote.php/dav/calendars/tester/') {
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
    res.end(body.includes('VTODO') ? todoReport : eventReport);
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

function run(args) {
  return new Promise(resolveRun => {
    const child = spawn(process.execPath, [bundle, ...args], { env });
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

result = await run(['tasks', 'list', '--calendar', 'Personal']);
let listedTask = null;
try {
  listedTask = JSON.parse(result.stdout)?.data?.[0] ?? null;
} catch {
  // The assertion below preserves the parse failure as test evidence.
}
record(
  'task text values are unescaped when read',
  result.code === 0 &&
    listedTask?.summary === 'Call Alice, Bob' &&
    listedTask?.description === 'First line\nSecond line',
  { listedTask, result }
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
