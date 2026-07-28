#!/usr/bin/env node

// OpenClaw Nextcloud skill — authenticated Nextcloud client.
//
// This script intentionally reads credentials from the environment
// (NEXTCLOUD_URL, NEXTCLOUD_USER, NEXTCLOUD_TOKEN) and sends them via Basic
// Auth to the configured NEXTCLOUD_URL. That credential→network pattern is
// the entire purpose of the skill: it cannot function without it. To bound
// the blast radius:
//   - The token is sent ONLY to NEXTCLOUD_URL. Every fetch call in this
//     script builds its URL from CONFIG.url; there are no hard-coded hosts.
//   - HTTPS is required for NEXTCLOUD_URL by default (see check below).
//     Local development against http://localhost can be enabled with
//     OPENCLAW_ALLOW_HTTP=1.
//   - No telemetry, no analytics, no auto-update.
//
// Static analysers may flag this file with rules like
// "suspicious.env_credential_access" because of the env-read + network-send
// pattern. That flag is expected; the constraints above are what you should
// audit instead.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { Buffer } from 'node:buffer';
import { XMLParser } from 'fast-xml-parser';
import { addDays, formatISO, format } from 'date-fns';
import crypto from 'node:crypto';

// --- Configuration ---
const CONFIG = {
    url: process.env.NEXTCLOUD_URL,
    user: process.env.NEXTCLOUD_USER,
    token: process.env.NEXTCLOUD_TOKEN
};

if (!CONFIG.url || !CONFIG.user || !CONFIG.token) {
    console.error(JSON.stringify({
        status: 'error',
        message: 'Missing configuration. Set NEXTCLOUD_URL, NEXTCLOUD_USER, and NEXTCLOUD_TOKEN.'
    }));
    process.exit(1);
}

// Refuse to send the token over plaintext HTTP unless explicitly opted in.
// Localhost is allowed without opt-in for development convenience.
{
    const parsed = (() => { try { return new URL(CONFIG.url); } catch { return null; } })();
    if (!parsed) {
        console.error(JSON.stringify({ status: 'error', message: `Invalid NEXTCLOUD_URL: '${CONFIG.url}'` }));
        process.exit(1);
    }
    const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
    if (parsed.protocol !== 'https:' && !isLocalhost && process.env.OPENCLAW_ALLOW_HTTP !== '1') {
        console.error(JSON.stringify({
            status: 'error',
            message: `Refusing to send credentials over '${parsed.protocol}//' to '${parsed.host}'. Use https:// or set OPENCLAW_ALLOW_HTTP=1 to override (not recommended).`
        }));
        process.exit(1);
    }
}

// Basic Auth Header
const AUTH_HEADER = 'Basic ' + Buffer.from(`${CONFIG.user}:${CONFIG.token}`).toString('base64');

// XML Parser
const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "@_"
});

// --- Helpers ---

async function request(endpoint, options = {}) {
    const url = `${CONFIG.url}${endpoint}`;
    const headers = {
        'Authorization': AUTH_HEADER,
        'User-Agent': 'OpenClaw-Nextcloud-Skill',
        ...options.headers
    };

    try {
        const response = await fetch(url, { ...options, headers });
        if (!response.ok) {
            const err = new Error(`HTTP ${response.status}: ${response.statusText}`);
            err.status = response.status;
            throw err;
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            return await response.json();
        } else if (contentType && contentType.includes('xml')) {
            const text = await response.text();
            return parser.parse(text);
        } else {
            return await response.text();
        }
    } catch (error) {
        const wrapped = new Error(`Request failed: ${error.message}`);
        if (error.status !== undefined) wrapped.status = error.status;
        throw wrapped;
    }
}

function output(data) {
    console.log(JSON.stringify({
        status: 'success',
        data: data
    }, null, 2));
}

function errorOutput(message) {
    console.error(JSON.stringify({
        status: 'error',
        message: message.stack || message
    }, null, 2));
    process.exit(1);
}

// --- Security: path traversal prevention ---
// Reject paths that attempt to escape the WebDAV files namespace via dot-segments,
// percent-encoded traversal, backslashes, null bytes, or control characters.
function sanitizePath(filePath) {
    if (typeof filePath !== 'string' || filePath === '') {
        throw new Error('File path must be a non-empty string.');
    }
    // Decode once to catch percent-encoded traversal (e.g. %2e%2e%2f)
    let decoded;
    try {
        decoded = decodeURIComponent(filePath);
    } catch {
        throw new Error('File path contains invalid percent-encoding.');
    }
    // Reject complete dot-segments after decoding. Both "." and ".." are
    // normalized by URL clients and can otherwise alias a different DAV target.
    const decodedSegments = decoded.split('/');
    if (decodedSegments.some(segment => segment === '.' || segment === '..')) {
        throw new Error('File path contains disallowed dot-segments (. or ..).');
    }
    if (/[\x00-\x1f\x7f]/.test(decoded)) {
        throw new Error('File path contains control characters.');
    }
    if (/\\/.test(decoded)) {
        throw new Error('File path contains backslashes.');
    }
    return decoded;
}

// URL-encode each path segment individually so that / in segment names are
// encoded as %2F and don't become path separators.
function encodePathSegments(decodedPath) {
    return decodedPath.split('/').map(seg => encodeURIComponent(seg)).join('/');
}

// --- Security: iCalendar / vCard property-value escaping ---
// Prevent property injection and value corruption by escaping special
// characters per RFC 5545 (iCalendar) and RFC 6350 (vCard).
//   \  → \\    (escape backslash first)
//   ;  → \;
//   ,  → \,
//   \n → \\n   (literal backslash-n to represent newline in the value)
//   \r → \\n
// Additionally strip raw CR/LF to prevent property-line injection.
function escapePropertyValue(value) {
    if (typeof value !== 'string') return String(value);
    // Escape existing backslashes before introducing the backslash-n sequence
    // used for newlines. This prevents both property injection and accidental
    // double-escaping of the newline marker.
    let escaped = value.replace(/\\/g, '\\\\');
    escaped = escaped.replace(/\r\n/g, '\\n').replace(/\n/g, '\\n').replace(/\r/g, '\\n');
    // Escape semicolons and commas which delimit structured values
    escaped = escaped.replace(/;/g, '\\;').replace(/,/g, '\\,');
    return escaped;
}

function ensureArray(item) {
    if (Array.isArray(item)) return item;
    if (item === undefined || item === null) return [];
    return [item];
}

// Accept both ISO 8601 (2026-04-15T17:00:00Z) and CalDAV compact format (20260415T170000Z).
// Compact form is what we emit in list output, so users naturally try it as input too.
// Match user-supplied calendar/address-book identifiers liberally:
// exact displayname → case-insensitive displayname → URL slug → full href.
// `items` are objects with at least { displayname, url }.
function matchByName(items, name) {
    if (!name) return null;
    const exact = items.find(i => i.displayname === name);
    if (exact) return exact;
    const lower = name.toLowerCase();
    const ci = items.find(i => i.displayname && i.displayname.toLowerCase() === lower);
    if (ci) return ci;
    const slug = lower.replace(/^https?:\/\/[^/]+/, '').replace(/\/+$/, '').split('/').filter(Boolean).pop();
    if (slug) {
        const bySlug = items.find(i => {
            const itemSlug = (i.url || '').replace(/\/+$/, '').split('/').filter(Boolean).pop();
            return itemSlug && itemSlug.toLowerCase() === slug;
        });
        if (bySlug) return bySlug;
    }
    return items.find(i => i.url && (i.url === name || name.endsWith(i.url))) || null;
}

function parseDateInput(str) {
    const compact = String(str).match(/^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})(Z?))?$/);
    if (compact) {
        const [, y, mo, d, h = '00', mi = '00', s = '00', z = ''] = compact;
        const date = new Date(`${y}-${mo}-${d}T${h}:${mi}:${s}${z}`);
        if (!isNaN(date.getTime())) return date;
    }
    const date = new Date(str);
    if (isNaN(date.getTime())) {
        throw new Error(`Invalid date '${str}'. Use ISO 8601 (2026-04-15T17:00:00Z) or CalDAV compact format (20260415T170000Z).`);
    }
    return date;
}

// --- Modules ---

// 1. Notes
const Notes = {
    async list() {
        const data = await request('/index.php/apps/notes/api/v1/notes', {
            headers: { 'Accept': 'application/json' }
        });
        return data.map(n => ({
            id: n.id,
            title: n.title,
            modified: n.modified,
            category: n.category
        }));
    },
    async get(id) {
        return await request(`/index.php/apps/notes/api/v1/notes/${id}`, {
            headers: { 'Accept': 'application/json' }
        });
    },
    async create(title, content, category = '') {
        if (!title || typeof title !== 'string' || title.trim() === '') {
            throw new Error('Title is required for creating a note.');
        }
        if (!content || typeof content !== 'string') {
            throw new Error('Content is required for creating a note.');
        }

        const payload = { title, content };
        if (category) {
            payload.category = category;
        }

        const data = await request('/index.php/apps/notes/api/v1/notes', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        return {
            id: data.id,
            title: data.title,
            modified: data.modified,
            category: data.category,
            content: data.content // Return content as well for verification
        };
    },
    async update(id, title, content, category) {
        if (!id) throw new Error('Note ID is required for update.');

        const payload = {};
        if (title !== undefined) payload.title = title;
        if (content !== undefined) payload.content = content;
        if (category !== undefined) payload.category = category;

        if (Object.keys(payload).length === 0) {
            throw new Error('Nothing to update. Provide title, content, or category.');
        }

        const data = await request(`/index.php/apps/notes/api/v1/notes/${id}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        return data;
    },
    async delete(id) {
        if (!id) throw new Error('Note ID is required for deletion.');

        await request(`/index.php/apps/notes/api/v1/notes/${id}`, {
            method: 'DELETE',
            headers: {
                'Accept': 'application/json'
            }
        });

        return { success: true, id };
    }
};

// 2. Files (WebDAV)
const Files = {
    async list(dirPath = '/') {
        const decodedPath = sanitizePath(dirPath);
        const relPath = decodedPath.replace(/^\/+/, '');
        const safePath = relPath ? encodePathSegments(relPath) : '';
        const endpoint = `/remote.php/dav/files/${encodeURIComponent(CONFIG.user)}/${safePath}`;

        // Explicitly request oc:fileid alongside the standard DAV props.
        // Without an explicit body, default PROPFIND props are returned and oc:fileid is omitted.
        const propfindBody = `<?xml version="1.0" encoding="utf-8"?>
<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:prop>
    <d:resourcetype/>
    <d:getcontentlength/>
    <d:getlastmodified/>
    <oc:fileid/>
  </d:prop>
</d:propfind>`;

        const response = await request(endpoint, {
            method: 'PROPFIND',
            headers: {
                'Depth': '1',
                'Content-Type': 'application/xml'
            },
            body: propfindBody
        });

        if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) {
            return [];
        }

        const responses = ensureArray(response['d:multistatus']['d:response']);
        const baseUrl = CONFIG.url.replace(/\/+$/, '');

        return responses.map(r => {
            const href = r['d:href'];
            const propstats = ensureArray(r['d:propstat']);
            if (!propstats[0] || !propstats[0]['d:prop']) return null;
            const props = propstats[0]['d:prop'];

            const isDir = props['d:resourcetype'] && props['d:resourcetype']['d:collection'] !== undefined;
            const name = decodeURIComponent(href.split('/').filter(p => p).pop());

            if (href.endsWith(encodeURIComponent(CONFIG.user) + '/' + safePath) ||
                href.endsWith(encodeURIComponent(CONFIG.user) + '/' + safePath + '/')) {
                 if (relPath !== '' && name === relPath.split('/').pop()) return null;
            }

            const fileId = props['oc:fileid'] != null ? String(props['oc:fileid']) : null;

            return {
                name: name,
                path: href,
                isDir: isDir,
                size: props['d:getcontentlength'],
                lastModified: props['d:getlastmodified'],
                fileId: fileId,
                internalLink: fileId ? `${baseUrl}/index.php/f/${fileId}` : null
            };
        }).filter(f => f);
    },
    
    async upload(filePath, content) {
        const decodedPath = sanitizePath(filePath);
        const relPath = decodedPath.replace(/^\/+/, '');
        if (!relPath) throw new Error('File path must be non-empty.');
        const safePath = encodePathSegments(relPath);

        // Ensure parent directories exist. MKCOL each segment; 405 means it already exists.
        const segments = relPath.split('/').filter(Boolean);
        if (segments.length > 1) {
            let currentPath = '';
            for (const seg of segments.slice(0, -1)) {
                currentPath = currentPath ? `${currentPath}/${encodeURIComponent(seg)}` : encodeURIComponent(seg);
                try {
                    await request(`/remote.php/dav/files/${encodeURIComponent(CONFIG.user)}/${currentPath}`, { method: 'MKCOL' });
                } catch (e) {
                    if (e.status !== 405) throw e;
                }
            }
        }

        const endpoint = `/remote.php/dav/files/${encodeURIComponent(CONFIG.user)}/${safePath}`;

        await request(endpoint, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/octet-stream'
            },
            body: content,
            rawBody: true
        });

        return { path: filePath, status: 'uploaded', size: content.length };
    },

    async get(filePath) {
        const decodedPath = sanitizePath(filePath);
        const relPath = decodedPath.replace(/^\/+/, '');
        if (!relPath) throw new Error('File path must be non-empty.');
        const safePath = encodePathSegments(relPath);
        const endpoint = `/remote.php/dav/files/${encodeURIComponent(CONFIG.user)}/${safePath}`;

        const response = await fetch(`${CONFIG.url}${endpoint}`, {
            method: 'GET',
            headers: {
                'Authorization': `Basic ${Buffer.from(`${CONFIG.user}:${CONFIG.token}`).toString('base64')}`
            }
        });

        if (!response.ok) {
            throw new Error(`Request failed: HTTP ${response.status}: ${response.statusText}`);
        }

        const content = await response.text();
        return { path: filePath, content, size: content.length };
    },

    async delete(filePath) {
        const decodedPath = sanitizePath(filePath);
        const relPath = decodedPath.replace(/^\/+/, '');
        if (!relPath) throw new Error('File path must be non-empty.');
        const safePath = encodePathSegments(relPath);
        const endpoint = `/remote.php/dav/files/${encodeURIComponent(CONFIG.user)}/${safePath}`;

        await request(endpoint, {
            method: 'DELETE'
        });

        return { path: filePath, status: 'deleted' };
    },

    async search(query) {
        const endpoint = `/remote.php/dav/`;
        const body = `
            <d:searchrequest xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
                <d:basicsearch>
                    <d:select>
                        <d:prop>
                            <d:getlastmodified/>
                            <d:getcontentlength/>
                            <d:resourcetype/>
                            <d:displayname/>
                            <oc:fileid/>
                        </d:prop>
                    </d:select>
                    <d:from>
                        <d:scope>
                            <d:href>/files/${CONFIG.user}</d:href>
                            <d:depth>infinity</d:depth>
                        </d:scope>
                    </d:from>
                    <d:where>
                        <d:like>
                            <d:prop>
                                <d:displayname/>
                            </d:prop>
                            <d:literal>%${query}%</d:literal>
                        </d:like>
                    </d:where>
                </d:basicsearch>
            </d:searchrequest>
        `;

        const response = await request(endpoint, {
            method: 'SEARCH',
            headers: { 'Content-Type': 'application/xml' },
            body: body
        });

        if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) return [];
        const responses = ensureArray(response['d:multistatus']['d:response']);
        const baseUrl = CONFIG.url.replace(/\/+$/, '');

        return responses.map(r => {
            const href = r['d:href'];
            const propstats = ensureArray(r['d:propstat']);
            if (!propstats[0] || !propstats[0]['d:prop']) return null;
            const props = propstats[0]['d:prop'];

            const isDir = props['d:resourcetype'] && props['d:resourcetype']['d:collection'] !== undefined;
            const fileId = props['oc:fileid'] != null ? String(props['oc:fileid']) : null;

            return {
                name: props['d:displayname'] || decodeURIComponent(href.split('/').pop()),
                path: href,
                isDir: isDir,
                size: props['d:getcontentlength'],
                lastModified: props['d:getlastmodified'],
                fileId: fileId,
                internalLink: fileId ? `${baseUrl}/index.php/f/${fileId}` : null
            };
        }).filter(f => f);
    }
};

// 3. Calendar & Tasks (CalDAV)
const CalDAV = {
    async findCalendars(componentType = null) {
        // console.error("DEBUG: Entering findCalendars");
        const endpoint = `/remote.php/dav/calendars/${CONFIG.user}/`;
        const response = await request(endpoint, {
            method: 'PROPFIND',
            headers: { 'Depth': '1' }
        });

        if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) return [];

        const responses = ensureArray(response['d:multistatus']['d:response']);

        return responses.map(r => {
             const propstats = ensureArray(r['d:propstat']);
             // console.error("DEBUG: Processing calendar propstat", JSON.stringify(propstats[0]));
             if (!propstats[0] || !propstats[0]['d:prop']) return null;
             const props = propstats[0]['d:prop'];

             if (!props['d:resourcetype'] || !('cal:calendar' in props['d:resourcetype'])) return null;

             // Get supported component type(s) (VEVENT, VTODO, or both).
             // fast-xml-parser returns a single object for one <cal:comp> or an array
             // when the calendar supports multiple component types.
             let compType = null;
             const compSet = props['cal:supported-calendar-component-set'];
             if (compSet && compSet['cal:comp']) {
                 // Normalize to array so we handle both single and multi-comp calendars.
                 const comps = Array.isArray(compSet['cal:comp']) ? compSet['cal:comp'] : [compSet['cal:comp']];
                 // If filtering for a specific type (e.g. VEVENT), find the matching one.
                 // Otherwise just use the first component type.
                 const match = componentType
                     ? comps.find(c => c['@_name'] === componentType)
                     : comps[0];
                 compType = match ? match['@_name'] : comps[0]['@_name'];
             }

             return {
                 url: r['d:href'],
                 displayname: props['d:displayname'],
                 componentType: compType
             };
        }).filter(c => c && (!componentType || c.componentType === componentType));
    },

    async getEvents(start, end) {
        const calendars = await this.findCalendars('VEVENT');
        const allEvents = [];

        const toCalDavDate = (dateStr) => {
            const d = parseDateInput(dateStr);
            return d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
        };
        const startStr = toCalDavDate(start);
        const endStr = toCalDavDate(end);

        const body = `
            <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
                <d:prop>
                    <d:getetag />
                    <c:calendar-data />
                </d:prop>
                <c:filter>
                    <c:comp-filter name="VCALENDAR">
                        <c:comp-filter name="VEVENT">
                            <c:time-range start="${startStr}" end="${endStr}" />
                        </c:comp-filter>
                    </c:comp-filter>
                </c:filter>
            </c:calendar-query>
        `;

        for (const cal of calendars) {
             try {
                // Construct URL correctly. cal.url usually starts with /
                const response = await request(cal.url, {
                    method: 'REPORT',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' },
                    body: body
                });

                 if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) continue;
                 const responses = ensureArray(response['d:multistatus']['d:response']);
                 
                 for (const r of responses) {
                     const propstats = ensureArray(r['d:propstat']);
                     if (!propstats[0] || !propstats[0]['d:prop']) continue;
                     
                     const calData = propstats[0]['d:prop']['cal:calendar-data'];
                     const unfolded = calData.replace(/\r?\n[ \t]/g, '');

                     const uidMatch = calData.match(/UID:(.*)/);
                     const summaryMatch = calData.match(/SUMMARY:(.*)/);
                     const descriptionMatch = unfolded.match(/^DESCRIPTION(?:;[^:]*)?:(.*)$/m);
                     const dtstartMatch = calData.match(/DTSTART(?:;.*)?:(.*)/);
                     const dtendMatch = calData.match(/DTEND(?:;.*)?:(.*)/);
                     const locationMatch = calData.match(/LOCATION:(.*)/);

                     allEvents.push({
                         uid: uidMatch ? uidMatch[1].trim() : 'No UID',
                         calendar: cal.displayname,
                         summary: summaryMatch ? summaryMatch[1].trim() : 'No Title',
                         description: descriptionMatch ? descriptionMatch[1].trim() : null,
                         start: dtstartMatch ? dtstartMatch[1].trim() : 'Unknown',
                         end: dtendMatch ? dtendMatch[1].trim() : null,
                         location: locationMatch ? locationMatch[1].trim() : null
                     });
                 }
             } catch (e) {
                 // ignore errors for specific calendars
             }
        }
        return allEvents;
    },

    async getTodos(calendarName = null) {
        let calendars = await this.findCalendars('VTODO');
        if (calendarName) {
            const matched = matchByName(calendars, calendarName);
            if (!matched) {
                const available = calendars.map(c => c.displayname).join(', ') || '(none)';
                throw new Error(`Task-enabled calendar '${calendarName}' not found. Available: ${available}`);
            }
            calendars = [matched];
        }
        // console.error("DEBUG: Found calendars", JSON.stringify(calendars));
        const allTodos = [];
        
        const body = `
            <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
                <d:prop>
                    <d:getetag />
                    <c:calendar-data />
                    <c:uid />
                </d:prop>
                <c:filter>
                    <c:comp-filter name="VCALENDAR">
                        <c:comp-filter name="VTODO">
                            <c:prop-filter name="STATUS">
                                <c:text-match negate-condition="yes">COMPLETED</c:text-match>
                            </c:prop-filter>
                        </c:comp-filter>
                    </c:comp-filter>
                </c:filter>
            </c:calendar-query>
        `;
        
         for (const cal of calendars) {
             try {
                const response = await request(cal.url, {
                    method: 'REPORT',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' },
                    body: body
                });

                 if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) continue;
                 const responses = ensureArray(response['d:multistatus']['d:response']);
                 
                 for (const r of responses) {
                     const propstats = ensureArray(r['d:propstat']);
                     // console.error("DEBUG: Processing todo propstat", JSON.stringify(propstats[0]));
                     if (!propstats[0] || !propstats[0]['d:prop']) {
                        continue; 
                     }
                     const calData = propstats[0]['d:prop']['cal:calendar-data'];
                     const unfolded = calData.replace(/\r?\n[ \t]/g, '');

                     const summaryMatch = calData.match(/SUMMARY:(.*)/);
                     const descriptionMatch = unfolded.match(/^DESCRIPTION(?:;[^:]*)?:(.*)$/m);
                     const statusMatch = calData.match(/STATUS:(.*)/);
                     const uidMatch = calData.match(/UID:(.*)/);
                     const dueMatch = calData.match(/DUE(?:;.*)?:(.*)/);
                     const priorityMatch = calData.match(/PRIORITY:(.*)/);

                     allTodos.push({
                         uid: uidMatch ? uidMatch[1].trim() : 'No UID',
                         calendar: cal.displayname,
                         summary: summaryMatch ? summaryMatch[1].trim() : 'No Title',
                         description: descriptionMatch ? descriptionMatch[1].trim() : null,
                         status: statusMatch ? statusMatch[1].trim() : 'NEEDS-ACTION',
                         due: dueMatch ? dueMatch[1].trim() : null,
                         priority: priorityMatch ? parseInt(priorityMatch[1].trim(), 10) : null
                     });
                 }
             } catch (e) {
                 // console.error("DEBUG: Error in calendar loop", e.message);
                 // ignore
             }
        }
        return allTodos;
    },

    async getCalendar(calendarName, componentType = null) {
        const calendars = await this.findCalendars(componentType);
        let targetCal = null;
        if (calendarName) {
            targetCal = matchByName(calendars, calendarName);
        } else if (calendars.length > 0) {
            targetCal = calendars[0];
        }

        if (!targetCal) {
            const typeDesc = componentType === 'VTODO' ? 'task-enabled ' : componentType === 'VEVENT' ? 'event-enabled ' : '';
            if (calendarName) {
                const available = calendars.map(c => c.displayname).join(', ') || '(none)';
                throw new Error(`${typeDesc}Calendar '${calendarName}' not found. Available: ${available}`);
            }
            throw new Error(`No ${typeDesc}calendars found.`);
        }
        return targetCal;
    },

    async findTaskPath(uid, calendarName) {
         const calendars = await this.findCalendars('VTODO');
         let searchTargets = calendars;
         if (calendarName) {
             const found = matchByName(calendars, calendarName);
             if (found) searchTargets = [found];
             else {
                 const available = calendars.map(c => c.displayname).join(', ') || '(none)';
                 throw new Error(`Task-enabled calendar '${calendarName}' not found. Available: ${available}`);
             }
         }

         const body = `
            <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
                <d:prop>
                    <d:getetag />
                    <c:calendar-data />
                </d:prop>
                <c:filter>
                    <c:comp-filter name="VCALENDAR">
                        <c:comp-filter name="VTODO">
                             <c:prop-filter name="UID">
                                <c:text-match collation="i;octet">${uid}</c:text-match>
                             </c:prop-filter>
                        </c:comp-filter>
                    </c:comp-filter>
                </c:filter>
            </c:calendar-query>
        `;

        for (const cal of searchTargets) {
            try {
                const response = await request(cal.url, {
                    method: 'REPORT',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' },
                    body: body
                });
                
                if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) continue;
                
                const responses = ensureArray(response['d:multistatus']['d:response']);
                
                if (responses.length > 0) {
                     const propstats = ensureArray(responses[0]['d:propstat']);
                     return {
                        href: responses[0]['d:href'],
                        etag: propstats[0]['d:prop']['d:getetag'],
                        data: propstats[0]['d:prop']['cal:calendar-data'],
                        calendarUrl: cal.url
                    };
                }
            } catch(e) { /* ignore */ }
        }
        return null;
    },
    
    _updateProperty(vcal, prop, value) {
        if (value === null || value === undefined) {
            return vcal;
        }
        // Match an existing line including any property parameters (e.g. DUE;TZID=Europe/London:...).
        const regex = new RegExp(`^${prop}(?:;[^:\\r\\n]*)?:.*$`, 'm');
        const newLine = `${prop}:${value}`;
        if (regex.test(vcal)) {
            return vcal.replace(regex, newLine);
        }
        const endMatch = vcal.match(/END:(VTODO|VEVENT)/);
        if (!endMatch) {
            throw new Error('Cannot insert property: no END:VTODO or END:VEVENT found in calendar data.');
        }
        return vcal.replace(endMatch[0], `${newLine}\n${endMatch[0]}`);
    },

    async createTask(title, calendarName, dueDate, priority, description) {
        const cal = await this.getCalendar(calendarName, 'VTODO');
        const uid = crypto.randomUUID();
        const now = new Date();
        const dtstamp = format(now, "yyyyMMdd'T'HHmmss'Z'");

        let vtodo = `BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//OpenClaw//Nextcloud Skill//EN\nBEGIN:VTODO\nUID:${uid}\nDTSTAMP:${dtstamp}\nSUMMARY:${escapePropertyValue(title)}\nSTATUS:NEEDS-ACTION\n`;

        if (dueDate) {
             const due = parseDateInput(dueDate);
             vtodo += `DUE:${format(due, "yyyyMMdd'T'HHmmss'Z'")}\n`;
        }

        if (priority) vtodo += `PRIORITY:${priority}\n`;
        if (description) vtodo += `DESCRIPTION:${escapePropertyValue(description)}\n`;

        vtodo += `END:VTODO\nEND:VCALENDAR`;

        const filename = `${uid}.ics`;
        const urlWithSlash = cal.url.endsWith('/') ? cal.url : cal.url + '/';
        const endpoint = `${urlWithSlash}${filename}`;

        await request(endpoint, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/calendar; charset=utf-8',
                'If-None-Match': '*'
            },
            body: vtodo
        });

        return { uid, status: 'created', calendar: cal.displayname };
    },

    async updateTask(uid, calendarName, updates) {
        const task = await this.findTaskPath(uid, calendarName);
        if (!task) throw new Error(`Task ${uid} not found.`);
        
        let vtodo = task.data;
        
        if (updates.title) vtodo = this._updateProperty(vtodo, 'SUMMARY', escapePropertyValue(updates.title));
        if (updates.priority) vtodo = this._updateProperty(vtodo, 'PRIORITY', updates.priority);
        if (updates.description) vtodo = this._updateProperty(vtodo, 'DESCRIPTION', escapePropertyValue(updates.description));
        if (updates.dueDate) {
             const due = parseDateInput(updates.dueDate);
             vtodo = this._updateProperty(vtodo, 'DUE', format(due, "yyyyMMdd'T'HHmmss'Z'"));
        }

        await request(task.href, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/calendar; charset=utf-8',
                'If-Match': task.etag
            },
            body: vtodo
        });
         return { uid, status: 'updated' };
    },

    async deleteTask(uid, calendarName) {
        const task = await this.findTaskPath(uid, calendarName);
        if (!task) throw new Error(`Task ${uid} not found.`);
        
        await request(task.href, {
            method: 'DELETE'
        });
        return { uid, status: 'deleted' };
    },

    async completeTask(uid, calendarName) {
        const task = await this.findTaskPath(uid, calendarName);
        if (!task) throw new Error(`Task ${uid} not found.`);
        
        let vtodo = task.data;
        const now = new Date();
        const completedDate = format(now, "yyyyMMdd'T'HHmmss'Z'");
        
        vtodo = this._updateProperty(vtodo, 'STATUS', 'COMPLETED');
        vtodo = this._updateProperty(vtodo, 'COMPLETED', completedDate);
        vtodo = this._updateProperty(vtodo, 'PERCENT-COMPLETE', '100');

        await request(task.href, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/calendar; charset=utf-8',
                'If-Match': task.etag
            },
            body: vtodo
        });
        return { uid, status: 'completed' };
    },

    // --- Calendar Events ---

    async createEvent(summary, start, end, calendarName, description, location) {
        const cal = await this.getCalendar(calendarName, 'VEVENT');
        const uid = crypto.randomUUID();
        const now = new Date();
        const dtstamp = format(now, "yyyyMMdd'T'HHmmss'Z'");

        const toCalDavDate = (dateStr) => {
            const d = parseDateInput(dateStr);
            return d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
        };

        let vevent = `BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//OpenClaw//Nextcloud Skill//EN\nBEGIN:VEVENT\nUID:${uid}\nDTSTAMP:${dtstamp}\nSUMMARY:${escapePropertyValue(summary)}\nDTSTART:${toCalDavDate(start)}\nDTEND:${toCalDavDate(end)}\n`;

        if (description) vevent += `DESCRIPTION:${escapePropertyValue(description)}\n`;
        if (location) vevent += `LOCATION:${escapePropertyValue(location)}\n`;

        vevent += `END:VEVENT\nEND:VCALENDAR`;

        const filename = `${uid}.ics`;
        const urlWithSlash = cal.url.endsWith('/') ? cal.url : cal.url + '/';
        const endpoint = `${urlWithSlash}${filename}`;

        await request(endpoint, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/calendar; charset=utf-8',
                'If-None-Match': '*'
            },
            body: vevent
        });

        return { uid, status: 'created', calendar: cal.displayname };
    },

    async findEventPath(uid, calendarName) {
        const calendars = await this.findCalendars('VEVENT');
        let searchTargets = calendars;
        if (calendarName) {
            const found = matchByName(calendars, calendarName);
            if (found) searchTargets = [found];
            else {
                const available = calendars.map(c => c.displayname).join(', ') || '(none)';
                throw new Error(`Event-enabled calendar '${calendarName}' not found. Available: ${available}`);
            }
        }

        const body = `
            <c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav">
                <d:prop>
                    <d:getetag />
                    <c:calendar-data />
                </d:prop>
                <c:filter>
                    <c:comp-filter name="VCALENDAR">
                        <c:comp-filter name="VEVENT">
                            <c:prop-filter name="UID">
                                <c:text-match collation="i;octet">${uid}</c:text-match>
                            </c:prop-filter>
                        </c:comp-filter>
                    </c:comp-filter>
                </c:filter>
            </c:calendar-query>
        `;

        for (const cal of searchTargets) {
            try {
                const response = await request(cal.url, {
                    method: 'REPORT',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' },
                    body: body
                });

                if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) continue;

                const responses = ensureArray(response['d:multistatus']['d:response']);

                if (responses.length > 0) {
                    const propstats = ensureArray(responses[0]['d:propstat']);
                    return {
                        href: responses[0]['d:href'],
                        etag: propstats[0]['d:prop']['d:getetag'],
                        data: propstats[0]['d:prop']['cal:calendar-data'],
                        calendarUrl: cal.url
                    };
                }
            } catch(e) { /* ignore */ }
        }
        return null;
    },

    async updateEvent(uid, calendarName, updates) {
        const event = await this.findEventPath(uid, calendarName);
        if (!event) throw new Error(`Event ${uid} not found.`);

        let vevent = event.data;

        if (updates.summary) vevent = this._updateProperty(vevent, 'SUMMARY', escapePropertyValue(updates.summary));
        if (updates.start) {
            const d = parseDateInput(updates.start);
            vevent = this._updateProperty(vevent, 'DTSTART', d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z');
        }
        if (updates.end) {
            const d = parseDateInput(updates.end);
            vevent = this._updateProperty(vevent, 'DTEND', d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z');
        }
        if (updates.description !== undefined) {
            vevent = this._updateProperty(vevent, 'DESCRIPTION', escapePropertyValue(updates.description));
        }
        if (updates.location !== undefined) {
            vevent = this._updateProperty(vevent, 'LOCATION', escapePropertyValue(updates.location));
        }

        await request(event.href, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/calendar; charset=utf-8',
                'If-Match': event.etag
            },
            body: vevent
        });
        return { uid, status: 'updated' };
    },

    async deleteEvent(uid, calendarName) {
        const event = await this.findEventPath(uid, calendarName);
        if (!event) throw new Error(`Event ${uid} not found.`);

        await request(event.href, {
            method: 'DELETE'
        });
        return { uid, status: 'deleted' };
    }
};

// 4. Shares (OCS Share API)
const Shares = {
    _ocsHeaders: { 'OCS-APIREQUEST': 'true', 'Accept': 'application/json' },

    _unwrap(envelope) {
        const meta = envelope && envelope.ocs && envelope.ocs.meta;
        if (!meta || meta.status !== 'ok') {
            throw new Error(`OCS error ${meta && meta.statuscode}: ${meta && meta.message}`);
        }
        return envelope.ocs.data;
    },

    _normalize(s) {
        const baseUrl = CONFIG.url.replace(/\/+$/, '');
        return {
            id: s.id,
            path: s.path,
            shareType: s.share_type,
            shareWith: s.share_with || null,
            permissions: s.permissions,
            token: s.token || null,
            url: s.url || (s.token ? `${baseUrl}/s/${s.token}` : null),
            expireDate: s.expiration || null
        };
    },

    async list({ path = null } = {}) {
        let endpoint = '/ocs/v2.php/apps/files_sharing/api/v1/shares';
        if (path) {
            const cleanPath = path.startsWith('/') ? path : `/${path}`;
            endpoint += `?path=${encodeURIComponent(cleanPath)}`;
        }
        const envelope = await request(endpoint, { method: 'GET', headers: this._ocsHeaders });
        const data = this._unwrap(envelope) || [];
        return (Array.isArray(data) ? data : [data]).map(s => this._normalize(s));
    },

    async createLink({ path, permissions = 'read', password = null, expireDate = null }) {
        if (!path) throw new Error('Missing path for share');
        const cleanPath = path.startsWith('/') ? path : `/${path}`;

        const permMap = {
            read: 1,    // read
            edit: 15    // create + read + update + delete
        };
        const perms = permMap[permissions];
        if (perms === undefined) {
            throw new Error(`Unknown --permissions '${permissions}'. Use 'read' or 'edit'.`);
        }

        const body = new URLSearchParams({
            path: cleanPath,
            shareType: '3', // public link
            permissions: String(perms)
        });
        if (password) body.set('password', password);
        if (expireDate) body.set('expireDate', expireDate);

        const envelope = await request('/ocs/v2.php/apps/files_sharing/api/v1/shares', {
            method: 'POST',
            headers: { ...this._ocsHeaders, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString()
        });
        const s = this._unwrap(envelope);
        return { ...this._normalize(s), passwordProtected: !!password };
    },

    async delete({ id }) {
        if (!id) throw new Error('Missing share id');
        const envelope = await request(
            `/ocs/v2.php/apps/files_sharing/api/v1/shares/${encodeURIComponent(id)}`,
            { method: 'DELETE', headers: this._ocsHeaders }
        );
        this._unwrap(envelope);
        return { id, status: 'deleted' };
    }
};

// 5. Contacts (CardDAV)
const Contacts = {
    async findAddressBooks() {
        const endpoint = `/remote.php/dav/addressbooks/users/${CONFIG.user}/`;
        const response = await request(endpoint, {
            method: 'PROPFIND',
            headers: { 'Depth': '1' }
        });

        if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) return [];

        const responses = ensureArray(response['d:multistatus']['d:response']);

        return responses.map(r => {
            const propstats = ensureArray(r['d:propstat']);
            if (!propstats[0] || !propstats[0]['d:prop']) return null;
            const props = propstats[0]['d:prop'];

            // Check if it's an address book (has card:addressbook in resourcetype)
            if (!props['d:resourcetype'] || !('card:addressbook' in props['d:resourcetype'])) return null;

            // Use displayname if available, otherwise extract from URL path
            let name = props['d:displayname'];
            if (!name) {
                // Extract last path segment from URL (e.g., /remote.php/dav/addressbooks/users/keith/contacts/ -> contacts)
                const urlParts = r['d:href'].split('/').filter(p => p);
                name = urlParts[urlParts.length - 1] || 'Unnamed';
            }

            return {
                url: r['d:href'],
                displayname: name
            };
        }).filter(a => a);
    },

    async getAddressBook(addressBookName) {
        const addressBooks = await this.findAddressBooks();
        let target = null;
        if (addressBookName) {
            target = matchByName(addressBooks, addressBookName);
        } else if (addressBooks.length > 0) {
            target = addressBooks[0];
        }

        if (!target) {
            if (addressBookName) {
                const available = addressBooks.map(a => a.displayname).join(', ') || '(none)';
                throw new Error(`Address book '${addressBookName}' not found. Available: ${available}`);
            }
            throw new Error('No address books found.');
        }
        return target;
    },

    async list(addressBookName = null) {
        let addressBooks = await this.findAddressBooks();
        if (addressBookName) {
            const matched = matchByName(addressBooks, addressBookName);
            if (!matched) {
                const available = addressBooks.map(a => a.displayname).join(', ') || '(none)';
                throw new Error(`Address book '${addressBookName}' not found. Available: ${available}`);
            }
            addressBooks = [matched];
        }

        const allContacts = [];

        const body = `
            <card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
                <d:prop>
                    <d:getetag />
                    <card:address-data />
                </d:prop>
            </card:addressbook-query>
        `;

        for (const ab of addressBooks) {
            try {
                const response = await request(ab.url, {
                    method: 'REPORT',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' },
                    body: body
                });

                if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) continue;
                const responses = ensureArray(response['d:multistatus']['d:response']);

                for (const r of responses) {
                    const propstats = ensureArray(r['d:propstat']);
                    if (!propstats[0] || !propstats[0]['d:prop']) continue;

                    const cardData = propstats[0]['d:prop']['card:address-data'];
                    if (!cardData) continue;

                    const contact = this._parseVCard(cardData);
                    contact.addressBook = ab.displayname;
                    contact.href = r['d:href'];
                    allContacts.push(contact);
                }
            } catch (e) {
                // ignore errors for individual address books
            }
        }
        return allContacts;
    },

    _parseVCard(vcard) {
        // Normalize line endings (vCard uses CRLF, and XML may encode CR as &#13;)
        const cleanValue = (val) => val ? val.replace(/&#13;/g, '').replace(/\r/g, '').trim() : null;

        const getField = (field) => {
            const regex = new RegExp(`^(?:[A-Za-z0-9-]+\\.)?${field}(?:;[^:\\r\\n]*)?:(.*)$`, 'mi');
            const match = vcard.match(regex);
            return match ? cleanValue(match[1]) : null;
        };

        const uid = getField('UID');
        const fn = getField('FN'); // Full Name
        const n = getField('N');   // Structured Name: Last;First;Middle;Prefix;Suffix

        // Parse phone numbers (can have multiple)
        const phones = [];
        const phoneRegex = /^(?:[A-Za-z0-9-]+\.)?TEL(?:;[^:\r\n]*)?:(.*)$/gmi;
        let phoneMatch;
        while ((phoneMatch = phoneRegex.exec(vcard)) !== null) {
            phones.push(cleanValue(phoneMatch[1]));
        }

        // Parse emails (can have multiple)
        const emails = [];
        const emailRegex = /^(?:[A-Za-z0-9-]+\.)?EMAIL(?:;[^:\r\n]*)?:(.*)$/gmi;
        let emailMatch;
        while ((emailMatch = emailRegex.exec(vcard)) !== null) {
            emails.push(cleanValue(emailMatch[1]));
        }

        const org = getField('ORG');
        const title = getField('TITLE');
        const note = getField('NOTE');

        return {
            uid: uid,
            fullName: fn,
            name: n,
            phones: phones.length > 0 ? phones : null,
            emails: emails.length > 0 ? emails : null,
            organization: org,
            title: title,
            note: note
        };
    },

    async get(uid, addressBookName = null) {
        const contacts = await this.list(addressBookName);
        const contact = contacts.find(c => c.uid === uid);
        if (!contact) {
            throw new Error(`Contact with UID '${uid}' not found.`);
        }
        return contact;
    },

    async findContactPath(uid, addressBookName = null) {
        let addressBooks = await this.findAddressBooks();
        if (addressBookName) {
            const found = matchByName(addressBooks, addressBookName);
            if (found) addressBooks = [found];
            else {
                const available = addressBooks.map(a => a.displayname).join(', ') || '(none)';
                throw new Error(`Address book '${addressBookName}' not found. Available: ${available}`);
            }
        }

        const body = `
            <card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
                <d:prop>
                    <d:getetag />
                    <card:address-data />
                </d:prop>
                <card:filter>
                    <card:prop-filter name="UID">
                        <card:text-match collation="i;octet">${uid}</card:text-match>
                    </card:prop-filter>
                </card:filter>
            </card:addressbook-query>
        `;

        for (const ab of addressBooks) {
            try {
                const response = await request(ab.url, {
                    method: 'REPORT',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' },
                    body: body
                });

                if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) continue;

                const responses = ensureArray(response['d:multistatus']['d:response']);

                if (responses.length > 0) {
                    const propstats = ensureArray(responses[0]['d:propstat']);
                    return {
                        href: responses[0]['d:href'],
                        etag: propstats[0]['d:prop']['d:getetag'],
                        data: propstats[0]['d:prop']['card:address-data'],
                        addressBookUrl: ab.url
                    };
                }
            } catch(e) { /* ignore */ }
        }
        return null;
    },

    async create(fullName, addressBookName, options = {}) {
        const ab = await this.getAddressBook(addressBookName);
        const uid = crypto.randomUUID();

        const escapedFn = escapePropertyValue(fullName);
        let vcard = `BEGIN:VCARD\nVERSION:3.0\nUID:${uid}\nFN:${escapedFn}\n`;

        // Parse name into structured format if possible.
        // N components are semicolon-delimited; escape each component individually.
        const nameParts = fullName.split(' ');
        if (nameParts.length >= 2) {
            const lastName = escapePropertyValue(nameParts[nameParts.length - 1]);
            const firstName = escapePropertyValue(nameParts.slice(0, -1).join(' '));
            vcard += `N:${lastName};${firstName};;;\n`;
        } else {
            vcard += `N:${escapedFn};;;;\n`;
        }

        if (options.email) vcard += `EMAIL:${escapePropertyValue(options.email)}\n`;
        if (options.phone) vcard += `TEL:${escapePropertyValue(options.phone)}\n`;
        if (options.organization) vcard += `ORG:${escapePropertyValue(options.organization)}\n`;
        if (options.title) vcard += `TITLE:${escapePropertyValue(options.title)}\n`;
        if (options.note) vcard += `NOTE:${escapePropertyValue(options.note)}\n`;

        vcard += `END:VCARD`;

        const filename = `${uid}.vcf`;
        const urlWithSlash = ab.url.endsWith('/') ? ab.url : ab.url + '/';
        const endpoint = `${urlWithSlash}${filename}`;

        await request(endpoint, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/vcard; charset=utf-8',
                'If-None-Match': '*'
            },
            body: vcard
        });

        return { uid, status: 'created', addressBook: ab.displayname };
    },

    _updateVCardField(vcard, field, value) {
        const regex = new RegExp(`^((?:[A-Za-z0-9-]+\\.)?${field}(?:;[^:\\r\\n]*)?:).*$`, 'mi');
        const newLine = `${field}:${value}`;
        if (regex.test(vcard)) {
            return vcard.replace(regex, (match, prefix) => `${prefix}${value}`);
        } else {
            return vcard.replace('END:VCARD', `${newLine}\nEND:VCARD`);
        }
    },

    async update(uid, addressBookName, updates) {
        const contact = await this.findContactPath(uid, addressBookName);
        if (!contact) throw new Error(`Contact ${uid} not found.`);

        let vcard = contact.data;

        if (updates.fullName) {
            vcard = this._updateVCardField(vcard, 'FN', escapePropertyValue(updates.fullName));
            // Update structured name too
            const nameParts = updates.fullName.split(' ');
            if (nameParts.length >= 2) {
                const lastName = escapePropertyValue(nameParts[nameParts.length - 1]);
                const firstName = escapePropertyValue(nameParts.slice(0, -1).join(' '));
                vcard = this._updateVCardField(vcard, 'N', `${lastName};${firstName};;;`);
            }
        }
        if (updates.email) vcard = this._updateVCardField(vcard, 'EMAIL', escapePropertyValue(updates.email));
        if (updates.phone) vcard = this._updateVCardField(vcard, 'TEL', escapePropertyValue(updates.phone));
        if (updates.organization) vcard = this._updateVCardField(vcard, 'ORG', escapePropertyValue(updates.organization));
        if (updates.title) vcard = this._updateVCardField(vcard, 'TITLE', escapePropertyValue(updates.title));
        if (updates.note) vcard = this._updateVCardField(vcard, 'NOTE', escapePropertyValue(updates.note));

        await request(contact.href, {
            method: 'PUT',
            headers: {
                'Content-Type': 'text/vcard; charset=utf-8',
                'If-Match': contact.etag
            },
            body: vcard
        });

        return { uid, status: 'updated' };
    },

    async delete(uid, addressBookName = null) {
        const contact = await this.findContactPath(uid, addressBookName);
        if (!contact) throw new Error(`Contact ${uid} not found.`);

        await request(contact.href, {
            method: 'DELETE'
        });

        return { uid, status: 'deleted' };
    },

    async search(query, addressBookName = null) {
        let addressBooks = await this.findAddressBooks();
        if (addressBookName) {
            const matched = matchByName(addressBooks, addressBookName);
            if (!matched) {
                const available = addressBooks.map(a => a.displayname).join(', ') || '(none)';
                throw new Error(`Address book '${addressBookName}' not found. Available: ${available}`);
            }
            addressBooks = [matched];
        }

        const allContacts = [];

        // CardDAV search using text-match
        const body = `
            <card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
                <d:prop>
                    <d:getetag />
                    <card:address-data />
                </d:prop>
                <card:filter test="anyof">
                    <card:prop-filter name="FN">
                        <card:text-match collation="i;unicode-casemap" match-type="contains">${query}</card:text-match>
                    </card:prop-filter>
                    <card:prop-filter name="EMAIL">
                        <card:text-match collation="i;unicode-casemap" match-type="contains">${query}</card:text-match>
                    </card:prop-filter>
                    <card:prop-filter name="TEL">
                        <card:text-match collation="i;unicode-casemap" match-type="contains">${query}</card:text-match>
                    </card:prop-filter>
                    <card:prop-filter name="ORG">
                        <card:text-match collation="i;unicode-casemap" match-type="contains">${query}</card:text-match>
                    </card:prop-filter>
                </card:filter>
            </card:addressbook-query>
        `;

        for (const ab of addressBooks) {
            try {
                const response = await request(ab.url, {
                    method: 'REPORT',
                    headers: { 'Depth': '1', 'Content-Type': 'application/xml' },
                    body: body
                });

                if (!response['d:multistatus'] || !response['d:multistatus']['d:response']) continue;
                const responses = ensureArray(response['d:multistatus']['d:response']);

                for (const r of responses) {
                    const propstats = ensureArray(r['d:propstat']);
                    if (!propstats[0] || !propstats[0]['d:prop']) continue;

                    const cardData = propstats[0]['d:prop']['card:address-data'];
                    if (!cardData) continue;

                    const contact = this._parseVCard(cardData);
                    contact.addressBook = ab.displayname;
                    contact.href = r['d:href'];
                    allContacts.push(contact);
                }
            } catch (e) {
                // ignore errors for individual address books
            }
        }
        return allContacts;
    }
};

// 6. Deck (Kanban boards, stacks, cards, labels, comments)
const Deck = {
    // Deck REST lives under /index.php/apps/deck/api/v1.1; comments use the OCS v1.0 endpoint.
    _base: '/index.php/apps/deck/api/v1.1',
    _headers: { 'OCS-APIRequest': 'true', 'Accept': 'application/json' },
    _jsonHeaders: { 'OCS-APIRequest': 'true', 'Accept': 'application/json', 'Content-Type': 'application/json' },

    _boardUrl(id) {
        const baseUrl = CONFIG.url.replace(/\/+$/, '');
        return `${baseUrl}/index.php/apps/deck/#/board/${id}`;
    },

    _normalizeBoard(b) {
        return {
            id: b.id,
            title: b.title,
            color: b.color,
            archived: b.archived,
            owner: b.owner && b.owner.uid,
            permissions: b.permissions,
            labelCount: Array.isArray(b.labels) ? b.labels.length : undefined,
            stackCount: Array.isArray(b.stacks) ? b.stacks.length : undefined,
            lastModified: b.lastModified,
            url: this._boardUrl(b.id)
        };
    },

    _normalizeCard(c) {
        return {
            id: c.id,
            title: c.title,
            description: c.description,
            stackId: c.stackId,
            type: c.type,
            order: c.order,
            labels: (c.labels || []).map(l => ({ id: l.id, title: l.title, color: l.color })),
            assignedUsers: (c.assignedUsers || []).map(u => (u.participant && u.participant.uid) || u.uid),
            duedate: c.duedate || null,
            done: c.done || null,
            archived: c.archived,
            commentsCount: c.commentsCount,
            createdAt: c.createdAt,
            lastModified: c.lastModified
        };
    },

    // --- Boards ---
    async listBoards() {
        const data = await request(`${this._base}/boards`, { headers: this._headers });
        // Deck DELETE is a soft-delete (sets deletedAt); hide those from listings.
        return (data || []).filter(b => !b.deletedAt).map(b => this._normalizeBoard(b));
    },

    async getBoard(boardId) {
        if (!boardId) throw new Error('Board ID is required.');
        return await request(`${this._base}/boards/${boardId}`, { headers: this._headers });
    },

    async createBoard(title, color = '0082c9') {
        if (!title || title.trim() === '') throw new Error('Title is required for creating a board.');
        const data = await request(`${this._base}/boards`, {
            method: 'POST',
            headers: this._jsonHeaders,
            body: JSON.stringify({ title, color })
        });
        return this._normalizeBoard(data);
    },

    async editBoard(boardId, updates = {}) {
        if (!boardId) throw new Error('Board ID is required for update.');
        // Deck PUT replaces the board; merge onto the current state (read-modify-write).
        const current = await this.getBoard(boardId);
        const payload = {
            title: updates.title !== undefined ? updates.title : current.title,
            color: updates.color !== undefined ? updates.color : current.color,
            archived: updates.archived !== undefined ? updates.archived : current.archived
        };
        const data = await request(`${this._base}/boards/${boardId}`, {
            method: 'PUT',
            headers: this._jsonHeaders,
            body: JSON.stringify(payload)
        });
        return this._normalizeBoard(data);
    },

    async deleteBoard(boardId) {
        if (!boardId) throw new Error('Board ID is required for deletion.');
        await request(`${this._base}/boards/${boardId}`, { method: 'DELETE', headers: this._headers });
        return { success: true, id: boardId };
    },

    // --- Stacks (columns) ---
    async listStacks(boardId) {
        if (!boardId) throw new Error('Board ID is required.');
        const data = await request(`${this._base}/boards/${boardId}/stacks`, { headers: this._headers });
        return (data || []).map(s => ({
            id: s.id,
            title: s.title,
            boardId: s.boardId,
            order: s.order,
            cards: (s.cards || []).map(c => this._normalizeCard(c)),
            cardCount: (s.cards || []).length,
            lastModified: s.lastModified
        }));
    },

    async createStack(boardId, title, order = 999) {
        if (!boardId) throw new Error('Board ID is required.');
        if (!title || title.trim() === '') throw new Error('Title is required for creating a stack.');
        const data = await request(`${this._base}/boards/${boardId}/stacks`, {
            method: 'POST',
            headers: this._jsonHeaders,
            body: JSON.stringify({ title, order })
        });
        return { id: data.id, title: data.title, boardId: data.boardId, order: data.order };
    },

    async editStack(boardId, stackId, updates = {}) {
        if (!boardId || !stackId) throw new Error('Board ID and Stack ID are required for update.');
        const stacks = await this.listStacks(boardId);
        const current = stacks.find(s => String(s.id) === String(stackId));
        if (!current) throw new Error(`Stack ${stackId} not found on board ${boardId}.`);
        const payload = {
            title: updates.title !== undefined ? updates.title : current.title,
            order: updates.order !== undefined ? updates.order : current.order
        };
        const data = await request(`${this._base}/boards/${boardId}/stacks/${stackId}`, {
            method: 'PUT',
            headers: this._jsonHeaders,
            body: JSON.stringify(payload)
        });
        return { id: data.id, title: data.title, boardId: data.boardId, order: data.order };
    },

    async deleteStack(boardId, stackId) {
        if (!boardId || !stackId) throw new Error('Board ID and Stack ID are required for deletion.');
        await request(`${this._base}/boards/${boardId}/stacks/${stackId}`, { method: 'DELETE', headers: this._headers });
        return { success: true, id: stackId };
    },

    // --- Cards ---
    async listCards(boardId, stackId = null) {
        if (!boardId) throw new Error('Board ID is required.');
        const stacks = await this.listStacks(boardId);
        const filtered = stackId !== null ? stacks.filter(s => String(s.id) === String(stackId)) : stacks;
        return filtered.flatMap(s => s.cards.map(c => ({ ...c, stackTitle: s.title })));
    },

    async getCard(boardId, stackId, cardId) {
        if (!boardId || !stackId || !cardId) throw new Error('Board ID, Stack ID and Card ID are required.');
        return await request(`${this._base}/boards/${boardId}/stacks/${stackId}/cards/${cardId}`, { headers: this._headers });
    },

    async createCard(boardId, stackId, title, options = {}) {
        if (!boardId || !stackId) throw new Error('Board ID and Stack ID are required.');
        if (!title || title.trim() === '') throw new Error('Title is required for creating a card.');
        const payload = { title, type: 'plain', order: options.order !== undefined ? options.order : 999 };
        if (options.description !== undefined) payload.description = options.description;
        if (options.duedate !== undefined) payload.duedate = options.duedate;
        const data = await request(`${this._base}/boards/${boardId}/stacks/${stackId}/cards`, {
            method: 'POST',
            headers: this._jsonHeaders,
            body: JSON.stringify(payload)
        });
        return this._normalizeCard(data);
    },

    async editCard(boardId, stackId, cardId, updates = {}) {
        if (!boardId || !stackId || !cardId) throw new Error('Board ID, Stack ID and Card ID are required for update.');
        // Deck PUT replaces the card; merge onto the current state (read-modify-write).
        const current = await this.getCard(boardId, stackId, cardId);
        const payload = {
            title: updates.title !== undefined ? updates.title : current.title,
            description: updates.description !== undefined ? updates.description : current.description,
            type: current.type || 'plain',
            owner: (current.owner && current.owner.uid) || current.owner,
            order: updates.order !== undefined ? updates.order : current.order,
            duedate: updates.duedate !== undefined ? updates.duedate : current.duedate
        };
        if (updates.done !== undefined) payload.done = updates.done; // ISO string or null
        else if (current.done) payload.done = current.done;
        if (updates.archived !== undefined) payload.archived = updates.archived;
        else payload.archived = current.archived;
        const data = await request(`${this._base}/boards/${boardId}/stacks/${stackId}/cards/${cardId}`, {
            method: 'PUT',
            headers: this._jsonHeaders,
            body: JSON.stringify(payload)
        });
        return this._normalizeCard(data);
    },

    async deleteCard(boardId, stackId, cardId) {
        if (!boardId || !stackId || !cardId) throw new Error('Board ID, Stack ID and Card ID are required for deletion.');
        await request(`${this._base}/boards/${boardId}/stacks/${stackId}/cards/${cardId}`, { method: 'DELETE', headers: this._headers });
        return { success: true, id: cardId };
    },

    async moveCard(boardId, stackId, cardId, toStackId, order = 999) {
        if (!boardId || !stackId || !cardId || !toStackId) {
            throw new Error('Board ID, Stack ID, Card ID and target --to-stack are required for move.');
        }
        // Deck's reorder endpoint expects the *target* stack in the path (and body);
        // the card's current stack is irrelevant to the move itself.
        const data = await request(`${this._base}/boards/${boardId}/stacks/${toStackId}/cards/${cardId}/reorder`, {
            method: 'PUT',
            headers: this._jsonHeaders,
            body: JSON.stringify({ order, stackId: Number(toStackId) })
        });
        // reorder returns the moved stack's cards; surface the moved card.
        const moved = Array.isArray(data)
            ? data.find(c => String(c.id) === String(cardId))
            : (data && data.cards ? data.cards.find(c => String(c.id) === String(cardId)) : data);
        return moved ? this._normalizeCard(moved) : { success: true, id: cardId, stackId: Number(toStackId) };
    },

    async assignLabel(boardId, stackId, cardId, labelId) {
        if (!boardId || !stackId || !cardId || !labelId) throw new Error('Board, Stack, Card and Label IDs are required.');
        await request(`${this._base}/boards/${boardId}/stacks/${stackId}/cards/${cardId}/assignLabel`, {
            method: 'PUT',
            headers: this._jsonHeaders,
            body: JSON.stringify({ labelId: Number(labelId) })
        });
        return { success: true, cardId, labelId, assigned: true };
    },

    async removeLabel(boardId, stackId, cardId, labelId) {
        if (!boardId || !stackId || !cardId || !labelId) throw new Error('Board, Stack, Card and Label IDs are required.');
        await request(`${this._base}/boards/${boardId}/stacks/${stackId}/cards/${cardId}/removeLabel`, {
            method: 'PUT',
            headers: this._jsonHeaders,
            body: JSON.stringify({ labelId: Number(labelId) })
        });
        return { success: true, cardId, labelId, assigned: false };
    },

    // --- Labels ---
    async listLabels(boardId) {
        if (!boardId) throw new Error('Board ID is required.');
        const board = await this.getBoard(boardId);
        return (board.labels || []).map(l => ({ id: l.id, title: l.title, color: l.color, boardId: l.boardId }));
    },

    async createLabel(boardId, title, color) {
        if (!boardId) throw new Error('Board ID is required.');
        if (!title || title.trim() === '') throw new Error('Title is required for creating a label.');
        if (!color) throw new Error('Color (hex, e.g. FF0000) is required for creating a label.');
        const data = await request(`${this._base}/boards/${boardId}/labels`, {
            method: 'POST',
            headers: this._jsonHeaders,
            body: JSON.stringify({ title, color })
        });
        return { id: data.id, title: data.title, color: data.color, boardId: data.boardId };
    },

    async editLabel(boardId, labelId, updates = {}) {
        if (!boardId || !labelId) throw new Error('Board ID and Label ID are required for update.');
        const labels = await this.listLabels(boardId);
        const current = labels.find(l => String(l.id) === String(labelId));
        if (!current) throw new Error(`Label ${labelId} not found on board ${boardId}.`);
        const payload = {
            title: updates.title !== undefined ? updates.title : current.title,
            color: updates.color !== undefined ? updates.color : current.color
        };
        const data = await request(`${this._base}/boards/${boardId}/labels/${labelId}`, {
            method: 'PUT',
            headers: this._jsonHeaders,
            body: JSON.stringify(payload)
        });
        return { id: data.id, title: data.title, color: data.color, boardId: data.boardId };
    },

    async deleteLabel(boardId, labelId) {
        if (!boardId || !labelId) throw new Error('Board ID and Label ID are required for deletion.');
        await request(`${this._base}/boards/${boardId}/labels/${labelId}`, { method: 'DELETE', headers: this._headers });
        return { success: true, id: labelId };
    },

    // --- Comments (OCS Deck API) ---
    _commentsBase(cardId) {
        return `/ocs/v2.php/apps/deck/api/v1.0/cards/${cardId}/comments`;
    },

    _unwrapOcs(envelope) {
        const meta = envelope && envelope.ocs && envelope.ocs.meta;
        if (!meta || (meta.status !== 'ok' && meta.statuscode >= 300)) {
            throw new Error(`OCS error ${meta && meta.statuscode}: ${meta && meta.message}`);
        }
        return envelope.ocs.data;
    },

    async listComments(cardId) {
        if (!cardId) throw new Error('Card ID is required.');
        const envelope = await request(this._commentsBase(cardId), { headers: this._headers });
        const data = this._unwrapOcs(envelope) || [];
        return (Array.isArray(data) ? data : [data]).map(c => ({
            id: c.id,
            message: c.message,
            actorId: c.actorId,
            actorDisplayName: c.actorDisplayName,
            creationDateTime: c.creationDateTime
        }));
    },

    async addComment(cardId, message) {
        if (!cardId) throw new Error('Card ID is required.');
        if (!message || message.trim() === '') throw new Error('Message is required for a comment.');
        const envelope = await request(this._commentsBase(cardId), {
            method: 'POST',
            headers: this._jsonHeaders,
            body: JSON.stringify({ message })
        });
        const c = this._unwrapOcs(envelope);
        return { id: c.id, message: c.message, actorId: c.actorId, creationDateTime: c.creationDateTime };
    },

    async deleteComment(cardId, commentId) {
        if (!cardId || !commentId) throw new Error('Card ID and Comment ID are required for deletion.');
        const envelope = await request(`${this._commentsBase(cardId)}/${commentId}`, {
            method: 'DELETE', headers: this._headers
        });
        this._unwrapOcs(envelope);
        return { success: true, id: commentId };
    }
};


// --- Main ---

async function main() {
    const args = process.argv.slice(2);
    const command = args[0];
    const subCommand = args[1];

    try {
        if (command === 'notes') {
            if (subCommand === 'list') {
                const result = await Notes.list();
                output(result);
            } else if (subCommand === 'get') {
                const idIndex = args.indexOf('--id');
                if (idIndex === -1) throw new Error('Missing --id');
                const result = await Notes.get(args[idIndex + 1]);
                output(result);
            } else if (subCommand === 'create') {
                const titleIndex = args.indexOf('--title');
                const contentIndex = args.indexOf('--content');
                const categoryIndex = args.indexOf('--category');
                
                if (titleIndex === -1 || contentIndex === -1) {
                    throw new Error('Missing --title or --content arguments');
                }
                
                const title = args[titleIndex + 1];
                const content = args[contentIndex + 1];
                const category = categoryIndex !== -1 ? args[categoryIndex + 1] : '';

                if (!title || title.startsWith('--')) throw new Error('Invalid title provided');
                if (!content || content.startsWith('--')) throw new Error('Invalid content provided');
                if (category && category.startsWith('--')) throw new Error('Invalid category provided');

                const result = await Notes.create(title, content, category);
                output(result);
            } else if (subCommand === 'edit') {
                const idIndex = args.indexOf('--id');
                const titleIndex = args.indexOf('--title');
                const contentIndex = args.indexOf('--content');
                const categoryIndex = args.indexOf('--category');

                if (idIndex === -1) throw new Error('Missing --id');

                const id = args[idIndex + 1];
                const title = titleIndex !== -1 ? args[titleIndex + 1] : undefined;
                const content = contentIndex !== -1 ? args[contentIndex + 1] : undefined;
                const category = categoryIndex !== -1 ? args[categoryIndex + 1] : undefined;

                const result = await Notes.update(id, title, content, category);
                output(result);
            } else if (subCommand === 'delete') {
                const idIndex = args.indexOf('--id');
                if (idIndex === -1) throw new Error('Missing --id');
                const result = await Notes.delete(args[idIndex + 1]);
                output(result);
            } else {
                throw new Error('Unknown notes command');
            }
        } else if (command === 'files') {
            if (subCommand === 'list') {
                const pathIndex = args.indexOf('--path');
                const path = pathIndex !== -1 ? args[pathIndex + 1] : '/';
                const result = await Files.list(path);
                output(result);
            } else if (subCommand === 'search') {
                const queryIndex = args.indexOf('--query');
                if (queryIndex === -1) throw new Error('Missing --query');
                const result = await Files.search(args[queryIndex + 1]);
                output(result);
            } else if (subCommand === 'upload') {
                const pathIndex = args.indexOf('--path');
                if (pathIndex === -1) throw new Error('Missing --path');
                const filePath = args[pathIndex + 1];

                const contentIndex = args.indexOf('--content');
                if (contentIndex === -1) throw new Error('Missing --content');
                const content = args[contentIndex + 1];

                output(await Files.upload(filePath, content));
            } else if (subCommand === 'get') {
                const pathIndex = args.indexOf('--path');
                if (pathIndex === -1) throw new Error('Missing --path');
                output(await Files.get(args[pathIndex + 1]));
            } else if (subCommand === 'delete') {
                const pathIndex = args.indexOf('--path');
                if (pathIndex === -1) throw new Error('Missing --path');
                output(await Files.delete(args[pathIndex + 1]));
            } else {
                throw new Error('Unknown files command');
            }
        } else if (command === 'calendar') {
             if (subCommand === 'list') {
                const fromIndex = args.indexOf('--from');
                const toIndex = args.indexOf('--to');
                const start = fromIndex !== -1 ? args[fromIndex + 1] : formatISO(new Date());
                const end = toIndex !== -1 ? args[toIndex + 1] : formatISO(addDays(new Date(), 7));
                const result = await CalDAV.getEvents(start, end);
                output(result);
            } else if (subCommand === 'create') {
                const summaryIndex = args.indexOf('--summary');
                if (summaryIndex === -1) throw new Error('Missing --summary');
                const summary = args[summaryIndex + 1];

                const startIndex = args.indexOf('--start');
                if (startIndex === -1) throw new Error('Missing --start');
                const start = args[startIndex + 1];

                const endIndex = args.indexOf('--end');
                if (endIndex === -1) throw new Error('Missing --end');
                const end = args[endIndex + 1];

                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;

                const descIndex = args.indexOf('--description');
                const description = descIndex !== -1 ? args[descIndex + 1] : null;

                const locIndex = args.indexOf('--location');
                const location = locIndex !== -1 ? args[locIndex + 1] : null;

                output(await CalDAV.createEvent(summary, start, end, calendar, description, location));
            } else if (subCommand === 'edit') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];

                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;

                const updates = {};
                const summaryIndex = args.indexOf('--summary');
                if (summaryIndex !== -1) updates.summary = args[summaryIndex + 1];

                const startIndex = args.indexOf('--start');
                if (startIndex !== -1) updates.start = args[startIndex + 1];

                const endIndex = args.indexOf('--end');
                if (endIndex !== -1) updates.end = args[endIndex + 1];

                const descIndex = args.indexOf('--description');
                if (descIndex !== -1) updates.description = args[descIndex + 1];

                const locIndex = args.indexOf('--location');
                if (locIndex !== -1) updates.location = args[locIndex + 1];

                output(await CalDAV.updateEvent(uid, calendar, updates));
            } else if (subCommand === 'delete') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];

                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;

                output(await CalDAV.deleteEvent(uid, calendar));
            } else {
                throw new Error('Unknown calendar command');
            }
        } else if (command === 'tasks') {
             if (subCommand === 'list') {
                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;
                const result = await CalDAV.getTodos(calendar);
                output(result);
             } else if (subCommand === 'create') {
                const titleIndex = args.indexOf('--title');
                if (titleIndex === -1) throw new Error('Missing --title');
                const title = args[titleIndex + 1];
                
                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;

                const dueIndex = args.indexOf('--due');
                const dueDate = dueIndex !== -1 ? args[dueIndex + 1] : null;

                const prioIndex = args.indexOf('--priority');
                const priority = prioIndex !== -1 ? args[prioIndex + 1] : null;

                const descIndex = args.indexOf('--description');
                const description = descIndex !== -1 ? args[descIndex + 1] : null;

                output(await CalDAV.createTask(title, calendar, dueDate, priority, description));

             } else if (subCommand === 'edit') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];

                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;

                const updates = {};
                const titleIndex = args.indexOf('--title');
                if (titleIndex !== -1) updates.title = args[titleIndex + 1];
                
                const dueIndex = args.indexOf('--due');
                if (dueIndex !== -1) updates.dueDate = args[dueIndex + 1];
                
                const prioIndex = args.indexOf('--priority');
                if (prioIndex !== -1) updates.priority = args[prioIndex + 1];
                
                const descIndex = args.indexOf('--description');
                if (descIndex !== -1) updates.description = args[descIndex + 1];

                output(await CalDAV.updateTask(uid, calendar, updates));

             } else if (subCommand === 'delete') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];
                
                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;

                output(await CalDAV.deleteTask(uid, calendar));

             } else if (subCommand === 'complete') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];

                const calIndex = args.indexOf('--calendar');
                const calendar = calIndex !== -1 ? args[calIndex + 1] : null;

                output(await CalDAV.completeTask(uid, calendar));
             } else {
                 throw new Error('Unknown tasks command');
             }
        } else if (command === 'calendars') {
            if (subCommand === 'list') {
                const typeIndex = args.indexOf('--type');
                const type = typeIndex !== -1 ? args[typeIndex + 1] : null;
                let componentType = null;
                if (type === 'tasks') componentType = 'VTODO';
                else if (type === 'events') componentType = 'VEVENT';
                const calendars = await CalDAV.findCalendars(componentType);
                output(calendars.map(c => ({ name: c.displayname, type: c.componentType === 'VTODO' ? 'tasks' : 'events' })));
            } else {
                throw new Error('Unknown calendars command');
            }
        } else if (command === 'addressbooks') {
            if (subCommand === 'list') {
                const addressBooks = await Contacts.findAddressBooks();
                output(addressBooks.map(a => ({ name: a.displayname })));
            } else {
                throw new Error('Unknown addressbooks command');
            }
        } else if (command === 'shares') {
            if (subCommand === 'create-link') {
                const pathIndex = args.indexOf('--path');
                if (pathIndex === -1) throw new Error('Missing --path');
                const sharePath = args[pathIndex + 1];

                const permIndex = args.indexOf('--permissions');
                const permissions = permIndex !== -1 ? args[permIndex + 1] : 'read';

                const pwIndex = args.indexOf('--password');
                const password = pwIndex !== -1 ? args[pwIndex + 1] : null;

                const expIndex = args.indexOf('--expire');
                const expireDate = expIndex !== -1 ? args[expIndex + 1] : null;

                output(await Shares.createLink({ path: sharePath, permissions, password, expireDate }));
            } else if (subCommand === 'list') {
                const pathIndex = args.indexOf('--path');
                const sharePath = pathIndex !== -1 ? args[pathIndex + 1] : null;
                output(await Shares.list({ path: sharePath }));
            } else if (subCommand === 'delete') {
                const idIndex = args.indexOf('--id');
                if (idIndex === -1) throw new Error('Missing --id');
                output(await Shares.delete({ id: args[idIndex + 1] }));
            } else {
                throw new Error('Unknown shares command');
            }
        } else if (command === 'contacts') {
            if (subCommand === 'list') {
                const abIndex = args.indexOf('--addressbook');
                const addressBook = abIndex !== -1 ? args[abIndex + 1] : null;
                const result = await Contacts.list(addressBook);
                output(result);
            } else if (subCommand === 'get') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];

                const abIndex = args.indexOf('--addressbook');
                const addressBook = abIndex !== -1 ? args[abIndex + 1] : null;

                output(await Contacts.get(uid, addressBook));
            } else if (subCommand === 'search') {
                const queryIndex = args.indexOf('--query');
                if (queryIndex === -1) throw new Error('Missing --query');
                const query = args[queryIndex + 1];

                const abIndex = args.indexOf('--addressbook');
                const addressBook = abIndex !== -1 ? args[abIndex + 1] : null;

                output(await Contacts.search(query, addressBook));
            } else if (subCommand === 'create') {
                const nameIndex = args.indexOf('--name');
                if (nameIndex === -1) throw new Error('Missing --name');
                const fullName = args[nameIndex + 1];

                const abIndex = args.indexOf('--addressbook');
                const addressBook = abIndex !== -1 ? args[abIndex + 1] : null;

                const options = {};
                const emailIndex = args.indexOf('--email');
                if (emailIndex !== -1) options.email = args[emailIndex + 1];

                const phoneIndex = args.indexOf('--phone');
                if (phoneIndex !== -1) options.phone = args[phoneIndex + 1];

                const orgIndex = args.indexOf('--organization');
                if (orgIndex !== -1) options.organization = args[orgIndex + 1];

                const titleIndex = args.indexOf('--title');
                if (titleIndex !== -1) options.title = args[titleIndex + 1];

                const noteIndex = args.indexOf('--note');
                if (noteIndex !== -1) options.note = args[noteIndex + 1];

                output(await Contacts.create(fullName, addressBook, options));
            } else if (subCommand === 'edit') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];

                const abIndex = args.indexOf('--addressbook');
                const addressBook = abIndex !== -1 ? args[abIndex + 1] : null;

                const updates = {};
                const nameIndex = args.indexOf('--name');
                if (nameIndex !== -1) updates.fullName = args[nameIndex + 1];

                const emailIndex = args.indexOf('--email');
                if (emailIndex !== -1) updates.email = args[emailIndex + 1];

                const phoneIndex = args.indexOf('--phone');
                if (phoneIndex !== -1) updates.phone = args[phoneIndex + 1];

                const orgIndex = args.indexOf('--organization');
                if (orgIndex !== -1) updates.organization = args[orgIndex + 1];

                const titleIndex = args.indexOf('--title');
                if (titleIndex !== -1) updates.title = args[titleIndex + 1];

                const noteIndex = args.indexOf('--note');
                if (noteIndex !== -1) updates.note = args[noteIndex + 1];

                output(await Contacts.update(uid, addressBook, updates));
            } else if (subCommand === 'delete') {
                const uidIndex = args.indexOf('--uid');
                if (uidIndex === -1) throw new Error('Missing --uid');
                const uid = args[uidIndex + 1];

                const abIndex = args.indexOf('--addressbook');
                const addressBook = abIndex !== -1 ? args[abIndex + 1] : null;

                output(await Contacts.delete(uid, addressBook));
            } else {
                throw new Error('Unknown contacts command');
            }
        } else if (command === 'boards') {
            if (subCommand === 'list') {
                output(await Deck.listBoards());
            } else if (subCommand === 'get') {
                const boardIndex = args.indexOf('--board');
                if (boardIndex === -1) throw new Error('Missing --board');
                output(await Deck.getBoard(args[boardIndex + 1]));
            } else if (subCommand === 'create') {
                const titleIndex = args.indexOf('--title');
                if (titleIndex === -1) throw new Error('Missing --title');
                const colorIndex = args.indexOf('--color');
                const color = colorIndex !== -1 ? args[colorIndex + 1] : undefined;
                output(await Deck.createBoard(args[titleIndex + 1], color));
            } else if (subCommand === 'edit') {
                const boardIndex = args.indexOf('--board');
                if (boardIndex === -1) throw new Error('Missing --board');
                const updates = {};
                const titleIndex = args.indexOf('--title');
                if (titleIndex !== -1) updates.title = args[titleIndex + 1];
                const colorIndex = args.indexOf('--color');
                if (colorIndex !== -1) updates.color = args[colorIndex + 1];
                const archivedIndex = args.indexOf('--archived');
                if (archivedIndex !== -1) updates.archived = args[archivedIndex + 1] === 'true';
                output(await Deck.editBoard(args[boardIndex + 1], updates));
            } else if (subCommand === 'delete') {
                const boardIndex = args.indexOf('--board');
                if (boardIndex === -1) throw new Error('Missing --board');
                output(await Deck.deleteBoard(args[boardIndex + 1]));
            } else {
                throw new Error('Unknown boards command');
            }
        } else if (command === 'stacks') {
            const boardIndex = args.indexOf('--board');
            if (boardIndex === -1) throw new Error('Missing --board');
            const boardId = args[boardIndex + 1];
            if (subCommand === 'list') {
                output(await Deck.listStacks(boardId));
            } else if (subCommand === 'create') {
                const titleIndex = args.indexOf('--title');
                if (titleIndex === -1) throw new Error('Missing --title');
                const orderIndex = args.indexOf('--order');
                const order = orderIndex !== -1 ? Number(args[orderIndex + 1]) : undefined;
                output(await Deck.createStack(boardId, args[titleIndex + 1], order));
            } else if (subCommand === 'edit') {
                const stackIndex = args.indexOf('--stack');
                if (stackIndex === -1) throw new Error('Missing --stack');
                const updates = {};
                const titleIndex = args.indexOf('--title');
                if (titleIndex !== -1) updates.title = args[titleIndex + 1];
                const orderIndex = args.indexOf('--order');
                if (orderIndex !== -1) updates.order = Number(args[orderIndex + 1]);
                output(await Deck.editStack(boardId, args[stackIndex + 1], updates));
            } else if (subCommand === 'delete') {
                const stackIndex = args.indexOf('--stack');
                if (stackIndex === -1) throw new Error('Missing --stack');
                output(await Deck.deleteStack(boardId, args[stackIndex + 1]));
            } else {
                throw new Error('Unknown stacks command');
            }
        } else if (command === 'cards') {
            if (subCommand === 'comment-list') {
                const cardIndex = args.indexOf('--card');
                if (cardIndex === -1) throw new Error('Missing --card');
                output(await Deck.listComments(args[cardIndex + 1]));
            } else if (subCommand === 'comment-add') {
                const cardIndex = args.indexOf('--card');
                if (cardIndex === -1) throw new Error('Missing --card');
                const msgIndex = args.indexOf('--message');
                if (msgIndex === -1) throw new Error('Missing --message');
                output(await Deck.addComment(args[cardIndex + 1], args[msgIndex + 1]));
            } else if (subCommand === 'comment-delete') {
                const cardIndex = args.indexOf('--card');
                if (cardIndex === -1) throw new Error('Missing --card');
                const commentIndex = args.indexOf('--comment');
                if (commentIndex === -1) throw new Error('Missing --comment');
                output(await Deck.deleteComment(args[cardIndex + 1], args[commentIndex + 1]));
            } else {
                const boardIndex = args.indexOf('--board');
                if (boardIndex === -1) throw new Error('Missing --board');
                const boardId = args[boardIndex + 1];
                const stackIndex = args.indexOf('--stack');
                const cardIndex = args.indexOf('--card');
                if (subCommand === 'list') {
                    const stackId = stackIndex !== -1 ? args[stackIndex + 1] : null;
                    output(await Deck.listCards(boardId, stackId));
                } else if (subCommand === 'get') {
                    if (stackIndex === -1) throw new Error('Missing --stack');
                    if (cardIndex === -1) throw new Error('Missing --card');
                    output(await Deck.getCard(boardId, args[stackIndex + 1], args[cardIndex + 1]));
                } else if (subCommand === 'create') {
                    if (stackIndex === -1) throw new Error('Missing --stack');
                    const titleIndex = args.indexOf('--title');
                    if (titleIndex === -1) throw new Error('Missing --title');
                    const options = {};
                    const descIndex = args.indexOf('--description');
                    if (descIndex !== -1) options.description = args[descIndex + 1];
                    const dueIndex = args.indexOf('--duedate');
                    if (dueIndex !== -1) options.duedate = args[dueIndex + 1];
                    const orderIndex = args.indexOf('--order');
                    if (orderIndex !== -1) options.order = Number(args[orderIndex + 1]);
                    output(await Deck.createCard(boardId, args[stackIndex + 1], args[titleIndex + 1], options));
                } else if (subCommand === 'edit') {
                    if (stackIndex === -1) throw new Error('Missing --stack');
                    if (cardIndex === -1) throw new Error('Missing --card');
                    const updates = {};
                    const titleIndex = args.indexOf('--title');
                    if (titleIndex !== -1) updates.title = args[titleIndex + 1];
                    const descIndex = args.indexOf('--description');
                    if (descIndex !== -1) updates.description = args[descIndex + 1];
                    const dueIndex = args.indexOf('--duedate');
                    if (dueIndex !== -1) updates.duedate = args[dueIndex + 1];
                    const orderIndex = args.indexOf('--order');
                    if (orderIndex !== -1) updates.order = Number(args[orderIndex + 1]);
                    const doneIndex = args.indexOf('--done');
                    if (doneIndex !== -1) updates.done = args[doneIndex + 1] === 'true' ? new Date().toISOString() : null;
                    const archivedIndex = args.indexOf('--archived');
                    if (archivedIndex !== -1) updates.archived = args[archivedIndex + 1] === 'true';
                    output(await Deck.editCard(boardId, args[stackIndex + 1], args[cardIndex + 1], updates));
                } else if (subCommand === 'delete') {
                    if (stackIndex === -1) throw new Error('Missing --stack');
                    if (cardIndex === -1) throw new Error('Missing --card');
                    output(await Deck.deleteCard(boardId, args[stackIndex + 1], args[cardIndex + 1]));
                } else if (subCommand === 'move') {
                    if (stackIndex === -1) throw new Error('Missing --stack');
                    if (cardIndex === -1) throw new Error('Missing --card');
                    const toIndex = args.indexOf('--to-stack');
                    if (toIndex === -1) throw new Error('Missing --to-stack');
                    const orderIndex = args.indexOf('--order');
                    const order = orderIndex !== -1 ? Number(args[orderIndex + 1]) : undefined;
                    output(await Deck.moveCard(boardId, args[stackIndex + 1], args[cardIndex + 1], args[toIndex + 1], order));
                } else if (subCommand === 'assign-label') {
                    if (stackIndex === -1) throw new Error('Missing --stack');
                    if (cardIndex === -1) throw new Error('Missing --card');
                    const labelIndex = args.indexOf('--label');
                    if (labelIndex === -1) throw new Error('Missing --label');
                    output(await Deck.assignLabel(boardId, args[stackIndex + 1], args[cardIndex + 1], args[labelIndex + 1]));
                } else if (subCommand === 'remove-label') {
                    if (stackIndex === -1) throw new Error('Missing --stack');
                    if (cardIndex === -1) throw new Error('Missing --card');
                    const labelIndex = args.indexOf('--label');
                    if (labelIndex === -1) throw new Error('Missing --label');
                    output(await Deck.removeLabel(boardId, args[stackIndex + 1], args[cardIndex + 1], args[labelIndex + 1]));
                } else {
                    throw new Error('Unknown cards command');
                }
            }
        } else if (command === 'labels') {
            const boardIndex = args.indexOf('--board');
            if (boardIndex === -1) throw new Error('Missing --board');
            const boardId = args[boardIndex + 1];
            if (subCommand === 'list') {
                output(await Deck.listLabels(boardId));
            } else if (subCommand === 'create') {
                const titleIndex = args.indexOf('--title');
                if (titleIndex === -1) throw new Error('Missing --title');
                const colorIndex = args.indexOf('--color');
                if (colorIndex === -1) throw new Error('Missing --color');
                output(await Deck.createLabel(boardId, args[titleIndex + 1], args[colorIndex + 1]));
            } else if (subCommand === 'edit') {
                const labelIndex = args.indexOf('--label');
                if (labelIndex === -1) throw new Error('Missing --label');
                const updates = {};
                const titleIndex = args.indexOf('--title');
                if (titleIndex !== -1) updates.title = args[titleIndex + 1];
                const colorIndex = args.indexOf('--color');
                if (colorIndex !== -1) updates.color = args[colorIndex + 1];
                output(await Deck.editLabel(boardId, args[labelIndex + 1], updates));
            } else if (subCommand === 'delete') {
                const labelIndex = args.indexOf('--label');
                if (labelIndex === -1) throw new Error('Missing --label');
                output(await Deck.deleteLabel(boardId, args[labelIndex + 1]));
            } else {
                throw new Error('Unknown labels command');
            }
        } else {
            console.log('Usage: node index.js <notes|files|calendar|calendars|tasks|contacts|addressbooks|shares|boards|stacks|cards|labels> <list|get|create|search|edit|delete|move|create-link> [options]');
        }
    } catch (err) {
        errorOutput(err);
    }
}

main();
