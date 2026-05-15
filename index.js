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
        const cleanPath = dirPath.startsWith('/') ? dirPath.slice(1) : dirPath;
        const endpoint = `/remote.php/dav/files/${CONFIG.user}/${cleanPath}`;

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

            if (href.endsWith(encodeURIComponent(CONFIG.user) + '/' + cleanPath) ||
                href.endsWith(encodeURIComponent(CONFIG.user) + '/' + cleanPath + '/')) {
                 if (cleanPath !== '' && name === cleanPath.split('/').pop()) return null;
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
        const cleanPath = filePath.startsWith('/') ? filePath.slice(1) : filePath;

        // Ensure parent directories exist. MKCOL each segment; 405 means it already exists.
        const segments = cleanPath.split('/').filter(Boolean);
        if (segments.length > 1) {
            let currentPath = '';
            for (const seg of segments.slice(0, -1)) {
                currentPath = currentPath ? `${currentPath}/${seg}` : seg;
                try {
                    await request(`/remote.php/dav/files/${CONFIG.user}/${currentPath}`, { method: 'MKCOL' });
                } catch (e) {
                    if (e.status !== 405) throw e;
                }
            }
        }

        const endpoint = `/remote.php/dav/files/${CONFIG.user}/${cleanPath}`;

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
        const cleanPath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
        const endpoint = `/remote.php/dav/files/${CONFIG.user}/${cleanPath}`;

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
        const cleanPath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
        const endpoint = `/remote.php/dav/files/${CONFIG.user}/${cleanPath}`;

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

        let vtodo = `BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//OpenClaw//Nextcloud Skill//EN\nBEGIN:VTODO\nUID:${uid}\nDTSTAMP:${dtstamp}\nSUMMARY:${title}\nSTATUS:NEEDS-ACTION\n`;

        if (dueDate) {
             const due = parseDateInput(dueDate);
             vtodo += `DUE:${format(due, "yyyyMMdd'T'HHmmss'Z'")}\n`;
        }

        if (priority) vtodo += `PRIORITY:${priority}\n`;
        if (description) vtodo += `DESCRIPTION:${description}\n`;

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
        
        if (updates.title) vtodo = this._updateProperty(vtodo, 'SUMMARY', updates.title);
        if (updates.priority) vtodo = this._updateProperty(vtodo, 'PRIORITY', updates.priority);
        if (updates.description) vtodo = this._updateProperty(vtodo, 'DESCRIPTION', updates.description);
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

        let vevent = `BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//OpenClaw//Nextcloud Skill//EN\nBEGIN:VEVENT\nUID:${uid}\nDTSTAMP:${dtstamp}\nSUMMARY:${summary}\nDTSTART:${toCalDavDate(start)}\nDTEND:${toCalDavDate(end)}\n`;

        if (description) vevent += `DESCRIPTION:${description}\n`;
        if (location) vevent += `LOCATION:${location}\n`;

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

        if (updates.summary) vevent = this._updateProperty(vevent, 'SUMMARY', updates.summary);
        if (updates.start) {
            const d = parseDateInput(updates.start);
            vevent = this._updateProperty(vevent, 'DTSTART', d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z');
        }
        if (updates.end) {
            const d = parseDateInput(updates.end);
            vevent = this._updateProperty(vevent, 'DTEND', d.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z');
        }
        if (updates.description !== undefined) {
            vevent = this._updateProperty(vevent, 'DESCRIPTION', updates.description);
        }
        if (updates.location !== undefined) {
            vevent = this._updateProperty(vevent, 'LOCATION', updates.location);
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
            const regex = new RegExp(`^${field}(?:;[^:]*)?:(.*)$`, 'mi');
            const match = vcard.match(regex);
            return match ? cleanValue(match[1]) : null;
        };

        const uid = getField('UID');
        const fn = getField('FN'); // Full Name
        const n = getField('N');   // Structured Name: Last;First;Middle;Prefix;Suffix

        // Parse phone numbers (can have multiple)
        const phones = [];
        const phoneRegex = /^TEL(?:;[^:]*)?:(.*)$/gmi;
        let phoneMatch;
        while ((phoneMatch = phoneRegex.exec(vcard)) !== null) {
            phones.push(cleanValue(phoneMatch[1]));
        }

        // Parse emails (can have multiple)
        const emails = [];
        const emailRegex = /^EMAIL(?:;[^:]*)?:(.*)$/gmi;
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

        let vcard = `BEGIN:VCARD\nVERSION:3.0\nUID:${uid}\nFN:${fullName}\n`;

        // Parse name into structured format if possible
        const nameParts = fullName.split(' ');
        if (nameParts.length >= 2) {
            const lastName = nameParts[nameParts.length - 1];
            const firstName = nameParts.slice(0, -1).join(' ');
            vcard += `N:${lastName};${firstName};;;\n`;
        } else {
            vcard += `N:${fullName};;;;\n`;
        }

        if (options.email) vcard += `EMAIL:${options.email}\n`;
        if (options.phone) vcard += `TEL:${options.phone}\n`;
        if (options.organization) vcard += `ORG:${options.organization}\n`;
        if (options.title) vcard += `TITLE:${options.title}\n`;
        if (options.note) vcard += `NOTE:${options.note}\n`;

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
        const regex = new RegExp(`^${field}(?:;[^:]*)?:.*$`, 'mi');
        const newLine = `${field}:${value}`;
        if (regex.test(vcard)) {
            return vcard.replace(regex, newLine);
        } else {
            return vcard.replace('END:VCARD', `${newLine}\nEND:VCARD`);
        }
    },

    async update(uid, addressBookName, updates) {
        const contact = await this.findContactPath(uid, addressBookName);
        if (!contact) throw new Error(`Contact ${uid} not found.`);

        let vcard = contact.data;

        if (updates.fullName) {
            vcard = this._updateVCardField(vcard, 'FN', updates.fullName);
            // Update structured name too
            const nameParts = updates.fullName.split(' ');
            if (nameParts.length >= 2) {
                const lastName = nameParts[nameParts.length - 1];
                const firstName = nameParts.slice(0, -1).join(' ');
                vcard = this._updateVCardField(vcard, 'N', `${lastName};${firstName};;;`);
            }
        }
        if (updates.email) vcard = this._updateVCardField(vcard, 'EMAIL', updates.email);
        if (updates.phone) vcard = this._updateVCardField(vcard, 'TEL', updates.phone);
        if (updates.organization) vcard = this._updateVCardField(vcard, 'ORG', updates.organization);
        if (updates.title) vcard = this._updateVCardField(vcard, 'TITLE', updates.title);
        if (updates.note) vcard = this._updateVCardField(vcard, 'NOTE', updates.note);

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
        } else {
            console.log('Usage: node index.js <notes|files|calendar|calendars|tasks|contacts|addressbooks|shares> <list|get|create|search|edit|delete|create-link> [options]');
        }
    } catch (err) {
        errorOutput(err);
    }
}

main();
