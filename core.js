/* Local cookie parsing. Never sends input to any server. */
(function(root) {
  function parse(text) {
    text = text.trim();
    if (!text) throw new Error('Paste cookies first.');
    let rows;
    if (/^[\[{]/.test(text)) {
      let data; try { data = JSON.parse(text); } catch { throw new Error('Invalid JSON. Paste the complete cookie export.'); }
      rows = Array.isArray(data) ? data : Array.isArray(data.cookies) ? data.cookies : data.name !== undefined ? [data] : null;
      if (!rows) throw new Error('Use a JSON cookie array or an object containing cookies.');
    } else {
      rows = text.replace(/^Cookie:\s*/i, '').split(/[;\r\n]+/).filter(x => x.trim()).map(part => {
        const i = part.indexOf('=');
        if (i < 1) throw new Error('Use JSON or name=value; name2=value2 format.');
        return {name: part.slice(0,i).trim(), value: part.slice(i+1).trim()};
      });
    }
    if (!rows.length) throw new Error('No cookies found.');
    if (rows.length > 3000) throw new Error('Maximum 3,000 cookies per import.');
    return rows;
  }
  function prepare(c, target, storeId, now = Date.now()/1000) {
    if (!c || typeof c.name !== 'string' || typeof c.value !== 'string') throw new Error('Invalid name/value');
    if (c.partitionKey || c.partitioned || c.firstPartyDomain) throw new Error('Partitioned cookie unsupported');
    const u = new URL(target);
    let domain = c.domain === undefined ? u.hostname : String(c.domain).toLowerCase().replace(/^\./, '');
    if (!domain || /[\s/:?#]/.test(domain)) throw new Error('Invalid domain');
    if (u.hostname !== domain && (!u.hostname.endsWith('.'+domain) || c.hostOnly === true)) throw new Error('Different website');
    const path = c.path === undefined ? '/' : c.path;
    if (typeof path !== 'string' || !path.startsWith('/') || /[\r\n]/.test(path)) throw new Error('Invalid path');
    const secure = c.secure === undefined ? u.protocol === 'https:' : c.secure === true;
    if (secure && u.protocol !== 'https:') throw new Error('Open HTTPS website');
    const out = {url:u.origin+'/', name:c.name, value:c.value, path, secure, httpOnly:c.httpOnly === true, storeId};
    if (c.domain !== undefined && c.hostOnly !== true) out.domain = domain;
    if (c.sameSite !== undefined) {
      const map = {none:'no_restriction',no_restriction:'no_restriction',lax:'lax',strict:'strict',unspecified:'unspecified'};
      out.sameSite = map[String(c.sameSite).toLowerCase()];
      if (!out.sameSite) throw new Error('Invalid SameSite');
    }
    const raw = c.expirationDate ?? c.expires;
    if (c.session !== true && raw !== undefined && raw !== -1 && raw !== 0) {
      let expiry = Number(raw);
      if (!Number.isFinite(expiry)) throw new Error('Invalid expiration');
      if (expiry > 1e12) expiry /= 1000;
      if (expiry <= now) throw new Error('Expired cookie');
      out.expirationDate = expiry;
    }
    return out;
  }
  root.CookieImport = {parse, prepare};
  if (typeof module !== 'undefined') module.exports = root.CookieImport;
})(globalThis);
