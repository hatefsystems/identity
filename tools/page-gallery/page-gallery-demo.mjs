import { chromium } from 'playwright';

/** A read-only source snapshot, rendered without the source's browser authority. */
export async function createDemoRenderer() {
  if (['DEBUG', 'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'PWDEBUG'].some(name => process.env[name])) {
    throw new Error('Demo renderer rejects diagnostic logging.');
  }
  const browser = await chromium.launch({ headless: true });
  let closed = false;
  const contexts = new Set();

  return {
    async capture(sourcePage, { selectors, privateValues, locale, fullPage, viewport, theme }) {
      if (closed || !Array.isArray(selectors) || !selectors.every(value => typeof value === 'string') ||
          !Array.isArray(privateValues) || !privateValues.every(value => typeof value === 'string') ||
          !['en', 'fa-IR'].includes(locale) || !['light', 'dark'].includes(theme) ||
          typeof fullPage !== 'boolean' || !Number.isInteger(viewport?.width) ||
          !Number.isInteger(viewport?.height) || viewport.width < 1 || viewport.height < 1) {
        throw new Error('Invalid demo capture options.');
      }
      let context;
      try {
        // Everything private stays in this evaluation, including raw CSS/URLs,
        // live form properties and the registry. Only the sanitized clone exits.
        const snapshot = await sourcePage.evaluate(async ({ selectors, privateValues, locale, theme }) => {
          const publicRegistryValues = new Set([
            'localhost', 'required', 'preferred', 'discouraged', 'public-key', 'platform',
            'cross-platform', 'webauthn', 'totp', 'email', 'sms', 'en', 'fa-IR', 'UTC',
            'active', 'disabled', 'suspended', 'pending_deletion', 'pending', 'confirmed',
            'true', 'false', 'null',
          ]);
          const secrets = [...new Set(privateValues.filter(value => value && !publicRegistryValues.has(value)))];
          const knownPublicValues = new Set([
            'active', 'disabled', 'suspended', 'pending_deletion', 'released', 'confirmed',
            'success', 'failed', 'pending', 'complete', 'enabled', 'not recorded', 'none',
            'yes', 'no', 'true', 'false', 'all', 'audit', 'ledger', 'webauthn', 'totp',
            'localhost', 'required', 'preferred', 'discouraged', 'public-key', 'platform',
            'cross-platform', 'unnamed passkey', 'unnamed', '-', '\u2014', '\u2013',
            'not provided', 'not set', 'your profile',
            '\u0641\u0639\u0627\u0644', '\u063a\u06cc\u0631\u0641\u0639\u0627\u0644',
            '\u062a\u0639\u0644\u06cc\u0642\u200c\u0634\u062f\u0647', '\u0622\u0632\u0627\u062f\u0634\u062f\u0647',
            '\u062b\u0628\u062a \u0646\u0634\u062f\u0647', '\u0628\u0644\u0647', '\u062e\u06cc\u0631',
            '\u062f\u0631 \u0627\u0646\u062a\u0638\u0627\u0631 \u062d\u0630\u0641',
            '\u0627\u0631\u0627\u0626\u0647 \u0646\u0634\u062f\u0647', '\u062a\u0646\u0638\u06cc\u0645 \u0646\u0634\u062f\u0647',
            '\u0646\u0645\u0627\u06cc\u0647\u0654 \u0634\u0645\u0627',
          ]);
    const root = document.documentElement.cloneNode(true);
    // All substitutions/theme mirroring below belong only to this detached,
    // sanitized presentation clone, never the live application document.
    root.setAttribute('data-gallery-synthetic', 'true');
          const originals = [document.documentElement, ...document.documentElement.querySelectorAll('*')];
          const copies = [root, ...root.querySelectorAll('*')];
          const sourceFor = new Map(copies.map((node, index) => [node, originals[index]]));
          const selected = new Set();
          for (const selector of ['[data-private]', '[data-legal-private]', ...selectors]) {
            for (const node of root.querySelectorAll(selector)) selected.add(node);
          }
          const inSelection = node => {
            for (let parent = node; parent; parent = parent.parentElement) if (selected.has(parent)) return true;
            return false;
          };
          const values = new Map();
          let nextID = 1, nextCode = 1;
          const jsonValue = (value, hint = '', depth = 0) => {
            if (depth > 40) return 'DEMO-VALUE';
            if (Array.isArray(value)) return value.map(item => jsonValue(item, hint, depth + 1));
            if (value && typeof value === 'object') {
              return Object.fromEntries(Object.entries(value).map(([key, item]) => {
                let safeKey = key;
                for (const secret of secrets) safeKey = safeKey.split(secret).join('demo_field');
                if (['uuid', 'email', 'hash'].includes(classify(safeKey))) safeKey = demo(classify(safeKey), safeKey);
                return [safeKey, jsonValue(item, key, depth + 1)];
              }));
            }
            if (value === null || typeof value === 'boolean') return value;
            const key = hint.toLowerCase();
            if (/(?:^|_)(?:id|ref|uuid|actor|account|session)(?:$|_)/.test(key)) return demo('uuid', String(value));
            if (typeof value === 'number') return 10;
            if (typeof value !== 'string' || value === '') return value;
            if (knownPublicValues.has(value.toLowerCase())) return value;
            let kind = classify(value);
            if (/email/.test(key)) kind = 'email';
            else if (/phone|mobile/.test(key)) kind = 'phone';
            else if (/timestamp|date|_at$|_time$/.test(key)) kind = 'date';
            else if (/recovery|code/.test(key)) kind = 'code';
            else if (/display.?name/.test(key)) kind = 'name';
            else if (/event|type/.test(key)) kind = 'event';
            else if (/reason|purpose|narrative|message/.test(key)) kind = 'reason';
            return demo(kind, value);
          };
          const demo = (kind, original = '') => {
            const key = `${kind}:${original}`;
            if (values.has(key)) return values.get(key);
            let result;
            switch (kind) {
              case 'uuid': result = `00000000-0000-4000-8000-${String(nextID++).padStart(12, '0')}`; break;
              case 'email': result = 'demo.user@example.test'; break;
              case 'phone': result = '+1 202 555 0110'; break;
              case 'ip': result = '192.0.2.10'; break;
              case 'date': result = '2026-01-01T12:00:00.000Z'; break;
              case 'code': result = `DEMO-${String(nextCode++).padStart(4, '0')}-0001`; break;
              case 'otp': result = '123456'; break;
              case 'number': result = locale === 'fa-IR' ? '\u06f1\u06f0' : '10'; break;
              case 'name': result = 'Demo Account'; break;
              case 'passkey': result = 'Demo Passkey'; break;
              case 'password': result = 'DEMO-PASSWORD'; break;
              case 'reason': result = 'Demo review request'; break;
              case 'authority': result = 'Demo Authority'; break;
              case 'hash': result = 'd'.repeat(64); break;
              case 'event': result = 'demo.event'; break;
              case 'json':
                try { result = JSON.stringify(jsonValue(JSON.parse(original)), null, 2); }
                catch { result = '{\n  "demo_value": "DEMO-VALUE"\n}'; }
                break;
              case 'url': result = 'https://example.test/demo'; break;
              default: result = 'DEMO-VALUE';
            }
            values.set(key, result);
            return result;
          };
          const classify = value => {
            const text = value.trim();
            if (/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(text)) return 'uuid';
            if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) return 'email';
            if (/^\d{4}-\d{2}-\d{2}(?:T|\s|$)/.test(text)) return 'date';
            if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text) || /^[0-9a-f]*:[0-9a-f:]+$/i.test(text)) return 'ip';
            if (/^(?:https?:|mailto:|tel:|blob:)/i.test(text)) return 'url';
            if (/^(?:\+\d[\d ()-]{8,}|0\d{9,10}|\d[\d ()-]*[ ()-][\d ()-]{7,})$/.test(text)) return 'phone';
            if (/^[A-Z0-9]{4,}(?:-[A-Z0-9]{4,})+$/.test(text)) return 'code';
            if (/^[0-9a-f]{32,}$/i.test(text)) return 'hash';
            if (/^[\d\u06f0-\u06f9\u0660-\u0669]+$/.test(text)) return text.length === 6 ? 'otp' : 'number';
            if (/^[{[]/.test(text)) return 'json';
            return 'value';
          };
          const contextKind = node => {
            const dd = node.closest('dd');
            const label = dd ? dd.previousElementSibling?.textContent || '' : '';
            const hint = [node.getAttribute('name'), node.getAttribute('type'), node.getAttribute('autocomplete'),
              node.getAttribute('data-testid'), label].filter(Boolean).join(' ').toLowerCase();
            if (/email|\u0627\u06cc\u0645\u06cc\u0644/.test(hint)) return 'email';
            if (/phone|mobile|tel|\u062a\u0644\u0641\u0646|\u0645\u0648\u0628\u0627\u06cc\u0644/.test(hint)) return 'phone';
            if (/recovery.?code/.test(hint)) return 'code';
            if (/otp|authenticator|verification.?code/.test(hint)) return 'otp';
            if (/password/.test(hint)) return 'password';
            if (/date|time|created|expires|\u0632\u0645\u0627\u0646|\u062a\u0627\u0631\u06cc\u062e/.test(hint) || node.closest('time')) return 'date';
            if (/passkey.*name|passkey_name/.test(hint) || node.matches('[data-testid="passkey-row"] h3')) return 'passkey';
            if (/display.?name|saved-display-name|\u0646\u0627\u0645/.test(hint)) return 'name';
            if (/authority|\u0645\u0631\u062c\u0639/.test(hint)) return 'authority';
            if (/reason|purpose|\u062f\u0644\u06cc\u0644/.test(hint)) return 'reason';
            if (/sequence|revision|count|number|limit|offset/.test(hint)) return 'number';
            if (/event.?type/.test(hint)) return 'event';
            if (/account|actor|session|uuid|operation|reference/.test(hint)) return 'uuid';
            return 'value';
          };
          const isOwnedLabel = node => node.closest('button, label, dt, summary, thead, option') ||
            (node.localName === 'th' && !node.children.length);
          const isPrivateLeaf = (node, text) => inSelection(node) && !isOwnedLabel(node) && (
            node.closest('dd, bdi, time, pre, code, [contenteditable="true"]') ||
            node.matches('[data-testid="saved-display-name"], [data-testid="passkey-row"] h3, #overview-profile') ||
            (node.matches('td') && !node.children.length) ||
            (!node.children.length && /^(?:[\d\u06f0-\u06f9\u0660-\u0669]+|[A-Za-z0-9_-]{24,})$/.test(text))
          );
          // Discover unregistered owned values before sanitizing accessible names
          // elsewhere (for example a passkey name in a Rename button's label).
          for (const node of copies) {
            if (node.matches('input:not([type="checkbox"]):not([type="radio"]):not([type="button"]):not([type="submit"]):not([type="reset"]):not([type="file"]), textarea')) {
              const value = sourceFor.get(node).value;
              const kind = contextKind(node);
              const publicParameter = /^(?:number|range|color)$/.test(node.type) ||
                (classify(value) === 'number' && value.length < 6 && ['value', 'number'].includes(kind));
              if (value && !publicParameter && !knownPublicValues.has(value.toLowerCase())) {
                values.set(`registry:${value}`, demo(kind === 'value' ? classify(value) : kind, value));
              }
            }
            if (node.matches('[data-testid="saved-display-name"], [data-testid="passkey-row"] h3, #overview-profile') &&
                !node.children.length && node.textContent.trim()) {
              const value = node.textContent.trim();
              if (!knownPublicValues.has(value.toLowerCase())) values.set(`registry:${value}`, demo(contextKind(node) === 'passkey' ? 'passkey' : 'name', value));
            }
            if (!node.children.length && isPrivateLeaf(node, node.textContent.trim())) {
              const value = node.textContent.trim();
              if (value && !knownPublicValues.has(value.toLowerCase()) &&
                  !(classify(value) === 'number' && value.length < 6) && !values.has(`registry:${value}`)) {
                const kind = contextKind(node);
                values.set(`registry:${value}`, demo(kind === 'value' ? classify(value) : kind, value));
              }
            }
          }
          const registry = [...new Set([...secrets, ...[...values.keys()].filter(key => key.startsWith('registry:')).map(key => key.slice(9))])]
            .sort((a, b) => b.length - a.length);
          const replacementFor = value => values.get(`registry:${value}`) || demo(classify(value) === 'value' ? 'name' : classify(value), value);
          const variants = registry.flatMap(value => [...new Set([value, encodeURIComponent(value), JSON.stringify(value).slice(1, -1)])]
            .map(encoded => [encoded, replacementFor(value)])).sort((a, b) => b[0].length - a[0].length);
          const sanitize = value => {
            let text = String(value);
            for (const [secret, replacement] of variants) text = text.split(secret).join(replacement);
            text = text.replace(/\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b/gi, value =>
              value.startsWith('00000000-0000-4000-8000-') ? value : demo('uuid', value));
            text = text.replace(/[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, value =>
              value === 'demo.user@example.test' ? value : demo('email', value));
            text = text.replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?\b/g,
              () => demo('date'));
            text = text.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, () => demo('ip'));
            text = text.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, () => demo('value'));
            text = text.replace(/\b[0-9a-f]{32,}\b/gi, () => demo('hash'));
            return text;
          };

          // Read original sheets, never a cloned sheet attached to the source.
          const cssParts = [];
          const assets = new Map();
          const dataURL = async url => {
            if (/^data:font\/(?:woff2?|ttf|otf);base64,[a-z0-9+/=]+$/i.test(url)) return url;
            const absolute = new URL(url, document.baseURI);
            if (absolute.origin !== location.origin || !/\.(?:woff2?|ttf|otf)(?:$|\?)/i.test(absolute.href)) return '';
            if (!assets.has(absolute.href)) assets.set(absolute.href, (async () => {
              const response = await fetch(absolute.href, { credentials: 'omit', mode: 'same-origin', redirect: 'error' });
              if (!response.ok) throw new Error('Local demo font unavailable.');
              const bytes = new Uint8Array(await response.arrayBuffer());
              if (!bytes.length || bytes.length > 4 * 1024 * 1024) throw new Error('Invalid local demo font.');
              let binary = '';
              for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
              const extension = absolute.pathname.split('.').pop().toLowerCase();
              return `data:font/${extension};base64,${btoa(binary)}`;
            })());
            return assets.get(absolute.href);
          };
          const inlineCSS = async (css, base) => {
            let result = '', offset = 0;
            const text = css.replace(/\/\*[\s\S]*?\*\//g, '');
            const pattern = /url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi;
            for (const match of text.matchAll(pattern)) {
              result += sanitize(text.slice(offset, match.index));
              const url = (match[1] ?? match[2] ?? match[3]).trim();
              let replacement = '';
              if (url.startsWith('#')) replacement = sanitize(url);
              else replacement = await dataURL(new URL(url, base).href);
              result += `url("${replacement}")`;
              offset = match.index + match[0].length;
            }
            return result + sanitize(text.slice(offset));
          };
          const sheets = new Set();
          const collectSheet = async sheet => {
            if (sheets.has(sheet) || sheet.disabled) return;
            sheets.add(sheet);
            const base = sheet.href || document.baseURI;
            if (new URL(base).origin !== location.origin && sheet.href) return;
            let css = '';
            try {
              for (const rule of sheet.cssRules) {
                if (rule.type === CSSRule.IMPORT_RULE) {
                  if (rule.styleSheet) await collectSheet(rule.styleSheet);
                } else css += rule.cssText + '\n';
              }
            } catch {
              if (!sheet.href) throw new Error('Demo stylesheet unavailable.');
              const response = await fetch(base, { credentials: 'omit', mode: 'same-origin', redirect: 'error' });
              if (!response.ok) throw new Error('Demo stylesheet unavailable.');
              css = await response.text();
              // An unreadable imported sheet cannot cause a renderer fetch.
              if (/@import\b/i.test(css)) throw new Error('Demo stylesheet import unavailable.');
            }
            css = await inlineCSS(css, base);
            const media = sanitize(sheet.media?.mediaText || '');
            cssParts.push(media ? `@media ${media}{${css}}` : css);
          };
          for (const sheet of [...document.styleSheets, ...document.adoptedStyleSheets]) await collectSheet(sheet);

          for (const node of root.querySelectorAll('script, style, link, base, template')) node.remove();
          for (const node of root.querySelectorAll('meta')) {
            if (node.hasAttribute('http-equiv') || (!node.hasAttribute('charset') && node.getAttribute('name') !== 'viewport')) node.remove();
          }
          const commentWalker = document.createTreeWalker(root, NodeFilter.SHOW_COMMENT);
          const comments = [];
          while (commentWalker.nextNode()) comments.push(commentWalker.currentNode);
          for (const comment of comments) comment.remove();
          const demoImage = 'data:image/svg+xml;base64,' + btoa('<svg xmlns="http://www.w3.org/2000/svg" width="160" height="100" viewBox="0 0 160 100"><rect width="160" height="100" fill="white"/><path d="M10 80 L50 30 L80 65 L110 40 L150 80" fill="none" stroke="navy" stroke-width="3"/><text x="80" y="95" text-anchor="middle" font-family="sans-serif" font-size="12" fill="navy">DEMO</text></svg>');
          for (const node of [root, ...root.querySelectorAll('*')]) {
            const source = sourceFor.get(node);
            for (const attr of [...node.attributes]) {
              const name = attr.name.toLowerCase();
              if (/^on/.test(name) || ['nonce', 'srcdoc', 'integrity', 'ping', 'srcset', 'imagesrcset'].includes(name)) {
                node.removeAttribute(attr.name);
                continue;
              }
              let value = sanitize(attr.value);
              if (name === 'datetime') value = demo('date');
              if (/^data-.*(?:session|secret|token|credential|user[-_]?id|actor|account[-_]?(?:id|ref)|key[-_]?id|operation|proof|challenge|signature|email|phone)/.test(name)) {
                value = attr.value ? demo(/email/.test(name) ? 'email' : /phone/.test(name) ? 'phone' : 'uuid', attr.value) : '';
              }
              if (name === 'style') value = await inlineCSS(attr.value, document.baseURI);
              if (['src', 'poster', 'background'].includes(name) || (['href', 'xlink:href'].includes(name) && node.localName === 'image')) value = demoImage;
              if (['action', 'formaction'].includes(name)) value = '#demo';
              if ((name === 'href' || name === 'xlink:href') && node.localName !== 'image') {
                if (value.startsWith('#')) value = sanitize(value);
                else if (/^(?:mailto:|tel:|blob:|data:|javascript:)/i.test(value)) value = '#demo';
                else {
                  const url = new URL(value, document.baseURI);
                  value = sanitize(url.pathname).replace(/\/(users|accounts|sessions|keys)\/([^/]+)/g,
                    (path, kind, id) => ['me', 'new', 'register'].includes(id) || id.startsWith('00000000-0000-4000-8000-') ? path : `/${kind}/${demo('uuid', id)}`);
                  if (url.origin !== location.origin) value = 'https://example.test' + value;
                  // Query/fragment parameters may carry authorities unregistered
                  // by the harness. Navigation is illustrative, not executable.
                }
              }
              node.setAttribute(attr.name, value);
            }
            if (node.localName === 'input') {
              if (['checkbox', 'radio'].includes(node.type)) {
                node.toggleAttribute('checked', source.checked);
              } else if (!['button', 'submit', 'reset', 'file'].includes(node.type)) {
                const original = source.value;
                let value = '';
                if (original) {
                  const kind = contextKind(node);
                  value = demo(kind === 'value' ? classify(original) : kind, original);
                  if (node.type === 'number' || node.type === 'range') {
                    value = /^(?:limit|page_size|pageSize|offset)$/.test(node.name) && !secrets.includes(original) ? original : '10';
                  }
                  if (node.type === 'date') value = '2026-01-01';
                  if (node.type === 'datetime-local') value = '2026-01-01T12:00';
                  if (node.type === 'time') value = '12:00';
                  if (node.type === 'month') value = '2026-01';
                  if (node.type === 'week') value = '2026-W01';
                  if (node.type === 'color') value = '#123456';
                  if (node.type === 'tel') value = '+12025550110';
                  if (node.type === 'password') node.type = 'text';
                }
                node.setAttribute('value', value);
              }
            } else if (node.localName === 'textarea') {
              const original = source.value;
              node.textContent = original ? demo(contextKind(node) === 'value' ? 'reason' : contextKind(node), original) : '';
            } else if (node.localName === 'option') {
              node.toggleAttribute('selected', source.selected);
            }
          }

          const textWalker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
          while (textWalker.nextNode()) {
            const textNode = textWalker.currentNode;
            const parent = textNode.parentElement;
            const original = textNode.nodeValue;
            if (!original.trim() || parent.closest('textarea, style')) continue;
            let value = sanitize(original);
            const trimmed = original.trim();
            const publicValue = knownPublicValues.has(trimmed.toLowerCase());
            const ownedLabel = isOwnedLabel(parent);
            const privateLeaf = isPrivateLeaf(parent, trimmed);
            if (parent.closest('pre, code') && !ownedLabel && !publicValue) {
              const kind = contextKind(parent);
              value = demo(kind === 'value' ? classify(trimmed) : kind, trimmed);
            } else if (privateLeaf && !publicValue && value === original) {
              const kind = contextKind(parent);
              value = demo(kind === 'value' ? classify(trimmed) : kind, trimmed);
            }
            // Replace only this value node, never an ancestor or its children.
            textNode.nodeValue = value;
            if (!ownedLabel && (privateLeaf || parent.closest('pre, code')) &&
                ['uuid', 'email', 'phone', 'ip', 'date', 'code', 'otp', 'hash', 'json', 'url'].includes(classify(value))) {
              const technical = parent.closest('time, bdi, code, pre') || (!parent.children.length ? parent : null);
              if (technical) technical.dir = 'ltr';
            }
          }
          root.lang = locale;
          root.dir = locale === 'fa-IR' ? 'rtl' : 'ltr';
          root.classList.toggle('dark', theme === 'dark');
          const head = root.querySelector('head');
          const csp = document.createElement('meta');
          csp.setAttribute('http-equiv', 'Content-Security-Policy');
          csp.content = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; font-src data:; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'";
          head.prepend(csp);
          const style = document.createElement('style');
          style.textContent = cssParts.join('\n');
          head.append(style);
          const nodes = [root, ...root.querySelectorAll('*')];
          const scroll = [], dialogs = [];
          let focused = -1;
          for (const [index, node] of nodes.entries()) {
            const source = sourceFor.get(node);
            if (!source) continue;
            if (source.scrollTop || source.scrollLeft) scroll.push({ index, top: source.scrollTop, left: source.scrollLeft });
            if (source === document.activeElement) focused = index;
            if (node.localName === 'dialog' && source.open) {
              node.removeAttribute('open');
              dialogs.push(index);
            }
          }
          const html = '<!doctype html>' + root.outerHTML;
          // Fail closed in source memory, before HTML crosses the browser/Node
          // boundary. Include DOM-decoded values as well as serialized variants.
          const serialized = (html + '\n' + root.textContent + '\n' + nodes.flatMap(node => [...node.attributes].map(attr => attr.value)).join('\n'))
            .replace(/data:font\/(?:woff2?|ttf|otf);base64,[a-z0-9+/=]+/gi, 'public-local-font');
          if (variants.some(([secret]) => serialized.includes(secret))) throw new Error('Unsafe demo snapshot.');
          return { html, scroll, dialogs, focused, windowScroll: { x: window.scrollX, y: window.scrollY } };
        }, { selectors, privateValues, locale, theme });

        context = await browser.newContext({
          viewport, colorScheme: theme, reducedMotion: 'reduce', serviceWorkers: 'block',
          bypassCSP: false, offline: true,
        });
        contexts.add(context);
        await context.route('**/*', route => route.abort());
        const page = await context.newPage();
        page.setDefaultTimeout(15_000);
        await page.setContent(snapshot.html, { waitUntil: 'load' });
        await page.evaluate(async snapshot => {
          await document.fonts.ready;
          const nodes = [document.documentElement, ...document.documentElement.querySelectorAll('*')];
          for (const index of snapshot.dialogs) nodes[index].showModal();
          for (const canvas of document.querySelectorAll('canvas')) {
            const drawing = canvas.getContext('2d');
            if (!drawing) continue;
            drawing.strokeStyle = '#123456';
            drawing.lineWidth = 2;
            drawing.beginPath();
            drawing.moveTo(8, canvas.height - 24);
            drawing.lineTo(canvas.width / 3, 12);
            drawing.lineTo(canvas.width * 2 / 3, canvas.height / 2);
            drawing.lineTo(canvas.width - 8, 12);
            drawing.stroke();
            drawing.fillStyle = '#123456';
            drawing.font = '16px sans-serif';
            drawing.fillText('DEMO', 8, canvas.height - 6);
          }
          if (snapshot.focused >= 0) nodes[snapshot.focused]?.focus({ preventScroll: true });
          await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
          window.scrollTo(snapshot.windowScroll.x, snapshot.windowScroll.y);
          for (const position of snapshot.scroll) {
            nodes[position.index].scrollTop = position.top;
            nodes[position.index].scrollLeft = position.left;
          }
          if (!document.body.innerText.trim() || !document.body.getBoundingClientRect().width) throw new Error('Empty demo render.');
          // An unused local Arial fallback may fail on Linux; the owned primary
          // Persian face must load, not every optional fallback declaration.
          if (document.documentElement.lang === 'fa-IR' &&
              ![...document.fonts].some(font => font.family === 'persianFont' && font.status === 'loaded')) throw new Error('Demo font failed.');
          if (snapshot.dialogs.some(index => !nodes[index].matches(':modal'))) throw new Error('Demo modal failed.');
        }, { ...snapshot, html: undefined });
        const png = await page.screenshot({ fullPage, animations: 'disabled', caret: 'initial' });
        if (png.length <= 100 || !png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
          throw new Error('Invalid demo image.');
        }
        return png;
      } catch {
        // Playwright errors can include evaluation arguments and call logs.
        // Never propagate them from a private source page.
        throw new Error('Demo capture unavailable; private diagnostics suppressed.');
      } finally {
        if (context) {
          await context.close();
          contexts.delete(context);
        }
      }
    },
    async close() {
      if (closed) return;
      closed = true;
      try {
        for (const context of contexts) await context.close();
      } finally {
        contexts.clear();
        await browser.close();
      }
    },
  };
}
