// Dawn-прокси: уся мережева робота плагіна тут, а ТВ робить лише прості GET на один домен (як з online.js).
// PoW, сесія і розшифровка AES-GCM — тут: слабкі ТВ не встигали розв'язати PoW за 120 с життя челенджу.
//   GET /titles?imdb=&name=&name=&year=&tv=1  — тайтли каталогу з релізами Dawn (один запит замість 5–20)
//   GET /v2/video/{id}/{video}                — { hls, skips } для вбудованого плеєра
//   GET /{id}/{video}.m3u8                    — 302 на HLS: постійні посилання для зовнішніх плеєрів (.m3u8 — HLS впізнають за URL)
//   GET /health                               — сесія Dawn отримується
const API = 'https://api.mikai.me/v1';
const DAWN = API + '/player/dawn';
const ARM = 'https://arm.haglund.dev/api/v2/imdb?id=';
const HOST = 'https://dawn.levende.xyz';
const enc = new TextEncoder();
const subtle = crypto.subtle;
const CORS = { 'Access-Control-Allow-Origin': '*' };

async function json(url, init) {
  const r = await fetch(url, init);
  if (!r.ok) throw Object.assign(new Error('HTTP ' + r.status), { status: r.status });
  return r.json();
}

// ---------- сесія Dawn ----------

// Сесія спільна для всіх ізолятів дата-центру (Cache API): PoW — раз на ~30 хв на дата-центр.
// ponytail: два холодні ізоляти одночасно розв'яжуть PoW обидва; KV/Durable Object — якщо Dawn почне різати за кількістю сесій
const SESSION_KEY = HOST + '/__session';
let session = null;

function zeroBits(buf) {
  let n = 0;
  for (const b of new Uint8Array(buf)) {
    if (b) return n + Math.clz32(b) - 24;
    n += 8;
  }
  return n;
}

async function solveSession() {
  const ch = (await json(DAWN + '/challenge')).result;
  let nonce = 0;
  while (zeroBits(await subtle.digest('SHA-256', enc.encode(ch.challenge + nonce))) < ch.difficulty) nonce++;
  const s = (await json(DAWN + '/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ challenge: ch.challenge, nonce: String(nonce) })
  })).result;
  const exp = Date.now() + s.expiresIn * 1000 - 60000;
  await caches.default.put(SESSION_KEY, new Response(JSON.stringify({ token: s.session, exp }), {
    headers: { 'Cache-Control': 'max-age=' + Math.floor((exp - Date.now()) / 1000) }
  }));
  return { token: s.session, exp };
}

async function newSession() {
  const hit = await caches.default.match(SESSION_KEY);
  let s = hit && (await hit.json());
  if (!s || Date.now() > s.exp) s = await solveSession();
  // ключ AES = HMAC("dawn:aurora:v1", session) — виводиться з токена, тож у кеші лише токен
  const hmac = await subtle.importKey('raw', enc.encode('dawn:aurora:v1'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const key = await subtle.importKey('raw', await subtle.sign('HMAC', hmac, enc.encode(s.token)), 'AES-GCM', false, ['decrypt']);
  return { token: s.token, key, exp: s.exp };
}

function getSession() {
  // session — Promise; exp дописується після отримання, до того вона вважається свіжою
  if (!session || Date.now() > session.exp) {
    const p = (session = newSession().then((s) => { p.exp = s.exp; return s; }, (e) => { session = null; throw e; }));
  }
  return session;
}

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function dawnOnce(path) {
  const s = await getSession();
  const r = (await json(DAWN + path, { headers: { 'X-Dawn-Session': s.token } })).result;
  return JSON.parse(new TextDecoder().decode(await subtle.decrypt({ name: 'AES-GCM', iv: b64(r.n) }, s.key, b64(r.d))));
}

async function dawn(path) {
  try {
    return await dawnOnce(path);
  } catch (e) {
    if (e.status !== 403) throw e;
    session = null;
    await caches.default.delete(SESSION_KEY); // відхилену сесію не беремо з кешу знову
    return dawnOnce(path);
  }
}

// ---------- кеш ----------

// Кеш дата-центру + злиття однакових запитів у польоті (тисячі глядачів популярної серії = 1 запит у Dawn).
// 404 теж кешується: тайтли без Dawn шукаються постійно
const inflight = new Map();

function cached(key, ttl, load, ctx) {
  if (inflight.has(key)) return inflight.get(key);
  const url = HOST + '/__cache' + key;
  const p = (async () => {
    const hit = await caches.default.match(url);
    if (hit) return hit.json();
    const data = await load().catch((e) => {
      if (e.status === 404) return { notFound: true };
      throw e;
    });
    ctx.waitUntil(caches.default.put(url, Response.json(data, { headers: { 'Cache-Control': 'max-age=' + ttl } })));
    return data;
  })().then((data) => {
    if (data.notFound) throw Object.assign(new Error('not found'), { status: 404 });
    return data;
  }).finally(() => inflight.delete(key));
  inflight.set(key, p);
  return p;
}

// релізи тайтла з серіями; 404 — у Dawn тайтла нема
function releases(id, ctx) {
  return cached('/v2/anime/' + id, 600, async () => {
    const d = await dawn('/v2/anime/' + id);
    return { releases: (d.releases || []).filter((r) => r.episodes && r.episodes.length) };
  }, ctx);
}

// потік і таймкоди пропуску (opening/ending) паралельно; без таймкодів серія все одно грає. Токен потоку живе ~40 хв
function video(id, vid, ctx) {
  return cached('/v2/video/' + id + '/' + vid, 300, async () => {
    const [v, skips] = await Promise.all([
      dawn('/v2/video/' + id + '/' + vid),
      json(DAWN + '/skips/' + id + '/' + vid).then((j) => (j.result || []).filter((s) => s.endSec > s.startSec)
        .map((s) => ({ start: s.startSec, end: s.endSec })), () => [])
    ]);
    return { hls: v.hls, skips };
  }, ctx);
}

// ---------- пошук тайтлів ----------

async function search(name) {
  try {
    return (await json(API + '/anime/search?name=' + encodeURIComponent(name))).result || [];
  } catch {
    return [];
  }
}

function uniq(lists) {
  const seen = new Set();
  return lists.flat().filter((a) => !seen.has(a.id) && seen.add(a.id));
}

// arm: IMDb → MAL-id кожного сезону/OVA; каталог шукає числовий name як MAL-id і віддає externalLinks для перевірки
async function byArm(imdb) {
  try {
    const mals = [...new Set((await json(ARM + encodeURIComponent(imdb))).map((e) => e.myanimelist).filter(Boolean))];
    return uniq(await Promise.all(mals.map(async (mal) => (await search(String(mal))).filter((a) => a.externalLinks?.malId === mal))));
  } catch {
    return [];
  }
}

async function findTitles({ imdb, names, year, tv }) {
  // IMDb нічого не підтвердив → нечіткий пошук каталогу віддає все підряд («Остання атака» — 23 тайтли);
  // лишаються близькі за роком (±1) і типом: фільм ↔ не-ТБ, серіал ↔ не-фільм
  const near = (found) => year ? found.filter((a) => Math.abs(a.year - year) <= 1 && (tv ? a.format !== 'movie' : a.format !== 'tv')) : found;

  // arm і пошук за назвою стартують паралельно; назва — запасний шлях, коли arm тайтл не знає
  const byName = Promise.all(names.map(search)).then(uniq);
  let list = imdb ? await byArm(imdb) : [];
  if (!list.length) {
    const found = await byName;
    list = near(found);
    if (imdb) {
      // пошук за назвою віддає порожні externalLinks — вони є лише в повній картці
      const matched = (await Promise.all(found.slice(0, 10).map((a) => json(API + '/anime/' + a.id)
        .then((j) => (j.result.externalLinks?.imdbId === imdb ? a : null), () => null)))).filter(Boolean);
      if (matched.length) list = matched;
    }
  }
  // анонси (year 0, startDate "0001-01-01") — в кінець
  const date = (a) => (a.year ? a.startDate || '' : '9999');
  return list.sort((a, b) => date(a).localeCompare(date(b)));
}

async function titles(q, ctx) {
  const list = await findTitles(q);
  // 404 — тайтла нема в Dawn; інший збій валить увесь запит (і не кешується) — плагін покаже помилку, повтор допоможе
  const rels = await Promise.all(list.map((a) => releases(a.id, ctx).then((d) => d.releases, (e) => {
    if (e.status === 404) return [];
    throw e;
  })));
  // плагіну — лише потрібні поля; тайтли без серій у Dawn — окремо, для повідомлення
  const names = (a) => ({ name: a.details?.names?.name, nameEnglish: a.details?.names?.nameEnglish });
  return {
    titles: list.map((a, i) => ({ id: a.id, slug: a.slug, year: a.year, format: a.format, startDate: a.startDate, details: { names: names(a) }, releases: rels[i] }))
      .filter((a) => a.releases.length),
    empty: list.filter((a, i) => !rels[i].length).map((a) => names(a).name || names(a).nameEnglish || a.slug)
  };
}

// ---------- маршрути ----------

const out = (data, maxAge) => Response.json(data, { headers: { ...CORS, 'Cache-Control': maxAge ? 'public, max-age=' + maxAge : 'no-store' } });

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname;
    let m;
    try {
      if (path === '/health') {
        const s = await getSession();
        return out({ ok: true, sessionTtl: Math.round((s.exp - Date.now()) / 1000) });
      }
      if (path === '/titles') {
        const p = url.searchParams;
        const q = { imdb: p.get('imdb') || '', names: p.getAll('name').filter(Boolean).slice(0, 3), year: +p.get('year') || 0, tv: p.get('tv') === '1' };
        const key = '/titles?' + [q.imdb, q.names.join('|'), q.year, +q.tv].map(encodeURIComponent).join('&');
        // браузер ТВ теж кешує 10 хв: повторне відкриття тайтла не витрачає ліміт воркера
        return out(await cached(key, 600, () => titles(q, ctx), ctx), 600);
      }
      if ((m = path.match(/^\/v2\/video\/(\d+)\/([\w-]+)$/))) return out(await video(m[1], m[2], ctx));
      if ((m = path.match(/^\/(\d+)\/([\w-]+)\.m3u8$/))) return Response.redirect((await video(m[1], m[2], ctx)).hls, 302);
      return new Response('not found', { status: 404, headers: CORS });
    } catch (e) {
      if (path === '/health') return Response.json({ ok: false, error: e.message }, { status: 502 });
      return new Response('Dawn: ' + e.message, { status: e.status === 404 ? 404 : 502, headers: CORS });
    }
  }
};
