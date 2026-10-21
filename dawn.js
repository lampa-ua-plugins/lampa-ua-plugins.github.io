// Dawn для Lampa: кнопка «Dawn» у картці аніме → екран у стилі online-плагінів (сезон, озвучка, серії).
// Тайтли: IMDb → arm → MAL-id → каталог; запасний шлях — пошук за назвою з перевіркою IMDb.
// Потік: плеєр Dawn — PoW → сесія → AES-GCM-відповідь (ключ = HMAC("dawn:aurora:v1", session)).
// Серії прив'язуються до TMDB за датою виходу → кадри, назви і прогрес як у Lampa.
// ES5 під цілі Lampa (Chrome 38, Safari 7): без fetch, Math.clz32, TextEncoder поза WebCrypto; Promise — поліфіл Lampa.
(function () {
  'use strict';

  if (window.dawn_plugin) return;

  var API = 'https://api.mikai.me/v1';
  var DAWN = API + '/player/dawn';
  var ARM = 'https://arm.haglund.dev/api/v2/imdb?id=';
  var net = window.Lampa && Lampa.Reguest ? new Lampa.Reguest() : null;
  var session = null;
  var pending = null;
  var libReady = null;

  // Lampa.Reguest: silent-запити йдуть паралельно; fetch — лише поза Lampa (test.mjs)
  function getJson(url, body, headers) {
    if (!net) {
      return fetch(url, body ? { method: 'POST', headers: headers, body: body } : { headers: headers }).then(function (r) {
        if (r.ok) return r.json();
        var e = new Error('HTTP ' + r.status);
        e.status = r.status;
        throw e;
      });
    }
    return new Promise(function (ok, fail) {
      net.silent(url, ok, function (x) {
        var e = new Error(net.errorDecode(x, ''));
        e.status = x && x.status;
        fail(e);
      }, body || false, headers ? { headers: headers } : undefined);
    });
  }

  function b64(s) {
    var bin = atob(s), a = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
    return a;
  }

  function zeroBits(buf) {
    var b = new Uint8Array(buf), n = 0;
    for (var i = 0; i < b.length; i++, n += 8) {
      if (b[i]) {
        for (var bit = 128; !(b[i] & bit); bit >>= 1) n++;
        return n;
      }
    }
    return n;
  }

  // crypto.subtle є лише в secure context: Lampa по http:// або старий WebView його не мають → node-forge з CDN.
  // Методи можуть повертати значення або Promise — виклики обгорнуті в Promise.resolve
  function webCrypto(subtle) {
    var enc = new TextEncoder();
    return {
      sha256: function (s) { return subtle.digest('SHA-256', enc.encode(s)); },
      aesKey: function (session) {
        return subtle.importKey('raw', enc.encode('dawn:aurora:v1'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
          .then(function (k) { return subtle.sign('HMAC', k, enc.encode(session)); })
          .then(function (raw) { return subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']); });
      },
      decrypt: function (key, n, d) {
        return subtle.decrypt({ name: 'AES-GCM', iv: b64(n) }, key, b64(d)).then(function (buf) {
          return new TextDecoder().decode(buf);
        });
      }
    };
  }

  function forgeCrypto(forge) {
    return {
      sha256: function (s) { return b64(btoa(forge.md.sha256.create().update(s, 'utf8').digest().getBytes())); },
      aesKey: function (session) {
        var h = forge.hmac.create();
        h.start('sha256', 'dawn:aurora:v1');
        h.update(session);
        return h.digest().getBytes();
      },
      // d = шифротекст + 16 байт тегу (формат WebCrypto)
      decrypt: function (key, n, d) {
        var bin = atob(d), c = forge.cipher.createDecipher('AES-GCM', key);
        c.start({ iv: atob(n), tag: forge.util.createBuffer(bin.slice(-16)) });
        c.update(forge.util.createBuffer(bin.slice(0, -16)));
        if (!c.finish()) throw new Error('AES-GCM: невірний тег');
        return forge.util.decodeUtf8(c.output.getBytes());
      }
    };
  }

  function lib() {
    if (window.crypto && window.crypto.subtle) return Promise.resolve(webCrypto(window.crypto.subtle));
    if (window.forge) return Promise.resolve(forgeCrypto(window.forge));
    return libReady || (libReady = new Promise(function (ok, fail) {
      var s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/node-forge@1.3.1/dist/forge.min.js';
      s.onload = function () { ok(forgeCrypto(window.forge)); };
      s.onerror = function () {
        libReady = null;
        fail(new Error('немає WebCrypto і не завантажився node-forge'));
      };
      document.head.appendChild(s);
    }));
  }

  // ponytail: один sha256 на nonce (~4k спроб при difficulty 15, <1 с); вбудований SHA-256, якщо складність зросте
  function solve(c, challenge, difficulty, nonce) {
    return Promise.resolve(c.sha256(challenge + nonce)).then(function (h) {
      return zeroBits(h) >= difficulty ? String(nonce) : solve(c, challenge, difficulty, nonce + 1);
    });
  }

  function newSession() {
    return lib().then(function (c) {
      return getJson(DAWN + '/challenge').then(function (j) {
        var ch = j.result;
        return solve(c, ch.challenge, ch.difficulty, 0).then(function (nonce) {
          return getJson(DAWN + '/session', JSON.stringify({ challenge: ch.challenge, nonce: nonce }), { 'Content-Type': 'application/json' });
        });
      }).then(function (j) {
        var s = j.result;
        return Promise.resolve(c.aesKey(s.session)).then(function (key) {
          return { token: s.session, key: key, crypto: c, exp: Date.now() + s.expiresIn * 1000 - 60000 };
        });
      });
    });
  }

  // одна сесія на всі паралельні запити
  function getSession() {
    if (session && Date.now() < session.exp) return Promise.resolve(session);
    return pending || (pending = newSession().then(function (s) {
      pending = null;
      return (session = s);
    }, function (e) {
      pending = null;
      throw e;
    }));
  }

  function dawnOnce(path) {
    return getSession().then(function (s) {
      return getJson(DAWN + path, null, { 'X-Dawn-Session': s.token }).then(function (j) {
        return s.crypto.decrypt(s.key, j.result.n, j.result.d);
      });
    }).then(JSON.parse);
  }

  // Сесію відхилено (403) → нова PoW і один повтор, як на сайті
  function dawn(path) {
    return dawnOnce(path).catch(function (e) {
      if (e.status !== 403) throw e;
      session = null;
      return dawnOnce(path);
    });
  }

  function search(name) {
    return getJson(API + '/anime/search?name=' + encodeURIComponent(name)).then(function (j) {
      return j.result || [];
    }, function () {
      return [];
    });
  }

  function uniq(lists) {
    var seen = {}, found = [];
    lists.forEach(function (l) {
      l.forEach(function (a) {
        if (!seen[a.id]) found.push(seen[a.id] = a);
      });
    });
    return found;
  }

  // arm: IMDb → MAL-id кожного сезону/OVA; каталог шукає числовий name як MAL-id і віддає externalLinks для перевірки
  function byArm(imdb) {
    return getJson(ARM + encodeURIComponent(imdb)).then(function (entries) {
      var mals = (entries || []).map(function (e) { return e.myanimelist; }).filter(function (m, i, a) {
        return m && a.indexOf(m) === i;
      });
      return Promise.all(mals.map(function (mal) {
        return search(String(mal)).then(function (list) {
          return list.filter(function (a) { return (a.externalLinks || {}).malId === mal; });
        });
      }));
    }).then(uniq, function () {
      return [];
    });
  }

  function findTitles(movie) {
    var names = [movie.original_name || movie.original_title, movie.name || movie.title].filter(function (n, i, a) {
      return n && a.indexOf(n) === i;
    });

    // arm і пошук за назвою стартують паралельно; назва — запасний шлях, коли arm тайтл не знає
    var byName = Promise.all(names.map(search)).then(uniq);
    var armed = movie.imdb_id ? byArm(movie.imdb_id) : Promise.resolve([]);

    return armed.then(function (found) {
      return found.length ? found : byName.then(movie.imdb_id ? verifyImdb : near);
    }).then(function (list) {
      return list.sort(function (a, b) {
        // анонси (year 0, startDate "0001-01-01") — в кінець
        return (a.year ? a.startDate || '' : '9999').localeCompare(b.year ? b.startDate || '' : '9999');
      });
    });

    // пошук за назвою віддає порожні externalLinks — вони є лише в повній картці
    function verifyImdb(found) {
      return Promise.all(found.slice(0, 10).map(function (a) {
        return getJson(API + '/anime/' + a.id).then(function (j) {
          return (j.result.externalLinks || {}).imdbId === movie.imdb_id ? a : null;
        }, function () {
          return null;
        });
      })).then(function (matched) {
        matched = matched.filter(Boolean);
        return matched.length ? matched : near(found);
      });
    }

    // IMDb нічого не підтвердив → нечіткий пошук каталогу віддає все підряд («Остання атака» — 23 тайтли);
    // лишаються близькі за роком (±1) і типом: фільм ↔ не-ТБ, серіал ↔ не-фільм
    function near(found) {
      var year = parseInt((movie.first_air_date || movie.release_date || '').slice(0, 4), 10);
      if (!year) return found;
      return found.filter(function (a) {
        return Math.abs(a.year - year) <= 1 && (movie.name ? a.format !== 'movie' : a.format !== 'tv');
      });
    }
  }

  var FORMATS = { tv: 'ТБ', movie: 'Фільм', ova: 'OVA', ona: 'ONA', special: 'Спешл' };

  function label(a) {
    var n = (a.details && a.details.names) || {};
    return n.name || n.nameEnglish || a.slug;
  }

  function isAnime(movie) {
    return movie.original_language === 'ja' || (movie.genres || []).some(function (g) { return g.id === 16; });
  }

  function days(date) {
    return Date.parse(date) / 864e5;
  }

  function tr(key) {
    return Lampa.Lang.translate(key);
  }

  // Перша серія тайтла каталогу серед серій TMDB — найближча за датою виходу (до 14 днів: TMDB і каталог розходяться на день-два)
  function locate(episodes, startDate) {
    var start = days(startDate), best = null, gap = 15;
    episodes.forEach(function (e) {
      var d = Math.abs(days(e.air_date) - start);
      if (d < gap) {
        gap = d;
        best = e;
      }
    });
    return best;
  }

  // Серії TMDB тайтла (episodes відсортовані за сезоном і серією): від його першої до першої серії наступного
  // тайтла або до кінця. Рахуємо позицією, а не episode_number: у One Piece TMDB нумерує наскрізно (S2 з 62-ї)
  function titleRange(episodes, first, starts) {
    var from = episodes.indexOf(first);
    if (from < 0) return [];
    var to = episodes.length;
    (starts || []).forEach(function (s) {
      var i = episodes.indexOf(s);
      if (i > from && i < to) to = i;
    });
    return episodes.slice(from, to);
  }

  // Перша серія тайтла в TMDB; фільми й анонси (year 0) не прив'язуються
  function start(a, eps) {
    return a.year && a.format !== 'movie' ? locate(eps, a.startDate) : null;
  }

  // Пункт фільтра «Сезон» = тайтл каталогу з його серіями TMDB (full); тайтл, що займає кілька сезонів TMDB
  // (One Piece — один тайтл на 23 сезони), ділиться посезонно (part), інакше це 1000+ карток в одному списку
  function entriesOf(titles, eps) {
    var starts = titles.map(function (a) { return start(a, eps); });
    var out = [];
    titles.forEach(function (a, i) {
      var full = titleRange(eps, starts[i], starts);
      var seasons = full.map(function (e) { return e.season_number; }).filter(function (s, j, l) { return l.indexOf(s) === j; });
      if (seasons.length < 2) return out.push({ anime: a, season: seasons[0], full: full, range: full, last: true });
      seasons.forEach(function (s, j) {
        out.push({
          anime: a,
          season: s,
          full: full,
          range: full.filter(function (e) { return e.season_number === s; }),
          last: j === seasons.length - 1,
          part: true
        });
      });
    });
    return out;
  }

  // Серії релізу, що належать пункту: посезонний — лише свого сезону; поза TMDB — останньому сезону тайтла
  function here(entry, release) {
    return release.episodes.filter(function (e) {
      if (!entry.part) return true;
      var te = entry.full[e.number - 1];
      return te ? te.season_number === entry.season : entry.last;
    });
  }

  function noty(e) {
    Lampa.Noty.show('Dawn: ' + ((e && e.message) || e));
  }

  // Екран у стилі online-плагінів Lampa: фільтр «Сезон» = пункти entriesOf, «Озвучка» = релізи Dawn
  function Component(object) {
    var scroll = new Lampa.Scroll({ mask: true, over: true });
    var files = new Lampa.Files(object);
    var filter = new Lampa.Filter(object);
    var movie = object.movie;
    var card_key = movie.original_name || movie.original_title || movie.name || movie.title;
    var titles = [];
    var entries = [];
    var rels = {};
    var choice = { season: 0, voice: 0, voice_name: '', title_id: '' };
    var last, last_filter;
    var alive = true;
    var self = this;

    scroll.body().addClass('torrent-list');

    // Серії TMDB усіх сезонів так, як їх показує Lampa (ця збірка ділить довгий 1-й сезон на псевдосезони за паузами >90 днів).
    // Кеш Reguest на добу (діє, коли в Lampa увімкнено кешування запитів): One Piece — 23 запити
    function tmdbEpisodes() {
      var api = Lampa.Api && Lampa.Api.sources && Lampa.Api.sources.tmdb;
      if (!movie.name || typeof movie.id !== 'number' || !api) return Promise.resolve([]);

      function season(n) {
        return new Promise(function (ok) {
          api.get('tv/' + movie.id + '/season/' + n, {}, ok, function () { ok(null); }, { life: 60 * 24 });
        });
      }

      return season(1).then(function (first) {
        var real = (movie.seasons || []).filter(function (s) { return s.season_number > 0; }).length;
        var count = Math.min(30, Math.max((first && first.seasons_count) || 0, movie.number_of_seasons || 0, real));
        var rest = [];
        for (var n = 2; n <= count; n++) rest.push(season(n));
        return Promise.all(rest).then(function (list) {
          return [first].concat(list).reduce(function (all, s) {
            return s && s.episodes ? all.concat(s.episodes) : all;
          }, []).sort(function (a, b) {
            return a.season_number - b.season_number || a.episode_number - b.episode_number;
          });
        });
      });
    }

    // Релізи Dawn тайтла (кеш у rels); 404 — у Dawn тайтла нема
    function releasesOf(a) {
      if (rels[a.id]) return Promise.resolve(rels[a.id]);
      return dawn('/v2/anime/' + a.id).then(function (d) {
        return (rels[a.id] = (d.releases || []).filter(function (r) { return r.episodes && r.episodes.length; }));
      }, function (e) {
        if (e.status === 404) return (rels[a.id] = []);
        throw e;
      });
    }

    function minus() {
      scroll.minus(window.innerWidth > 580 ? false : files.render().find('.files__left'));
    }

    function lines() {
      return scroll.render().find('.selector').not('.simple-button');
    }

    window.addEventListener('resize', minus, false);
    minus();

    function fail(e) {
      if (alive) self.empty('Dawn: ' + ((e && e.message) || e));
    }

    // вибір запам'ятовується за id тайтла (і сезоном для part): новий тайтл у каталозі зсуває індекси
    function entryKey(entry) {
      return entry.anime.id + ':' + (entry.part ? entry.season : '');
    }

    this.create = function () {
      filter.onSearch = function (value) {
        Lampa.Activity.replace({ search: value, clarification: true });
      };
      filter.onBack = this.start.bind(this);
      filter.render().find('.filter--sort').remove();
      filter.render().find('.selector').on('hover:focus', function (e) {
        last_filter = e.target;
      });
      filter.onSelect = function (type, a, b) {
        if (type !== 'filter') return;
        if (a.reset) choice = { season: 0, voice: 0, voice_name: '', title_id: '' };
        else {
          choice[a.stype] = b.index;
          if (a.stype === 'season') choice.title_id = entryKey(entries[b.index]);
          if (a.stype === 'voice') {
            choice.voice_name = b.title;
            jumpToVoice(rels[entries[choice.season].anime.id][b.index]);
          }
        }
        var data = Lampa.Storage.cache('dawn_choice', 500, {});
        data[movie.id] = choice;
        Lampa.Storage.set('dawn_choice', data);
        load();
      };

      files.append(scroll.render());
      scroll.append(filter.render());
      this.loading(true);

      // TMDB, пошук і релізи Dawn усіх тайтлів — паралельно (сесія PoW одна на всі запити)
      var eps = tmdbEpisodes();
      findTitles(object.clarification ? { name: object.search } : movie).then(function (list) {
        return Promise.all([eps].concat(list.map(function (a) {
          return releasesOf(a).catch(function () { return null; });
        }))).then(function (res) {
          if (!alive) return;
          if (!list.length) return self.empty('На запит (' + (object.search || card_key) + ') нічого не знайдено');
          // лише тайтли з серіями в Dawn; помилка мережі (null) — тайтл лишається
          titles = list.filter(function (a, i) { return !res[i + 1] || res[i + 1].length; });
          if (!titles.length) return self.empty('У плеєрі Dawn немає серій: ' + list.map(label).join(', '));
          // посезонні пункти без жодної серії в жодній озвучці (One Piece S2–S11) не показуємо
          entries = entriesOf(titles, res[0]).filter(function (en) {
            var r = rels[en.anime.id];
            return !en.part || !r || r.some(function (rel) { return here(en, rel).length; });
          });
          Lampa.Arrays.extend(choice, Lampa.Storage.cache('dawn_choice', 500, {})[movie.id] || {}, true);
          load();
        });
      }).catch(fail);

      return this.render();
    };

    // Озвучка, якої нема в поточному сезоні, → перший сезон цього тайтла, де вона є
    function jumpToVoice(release) {
      var entry = entries[choice.season];
      if (!release || here(entry, release).length) return;
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].anime === entry.anime && here(entries[i], release).length) {
          choice.season = i;
          choice.title_id = entryKey(entries[i]);
          return;
        }
      }
    }

    function load() {
      var saved = entries.map(entryKey).indexOf(choice.title_id);
      if (saved >= 0) choice.season = saved;
      if (!entries[choice.season]) choice.season = 0;
      var entry = entries[choice.season];

      self.reset();
      self.loading(true);

      releasesOf(entry.anime).then(function (list) {
        if (!alive) return;
        // у фільтрі всі озвучки тайтла; запам'ятована, якої нема в цьому сезоні, не обирається (але й не забувається)
        var voices = list.map(function (r) { return r.team.name + (r.isSubs ? ' (субтитри)' : ''); });
        var mine = list.map(function (r) { return here(entry, r); });
        var v = voices.indexOf(choice.voice_name);
        if (!mine[v] || !mine[v].length) v = mine[choice.voice] && mine[choice.voice].length ? choice.voice : mine.map(function (m) { return m.length > 0; }).indexOf(true);
        choice.voice = Math.max(0, v);

        setFilter(voices.map(function (title, i) {
          return { title: title, subtitle: mine[i].length ? mine[i].length + ' сер. у сезоні' : 'немає в цьому сезоні' };
        }));
        if (!list.length) return self.empty('У плеєрі Dawn немає серій');
        draw(entry, mine[choice.voice], voices[choice.voice]);
      }).catch(fail);
    }

    // Той самий ключ, що в Lampa (timeline.js, episode.js): «:» між сезоном > 10 і серією
    function timelineKey(season, episode) {
      return [season, season > 10 ? ':' : '', episode, card_key].join('');
    }

    // Пункти підписані сезоном TMDB (як у картці Lampa), назва з каталогу — під ним. Діапазон серій лише коли
    // сезон TMDB розбитий на кілька пунктів («Сезон 3 · серії 13–22»), інакше просто «Сезон 2».
    // Не знайдені в TMDB: ТБ — назвою (інакше без TMDB усі сезони були б «ТБ · рік»), OVA/спешли/фільми — типом
    function titleItem(entry, split) {
      var a = entry.anime, r = entry.range;
      var kind = [FORMATS[a.format] || a.format, a.year].filter(Boolean).join(' · ');
      if (!r.length) return a.format === 'tv' ? { title: label(a), subtitle: kind } : { title: kind, subtitle: label(a) };
      // кінець частини — за TMDB (як у списку серій), а якщо в Dawn серій більше — за Dawn
      var end = r[r.length - 1].episode_number;
      if (!entry.part) {
        (rels[a.id] || []).forEach(function (rel) {
          rel.episodes.forEach(function (e) { end = Math.max(end, r[0].episode_number + e.number - 1); });
        });
      }
      return {
        title: tr('torrent_serial_season') + ' ' + entry.season + (split ? ' · серії ' + r[0].episode_number + '–' + end : ''),
        subtitle: label(a)
      };
    }

    function setFilter(voices) {
      var per = {};
      entries.forEach(function (en) {
        if (en.range.length) per[en.season] = (per[en.season] || 0) + 1;
      });
      var items = {
        voice: voices,
        season: entries.map(function (en) { return titleItem(en, en.range.length && per[en.season] > 1); })
      };
      var select = [{ title: tr('torrent_parser_reset'), reset: true }];
      var chosen = [];

      [['voice', 'torrent_parser_voice'], ['season', 'torrent_serial_season']].forEach(function (f) {
        var type = f[0], title = tr(f[1]), current = items[type][choice[type]];
        if (items[type].length < 2) return;
        select.push({
          title: title,
          subtitle: current.title,
          stype: type,
          items: items[type].map(function (it, index) {
            return { title: it.title, subtitle: it.subtitle, selected: choice[type] === index, index: index };
          })
        });
        // «Сезон 4 · серії 17–28» уже містить слово «Сезон»
        chosen.push(type === 'season' ? current.title : title + ': ' + current.title);
      });

      filter.set('filter', select);
      filter.chosen('filter', chosen);
    }

    function draw(entry, episodes, voice) {
      var viewed = Lampa.Storage.cache('dawn_view', 5000, []);
      var anime = entry.anime;
      var name = label(anime);
      var film = anime.format === 'movie' && episodes.length === 1;
      var byTmdb = {};

      // ponytail: url кешується до кінця сесії плеєра; токен потоку живе ~40 хв, після цього серію треба відкрити заново
      var playlist = episodes.map(function (ep) {
        // знайдена в TMDB серія дає сезон/серію як у Lampa → спільний прогрес з іншими плагінами;
        // не знайдена (OVA, спешл) — власний ключ за id тайтла, щоб не наступити на справжній сезон
        var te = entry.full[ep.number - 1] || null;
        var key = film ? card_key : te ? timelineKey(te.season_number, te.episode_number) : ['dawn', anime.id, ep.number, card_key].join('');
        var item = {
          title: playTitle(te, ep),
          timeline: Lampa.Timeline.view(Lampa.Utils.hash(key)),
          season: te ? te.season_number : 0,
          episode: te ? te.episode_number : 0,
          card: movie,
          hash_file: Lampa.Utils.hash(key + 'dawn'),
          tmdb: te,
          ep: ep
        };
        // Lampa викликає url(call) лише для серії, обраної в плейлисті, по одній (wait_for_loading_url у player.js).
        // Помилка: без call() плеєр завис би на завантаженні до закриття — закриваємо його, екран серій лишається
        item.url = function (call) {
          resolve(item).then(function () { call(); }, function (e) {
            noty(e);
            Lampa.Player.close();
          });
        };
        if (te) byTmdb[te.season_number + ':' + te.episode_number] = item;
        return item;
      });

      // Як у інших плагінах: «Серіал / Сезон 4 / 17. Назва серії»; без TMDB — тайтл каталогу і його номер серії
      function playTitle(te, ep) {
        if (film) return name;
        var base = movie.name || movie.title || name;
        if (!te) return base + ' / ' + name + ' / ' + tr('torrent_serial_episode') + ' ' + ep.number;
        return base + ' / ' + tr('torrent_serial_season') + ' ' + te.season_number + ' / ' + te.episode_number + (te.name ? '. ' + te.name : '');
      }

      // Потік і таймкоди пропуску (opening/ending) паралельно; таймкоди → segments.skip плеєра Lampa
      // (пропуск або кнопка — за налаштуванням «Пропуск» у Lampa). Без таймкодів серія все одно грає
      function resolve(item) {
        if (typeof item.url === 'string') return Promise.resolve(item.url);
        var path = anime.id + '/' + item.ep.video;
        var skips = getJson(DAWN + '/skips/' + path).then(function (j) {
          return (j.result || []).filter(function (s) { return s.endSec > s.startSec; }).map(function (s) {
            return { start: s.startSec, end: s.endSec };
          });
        }, function () {
          return [];
        });
        return Promise.all([dawn('/v2/video/' + path), skips]).then(function (r) {
          if (r[1].length) item.segments = { skip: r[1] };
          return (item.url = r[0].hls);
        });
      }

      function play(item) {
        var cancelled = false;
        Lampa.Loading.start(function () {
          cancelled = true;
          Lampa.Loading.stop();
        });
        resolve(item).then(function () {
          Lampa.Loading.stop();
          if (cancelled) return;
          if (movie.id) Lampa.Favorite.add('history', movie, 100);
          item.playlist = playlist;
          Lampa.Player.play(item);
          Lampa.Player.playlist(playlist);
        }, function (e) {
          Lampa.Loading.stop();
          noty(e);
        });
      }

      function mark(html, on) {
        html.find('.online-prestige__viewed').remove();
        if (on) html.find('.online-prestige__img').append('<div class="online-prestige__viewed">' + Lampa.Template.get('icon_viewed', {}, true) + '</div>');
      }

      function setViewed(html, item, on) {
        Lampa.Arrays.remove(viewed, item.hash_file);
        if (on) viewed.push(item.hash_file);
        Lampa.Storage.set('dawn_view', viewed);
        mark(html, on);
      }

      // Картка серії; без item — серія TMDB, якої нема в цій озвучці: напівпрозора, без запуску (як в online.js)
      function card(te, item) {
        var number = te ? te.episode_number : item.ep.number;
        var info = [];
        if (te && te.air_date && window.innerWidth > 480) info.push(Lampa.Utils.parseTime(te.air_date).full);
        if (item) info.push(voice);
        var left = item || !te ? 0 : Math.round(days(te.air_date) - Date.now() / 864e5);

        var html = Lampa.Template.get('dawn_full', {
          title: film ? name : (te && te.name) || tr('torrent_serial_episode') + ' ' + number,
          time: te && te.runtime ? Lampa.Utils.secondsToTime(te.runtime * 60, true) : '',
          info: info.map(function (line) { return '<span>' + line + '</span>'; }).join('<span class="online-prestige-split">●</span>'),
          quality: left > 0 ? tr('full_episode_days_left') + ': ' + left : ''
        });

        poster(html, film ? 0 : number, te && te.still_path);
        html.find('.online-prestige__timeline').append(Lampa.Timeline.render(item ? item.timeline : Lampa.Timeline.view(Lampa.Utils.hash(timelineKey(te.season_number, te.episode_number)))));
        self.append(html);
        if (!item) return html.css('opacity', '0.5');

        mark(html, viewed.indexOf(item.hash_file) !== -1);
        html.on('hover:enter', function () {
          play(item);
          setViewed(html, item, true);
        }).on('hover:long', function () {
          menu(html, item);
        });
      }

      function menu(html, item) {
        var enabled = Lampa.Controller.enabled().name;
        var items = [
          { title: tr('torrent_parser_label_title'), mark: true },
          { title: tr('torrent_parser_label_cancel_title'), clearmark: true },
          { title: tr('time_reset'), timeclear: true }
        ];
        if (Lampa.Platform.is('webos')) items.push({ title: tr('player_lauch') + ' - Webos', player: 'webos' });
        if (Lampa.Platform.is('android')) items.push({ title: tr('player_lauch') + ' - Android', player: 'android' });
        items.push({ title: tr('player_lauch') + ' - Lampa', player: 'lampa' }, { title: tr('copy_link'), copylink: true });

        Lampa.Select.show({
          title: tr('title_action'),
          items: items,
          onBack: function () {
            Lampa.Controller.toggle(enabled);
          },
          onSelect: function (a) {
            if (a.mark || a.clearmark) setViewed(html, item, !!a.mark);
            if (a.timeclear) {
              item.timeline.percent = item.timeline.time = item.timeline.duration = 0;
              Lampa.Timeline.update(item.timeline);
            }
            Lampa.Controller.toggle(enabled);
            if (a.player) {
              Lampa.Player.runas(a.player);
              html.trigger('hover:enter');
            }
            if (a.copylink) {
              resolve(item).then(function (url) {
                Lampa.Utils.copyTextToClipboard(url, function () {
                  Lampa.Noty.show(tr('copy_secuses'));
                }, function () {
                  Lampa.Noty.show(tr('copy_error'));
                });
              }, noty);
            }
          }
        });
      }

      // серії TMDB пункту по порядку (наявні й ні), потім серії поза TMDB
      entry.range.forEach(function (te) {
        card(te, byTmdb[te.season_number + ':' + te.episode_number]);
      });
      playlist.filter(function (it) { return !it.tmdb; }).sort(function (a, b) {
        return a.ep.number - b.ep.number;
      }).forEach(function (it) {
        card(null, it);
      });

      self.start(true);
      self.loading(false);
    }

    // кадр серії з TMDB, інакше фон картки
    function poster(html, number, still) {
      var image = html.find('.online-prestige__img');
      var loader = html.find('.online-prestige__loader');
      var path = still || movie.backdrop_path;
      var badge = function () {
        if (number) image.append('<div class="online-prestige__episode-number">' + (number < 10 ? '0' + number : number) + '</div>');
      };

      if (!path) {
        html.find('img').remove();
        loader.remove();
        return badge();
      }

      var img = html.find('img')[0];
      img.onerror = function () {
        img.src = './img/img_broken.svg';
      };
      img.onload = function () {
        image.addClass('online-prestige__img--loaded');
        loader.remove();
        badge();
      };
      img.src = Lampa.TMDB.image('t/p/w300' + path);
    }

    this.reset = function () {
      last = false;
      scroll.render().find('.empty').remove();
      filter.render().detach();
      scroll.clear();
      scroll.append(filter.render());
    };

    this.loading = function (status) {
      this.activity.loader(status);
      if (!status) this.activity.toggle();
    };

    this.append = function (item) {
      item.on('hover:focus', function (e) {
        last = e.target;
        scroll.update($(e.target), true);
      });
      scroll.append(item);
    };

    this.empty = function (msg) {
      var empty = Lampa.Template.get('list_empty');
      if (msg) empty.find('.empty__descr').text(msg);
      scroll.append(empty);
      this.loading(false);
    };

    this.start = function (first_select) {
      if (Lampa.Activity.active().activity !== this.activity) return;
      if (first_select) last = lines().eq(0)[0];

      Lampa.Background.immediately(Lampa.Utils.cardImgBackground(movie));
      Lampa.Controller.add('content', {
        toggle: function () {
          Lampa.Controller.collectionSet(scroll.render(), files.render());
          Lampa.Controller.collectionFocus(last || false, scroll.render());
        },
        up: function () {
          if (!Navigator.canmove('up')) return Lampa.Controller.toggle('head');
          if (last_filter && lines().index(last) === 0) Lampa.Controller.collectionFocus(last_filter, scroll.render());
          else Navigator.move('up');
        },
        down: function () {
          Navigator.move('down');
        },
        right: function () {
          if (Navigator.canmove('right')) Navigator.move('right');
          else filter.show(tr('title_filter'), 'filter');
        },
        left: function () {
          if (Navigator.canmove('left')) Navigator.move('left');
          else Lampa.Controller.toggle('menu');
        },
        back: this.back
      });
      Lampa.Controller.toggle('content');
    };

    this.render = function () {
      return files.render();
    };

    this.back = function () {
      Lampa.Activity.backward();
    };

    this.pause = function () {};
    this.stop = function () {};

    this.destroy = function () {
      alive = false;
      files.destroy();
      scroll.destroy();
      window.removeEventListener('resize', minus);
    };
  }

  // CSS online-prestige (як в online.js / Флігель) — лише використані правила; префікси тільки -webkit- для старих WebView
  var FLEX = 'display:-webkit-box;display:-webkit-flex;display:flex;';
  var CENTER = '-webkit-box-align:center;-webkit-align-items:center;align-items:center;';
  var CLAMP = 'overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical';
  var CSS = '.online-prestige{position:relative;border-radius:.3em;background-color:rgba(0,0,0,.3);' + FLEX + 'will-change:transform}' +
    '.online-prestige__body{padding:1.2em;line-height:1.3;-webkit-box-flex:1;-webkit-flex-grow:1;flex-grow:1;position:relative}' +
    '.online-prestige__img{position:relative;width:13em;-webkit-flex-shrink:0;flex-shrink:0;min-height:8.2em}' +
    '.online-prestige__img>img{position:absolute;top:0;left:0;width:100%;height:100%;object-fit:cover;border-radius:.3em;opacity:0;-webkit-transition:opacity .3s;transition:opacity .3s}' +
    '.online-prestige__img--loaded>img{opacity:1}' +
    '.online-prestige__viewed{position:absolute;top:1em;left:1em;background:rgba(0,0,0,.45);border-radius:100%;padding:.25em;font-size:.76em}' +
    '.online-prestige__viewed>svg{width:1.5em!important;height:1.5em!important}' +
    '.online-prestige__episode-number{position:absolute;top:0;left:0;right:0;bottom:0;' + FLEX + CENTER + '-webkit-box-pack:center;-webkit-justify-content:center;justify-content:center;font-size:2em}' +
    '.online-prestige__loader{position:absolute;top:50%;left:50%;width:2em;height:2em;margin:-1em 0 0 -1em;background:url(./img/loader.svg) no-repeat center;background-size:contain}' +
    '.online-prestige__head,.online-prestige__footer{' + FLEX + CENTER + '-webkit-box-pack:justify;-webkit-justify-content:space-between;justify-content:space-between}' +
    '.online-prestige__timeline{margin:.8em 0}.online-prestige__timeline>.time-line{display:block!important}' +
    '.online-prestige__title,.online-prestige__info>*{' + CLAMP + '}.online-prestige__title{font-size:1.7em}' +
    '.online-prestige__time{padding-left:2em}.online-prestige__info{' + FLEX + CENTER + '}' +
    '.online-prestige__quality{padding-left:1em;white-space:nowrap}' +
    '.online-prestige-split{font-size:.8em;margin:0 1em;-webkit-flex-shrink:0;flex-shrink:0}' +
    '.online-prestige.focus::after{content:"";position:absolute;top:-.6em;left:-.6em;right:-.6em;bottom:-.6em;border-radius:.7em;border:solid .3em #fff;z-index:-1;pointer-events:none}' +
    '.online-prestige+.online-prestige{margin-top:1.5em}' +
    '@media screen and (max-width:480px){.online-prestige__body{padding:.8em 1.2em}.online-prestige__img{width:7em;min-height:6em}.online-prestige__title{font-size:1.4em}}';

  function addTemplates() {
    Lampa.Template.add('dawn_full', '<div class="online-prestige online-prestige--full selector">' +
      '<div class="online-prestige__img"><img alt=""><div class="online-prestige__loader"></div></div>' +
      '<div class="online-prestige__body">' +
      '<div class="online-prestige__head"><div class="online-prestige__title">{title}</div><div class="online-prestige__time">{time}</div></div>' +
      '<div class="online-prestige__timeline"></div>' +
      '<div class="online-prestige__footer"><div class="online-prestige__info">{info}</div><div class="online-prestige__quality">{quality}</div></div>' +
      '</div></div>');
    if (!$('#dawn_style').length) $('body').append('<style id="dawn_style">' + CSS + '</style>');
  }

  function push(movie) {
    Lampa.Activity.push({
      url: '',
      title: 'Dawn',
      component: 'dawn',
      search: movie.title || movie.name,
      search_one: movie.title || movie.name,
      search_two: movie.original_title || movie.original_name,
      movie: movie,
      page: 1
    });
  }

  // «Онлайн» на кнопці, назва плеєра — підписом під нею (data-subtitle, як у інших online-плагінів)
  var BUTTON = '<div class="full-start__button selector view--online dawn--button" data-subtitle="Dawn">' +
    // іконка «Кома»: дві панелі манги з косим просвітом, play вирізаний у великій (evenodd — без mask і id)
    '<svg width="28" height="28" viewBox="0 0 28 28" xmlns="http://www.w3.org/2000/svg">' +
    '<path d="M3 3h22v13L3 20zM11.2 6.3v8.4l7.2-4.2z" fill="currentColor" fill-rule="evenodd" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>' +
    '<path d="M3 23l22-4v6H3z" fill="currentColor" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/></svg>' +
    '<span>Онлайн</span></div>';

  function addButton(render, movie) {
    if (!render.length || !movie || !isAnime(movie) || render.parent().find('.dawn--button').length) return;
    render.after($(BUTTON).on('hover:enter', function () { push(movie); }));
  }

  function startPlugin() {
    addTemplates();
    Lampa.Component.add('dawn', Component);

    Lampa.Manifest.plugins = {
      type: 'video',
      version: '1.0.0',
      name: 'Dawn',
      description: 'Аніме з українською озвучкою',
      component: 'dawn',
      onContextMenu: function () {
        return { name: 'Dawn', description: '' };
      },
      onContextLauch: push
    };

    Lampa.Listener.follow('full', function (e) {
      if (e.type == 'complite') addButton(e.object.activity.render().find('.view--torrent'), e.data.movie);
    });

    try {
      var active = Lampa.Activity.active();
      if (active.component == 'full') addButton(active.activity.render().find('.view--torrent'), active.card);
    } catch (e) {}
  }

  window.dawn_plugin = { findTitles: findTitles, dawn: dawn, locate: locate, titleRange: titleRange, entriesOf: entriesOf, zeroBits: zeroBits };

  if (window.appready) startPlugin();
  else Lampa.Listener.follow('app', function (e) {
    if (e.type === 'ready') startPlugin();
  });
})();
