// Duggleby Poker League public stats. The stats in data.json are encrypted on the Pi
// (AES-256-GCM, key from the league password via PBKDF2-SHA256); this page decrypts them in the
// browser. "Remember on this device" keeps the derived key, never the password.
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const AAD = new TextEncoder().encode("DPL-stats-v1");
  const STORE = "dpl-stats-key";
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const money = (c) => (c < 0 ? "-$" : "$") + (Math.abs(c) / 100).toLocaleString(undefined, { minimumFractionDigits: Math.abs(c) % 100 ? 2 : 0 });
  const store = {
    get() { try { return JSON.parse(localStorage.getItem(STORE)); } catch (e) { return null; } },
    set(v) { try { localStorage.setItem(STORE, JSON.stringify(v)); } catch (e) { /* private mode */ } },
    clear() { try { localStorage.removeItem(STORE); } catch (e) { /* ignore */ } },
  };
  let env, data, view = { tab: "standings", season: null, player: null, q: "" };

  async function decrypt(key) {
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv), additionalData: AAD }, key, b64(env.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  async function keyFromPassword(pw, extractable) {
    const raw = new TextEncoder().encode(pw.trim().normalize("NFC"));
    const base = await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64(env.salt), iterations: env.iterations },
      base, { name: "AES-GCM", length: 256 }, extractable, ["decrypt"]);
  }

  async function start() {
    if (!window.crypto || !crypto.subtle) {
      $("lock").hidden = false;
      $("err").textContent = "This browser can't unlock the stats (it needs a secure https page).";
      return;
    }
    try {
      env = await (await fetch("data.json", { cache: "no-store" })).json();
    } catch (e) {
      $("lock").hidden = false;
      $("err").textContent = "Couldn't load the stats. Check your connection and reload.";
      return;
    }
    const saved = store.get();
    if (saved && saved.salt === env.salt) {
      try {
        const key = await crypto.subtle.importKey("raw", b64(saved.key), "AES-GCM", false, ["decrypt"]);
        return show(await decrypt(key));
      } catch (e) { store.clear(); }
    } else if (saved) {
      store.clear(); // the password was changed
    }
    $("lock").hidden = false;
    $("pw").focus();
  }

  $("unlock").onsubmit = async (e) => {
    e.preventDefault();
    $("err").textContent = "";
    $("go").disabled = true;
    $("go").textContent = "Unlocking…";
    try {
      const remember = $("remember").checked, key = await keyFromPassword($("pw").value, remember);
      let d;
      try { d = await decrypt(key); } catch (err) { throw new Error("Wrong password."); }
      if (remember) {
        const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
        store.set({ salt: env.salt, key: btoa(String.fromCharCode(...raw)) });
      }
      $("pw").value = "";
      show(d);
    } catch (err) {
      $("err").textContent = err.message || "Couldn't unlock.";
    } finally {
      $("go").disabled = false;
      $("go").textContent = "Unlock";
    }
  };

  $("forget").onclick = () => { store.clear(); location.reload(); };

  function show(d) {
    data = d;
    $("lock").hidden = true;
    $("app").hidden = false;
    $("forget").hidden = false;
    const open = d.seasons.find((s) => s.status !== "closed") || d.seasons[0];
    view.season = open ? open.id : null;
    render();
  }

  function render() {
    const tabs = [["standings", "Standings"], ["race", "Race"], ["h2h", "Head to Head"], ["players", "Players"], ["seasons", "Seasons"], ["hof", "Hall of Fame"]];
    const body = view.player != null ? profile(view.player) : { standings, race, h2h, players, seasons, hof }[view.tab]();
    $("app").innerHTML = `
      <div class="tabs">${tabs.map(([k, l]) => `<button data-tab="${k}" class="${k === view.tab && view.player == null ? "on" : ""}">${l}</button>`).join("")}</div>
      ${body}
      <p class="muted">Updated ${new Date(data.generated_at).toLocaleString()}. Only finalized games count.</p>`;
    $("app").querySelectorAll("[data-tab]").forEach((b) => (b.onclick = () => { view.tab = b.dataset.tab; view.player = null; render(); }));
    $("app").querySelectorAll("[data-p]").forEach((b) => (b.onclick = () => { view.player = Number(b.dataset.p); render(); window.scrollTo(0, 0); }));
    for (const k of ["h2a", "h2b"]) if ($(k)) $(k).onchange = () => { view[k] = Number($(k).value); render(); };
    const sel = $("season");
    if (sel) sel.onchange = () => { view.season = Number(sel.value); render(); };
    const q = $("q");
    if (q) {
      q.oninput = () => { view.q = q.value; const pos = q.selectionStart; render(); $("q").focus(); $("q").setSelectionRange(pos, pos); };
    }
    if ($("back")) $("back").onclick = () => { view.player = null; render(); };
  }

  function standings() {
    if (!data.seasons.length) return `<div class="panel"><p class="muted">No seasons yet.</p></div>`;
    const s = data.seasons.find((x) => x.id === view.season) || data.seasons[0], m = data.show_money;
    return `<div class="panel stack">
      <div class="top"><h2 style="margin:0">${esc(s.name)} Standings</h2>
        <select id="season" style="width:auto" aria-label="Season">${data.seasons.map((x) => `<option value="${x.id}" ${x.id === s.id ? "selected" : ""}>${esc(x.name)}${x.status === "closed" ? " (closed)" : ""}</option>`).join("")}</select></div>
      <p class="muted">${s.games_finalized} of ${s.game_target} league games played. Tied players share a rank (T).</p>
      <div class="scroll"><table><thead><tr><th>#</th><th>Player</th><th class="n">Points</th><th class="n">GP</th><th class="n">Wins</th><th class="n">ITM</th><th class="n">KOs</th><th class="n">Rebuys</th><th class="n">Avg</th>${m ? `<th class="n">Won</th>` : ""}</tr></thead>
      <tbody>${s.standings.map((r) => `<tr data-p="${r.player_id}">
        <td>${r.tied ? "T" : ""}${r.rank}</td><td><b>${esc(r.display_name)}</b></td><td class="n"><b class="gold">${r.points}</b></td>
        <td class="n">${r.games_played}</td><td class="n">${r.wins}</td><td class="n">${r.itm}</td><td class="n">${r.knockouts}</td><td class="n">${r.rebuys}</td>
        <td class="n">${r.avg_finish ?? "–"}</td>${m ? `<td class="n">${money(r.winnings_cents)}</td>` : ""}</tr>`).join("") || `<tr><td colspan="10" class="muted">No players yet.</td></tr>`}</tbody></table></div>
    </div>`;
  }

  // The Championship Race: each top-8 player's cumulative league points after every finalized game
  // (the same chart and colours as the TV during breaks). Finalized results only.
  function race() {
    const list = data.seasons.filter((x) => x.race);
    if (!list.length) return `<div class="panel"><p class="muted">The race starts once the first league game of a season is finalized.</p></div>`;
    const s = list.find((x) => x.id === view.season) || list[0], r = s.race;
    // Drawn at the screen's real width (1 unit = 1 px) so the labels stay readable on phones.
    const W = Math.max(280, Math.min(900, ($("app").clientWidth || 480) - 34)), H = Math.round(Math.min(340, Math.max(220, W * 0.6)));
    const L = 36, R = 12, T = 10, B = 30;
    const n = Math.max(r.game_target || 0, r.games[r.games.length - 1] || 1);
    const max = Math.max(1, ...r.players.map((p) => p.points[p.points.length - 1] || 0));
    const raw = max / 5, mag = 10 ** Math.floor(Math.log10(raw));
    const step = Math.max(1, [1, 2, 2.5, 5, 10].map((k) => k * mag).find((v) => v >= raw));
    const top = Math.ceil(max / step) * step;
    const x = (g) => L + ((W - L - R) * g) / n, y = (v) => T + (H - T - B) * (1 - v / top);
    const every = Math.ceil(n / 10);
    let svg = "";
    for (let v = 0; v <= top + 1e-9; v += step)
      svg += `<line x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}" class="grid"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${+v.toFixed(1)}</text>`;
    for (let g = 1; g <= n; g++)
      if (g % every === 0 || g === 1) svg += `<text x="${x(g)}" y="${H - B + 16}" text-anchor="middle">${g}</text>`;
    svg += `<text x="${(L + W - R) / 2}" y="${H - 2}" text-anchor="middle">League game</text>`;
    for (const p of [...r.players].reverse()) {  // the leader is drawn last, on top
      const pts = [[0, 0], ...r.games.map((g, i) => [g, p.points[i]])];
      const [lx, ly] = pts[pts.length - 1];
      svg += `<polyline points="${pts.map(([g, v]) => `${x(g).toFixed(1)},${y(v).toFixed(1)}`).join(" ")}" stroke="${p.colour}"/>
        <circle cx="${x(lx)}" cy="${y(ly)}" r="4" fill="${p.colour}"/>`;
    }
    return `<div class="panel stack">
      <div class="top"><h2 style="margin:0">${esc(s.name)} Championship Race</h2>
        <select id="season" style="width:auto" aria-label="Season">${list.map((x) => `<option value="${x.id}" ${x.id === s.id ? "selected" : ""}>${esc(x.name)}${x.status === "closed" ? " (closed)" : ""}</option>`).join("")}</select></div>
      <p class="muted">Points after each of the ${s.games_finalized} league games played so far (of ${s.game_target}). Top 8 only; everyone is in the Standings.</p>
      <svg class="race" viewBox="0 0 ${W} ${H}" role="img" aria-label="Cumulative points per league game">${svg}</svg>
      <table><thead><tr><th>#</th><th>Player</th><th class="n">Points</th><th class="n">Behind</th></tr></thead>
      <tbody>${r.players.map((p) => `<tr data-p="${p.player_id}"><td>${p.tied ? "T" : ""}${p.rank}</td>
        <td><span class="sw" style="background:${p.colour}"></span><b>${esc(p.name)}</b></td>
        <td class="n"><b class="gold">${p.total}</b></td><td class="n">${p.behind ? `−${p.behind}` : "Leader"}</td></tr>`).join("")}</tbody></table>
    </div>`;
  }

  // Head to Head: any two players side by side (the TV's Heads-Up Showdown, without money).
  function h2h() {
    const H = data.head_to_head || { players: {}, pairs: {} };
    const list = data.players.map((p) => p.player).filter((p) => H.players[p.id]);
    if (list.length < 2) return `<div class="panel"><p class="muted">Head to Head starts once two players have finished a game.</p></div>`;
    if (!list.some((p) => p.id === view.h2a) || !list.some((p) => p.id === view.h2b)) {
      // Default: the top two of the current standings, else the first two players.
      const st = (data.seasons.find((s) => s.status !== "closed") || data.seasons[0] || { standings: [] }).standings
        .map((r) => r.player_id).filter((id) => H.players[id]);
      const ids = [...st, ...list.map((p) => p.id)].filter((v, i, a) => a.indexOf(v) === i);
      if (!list.some((p) => p.id === view.h2a)) view.h2a = ids.find((id) => id !== view.h2b);
      if (!list.some((p) => p.id === view.h2b)) view.h2b = ids.find((id) => id !== view.h2a);
    }
    const a = view.h2a, b = view.h2b;
    const pick = (id, other) => `<select id="${id}" aria-label="Player">${list.map((p) => `<option value="${p.id}" ${p.id === view[id] ? "selected" : ""} ${p.id === other ? "disabled" : ""}>${esc(p.display_name)}</option>`).join("")}</select>`;
    const name = (id) => esc(list.find((p) => p.id === id).display_name);
    const A = H.players[a], B = H.players[b];
    const d = H.pairs[`${Math.min(a, b)}-${Math.max(a, b)}`] || { games: 0, a_higher: 0, b_higher: 0, kos_ab: 0, kos_ba: 0 };
    const aFirst = a < b, side = (x, y) => (aFirst ? [x, y] : [y, x]);
    const [koA, koB] = side(d.kos_ab, d.kos_ba), [hiA, hiB] = side(d.a_higher, d.b_higher);
    const wins = (p) => p.wins_league + p.wins_casual + p.wins_historical;
    const wsub = (p) => [`${p.wins_league} league`, `${p.wins_casual} casual`, p.wins_historical ? `${p.wins_historical} historical` : ""].filter(Boolean).join(" · ");
    const hu = (p) => (p.hu_matches ? `${p.hu_wins}–${p.hu_matches - p.hu_wins}` : "–");
    // One row: left value, label, right value; the bigger number is gold.
    const row = (label, va, vb, na, nb, sa = "", sb = "") => `<div class="h2row">
        <div class="${na > nb ? "lead" : ""}"><div class="v">${va}</div>${sa ? `<div class="s">${sa}</div>` : ""}</div>
        <div class="k">${label}</div>
        <div class="${nb > na ? "lead" : ""}"><div class="v">${vb}</div>${sb ? `<div class="s">${sb}</div>` : ""}</div></div>`;
    return `<div class="panel stack">
      <h2 style="margin:0">Head to Head</h2>
      <div class="h2pick">${pick("h2a", b)}<span class="vs">vs</span>${pick("h2b", a)}</div>
      <div class="h2row names"><div><b>${name(a)}</b></div><div></div><div><b>${name(b)}</b></div></div>
      ${row(`Knocked out the other`, koA, koB, koA, koB)}
      ${row(`Finished higher<br><span class="muted">in ${d.games} game${d.games === 1 ? "" : "s"} together</span>`, hiA, hiB, hiA, hiB)}
      ${row("Heads-up record<br><span class=\"muted\">won–lost, all opponents</span>", hu(A), hu(B), A.hu_pct ?? -1, B.hu_pct ?? -1,
            A.hu_pct != null ? `${A.hu_pct}%` : "", B.hu_pct != null ? `${B.hu_pct}%` : "")}
      ${row("Career wins", wins(A), wins(B), wins(A), wins(B), wsub(A), wsub(B))}
      ${row("Games played", A.games, B.games, 0, 0)}
      <p class="muted" style="margin:0">Finalized games recorded in the app; career wins also count historical records.
        Heads-up means finishing 1st or 2nd.</p>
    </div>`;
  }

  function players() {
    const q = view.q.trim().toLowerCase();
    const list = data.players.filter((p) => p.player.display_name.toLowerCase().includes(q));
    return `<div class="panel stack"><h2 style="margin:0">Players</h2>
      <input id="q" type="text" placeholder="Search players" aria-label="Search players" value="${esc(view.q)}">
      <div class="list">${list.map((p) => `<button data-p="${p.player.id}">${esc(p.player.display_name)}</button>`).join("") || `<p class="muted">No players found.</p>`}</div></div>`;
  }

  function profile(id) {
    const p = data.players.find((x) => x.player.id === id);
    if (!p) return `<button id="back">← Back</button><p class="muted">No stats for this player yet.</p>`;
    const cs = p.current_season, w = p.winnings;
    const tile = (k, v) => `<div class="tile"><div class="v">${v}</div><div class="k">${k}</div></div>`;
    return `<button id="back">← Back</button>
      <div class="panel stack">
        <div class="head"><div class="avatar">♠</div><div><h1 style="margin:0">${esc(p.player.display_name)}</h1>
          <div class="gold" style="font-weight:700">${cs ? `${cs.tied ? "T" : "#"}${cs.rank} in ${esc(cs.season_name)} · ${cs.points} pts` : ""}</div></div></div>
        <div class="tiles4">${tile("Games", p.games_played)}${tile("Wins", p.first_places)}${tile("Knockouts", p.knockouts)}${tile("Avg Finish", p.avg_finish ?? "–")}</div>
        <div class="tiles4">${tile("ITM Finishes", p.itm_finishes)}${tile("Current ITM Streak", p.current_itm_streak)}${tile("Longest ITM Streak", p.longest_itm_streak)}${tile("Most KOs in a Game", p.most_knockouts_in_game)}</div>
        ${w ? `<dl class="kv"><dt>Winnings: league</dt><dd>${money(w.official_cents)}</dd><dt>Winnings: casual</dt><dd>${money(w.casual_cents)}</dd>
          ${p.has_historical ? `<dt>Winnings: historical</dt><dd>${money(w.historical_cents)}</dd>` : ""}<dt>Total</dt><dd>${money(w.total_cents)}</dd></dl>` : ""}
        <dl class="kv"><dt>Rebuys</dt><dd>${p.rebuys}</dd></dl>
        ${p.seasons.length ? `<h3>Seasons</h3><div class="scroll"><table><thead><tr><th>Season</th><th class="n">Rank</th><th class="n">Points</th><th class="n">Games</th><th class="n">Wins</th></tr></thead><tbody>${p.seasons.map((s) => `
          <tr><td>${esc(s.season_name)}${s.historical ? ` <span class="badge">historical</span>` : ""}</td><td class="n">${s.rank ? (s.tied ? "T" : "") + s.rank : "–"}</td><td class="n">${s.points}</td><td class="n">${s.games_played}</td><td class="n">${s.wins}</td></tr>`).join("")}</tbody></table></div>` : ""}
        <p class="muted">${esc(p.note)}</p>
      </div>`;
  }

  // The league's all-time records (no pictures on the website).
  function hof() {
    const recs = data.hall_of_fame || [], ord = { 1: "1st", 2: "2nd", 3: "3rd" };
    if (!recs.length) return `<div class="panel"><p class="muted">No records yet.</p></div>`;
    return `<div class="hofgrid">${recs.map((r) => `
      <div class="panel stack" style="gap:6px"><h2 style="margin:0;font-size:20px">${esc(r.title)}</h2>
        <p class="muted" style="margin:0;font-size:13px">${esc(r.note)}</p>
        ${r.leaders.length ? r.leaders.map((x) => `
          <div class="hofrow ${x.rank === 1 ? "first" : ""}" data-p="${x.player_id}">
            <span class="rk">${ord[x.rank] || x.rank}</span>
            <span><b>${esc(x.name)}</b>${x.detail ? `<br><span class="muted" style="font-size:12px">${esc(x.detail)}</span>` : ""}</span>
            <span class="v">${esc(x.display)}${x.display.endsWith("%") ? "" : ` <span class="muted" style="font-size:12px">${esc(r.unit)}</span>`}</span>
          </div>`).join("") : `<p class="muted">No record yet.</p>`}
      </div>`).join("")}</div>`;
  }

  function seasons() {
    const m = data.show_money;
    return data.seasons.map((s) => {
      const leader = s.standings[0];
      const fin = s.final;
      return `<div class="panel stack"><div class="top"><h2 style="margin:0">${esc(s.name)}</h2>
          <span class="badge ${s.status === "closed" ? "" : "ok"}">${s.status === "closed" ? "Closed" : "In progress"}</span></div>
        <p class="muted">${s.games_finalized} of ${s.game_target} league games played${s.closed_at ? ` · closed ${new Date(s.closed_at).toLocaleDateString()}` : ""}.</p>
        ${fin ? `<h3>Final places</h3><div class="scroll"><table><thead><tr><th>Place</th><th>Player</th>${m ? `<th class="n">Season payout</th>` : ""}</tr></thead><tbody>${fin.places.map((x) => `
          <tr data-p="${x.player_id}"><td>${x.place === 1 ? "🏆 " : ""}${x.place}</td><td><b>${esc(x.display_name)}</b></td>${m ? `<td class="n">${x.payout_cents ? money(x.payout_cents) : "–"}</td>` : ""}</tr>`).join("")}</tbody></table></div>
          ${m && fin.pool_cents != null ? `<p>Season pool: <b class="gold">${money(fin.pool_cents)}</b></p>` : ""}`
        : leader && leader.points ? `<p>Leading: <b class="gold">${esc(s.standings.filter((r) => r.rank === 1).map((r) => r.display_name).join(", "))}</b> with ${leader.points} points.</p>` : `<p class="muted">No games yet.</p>`}
      </div>`;
    }).join("") || `<div class="panel"><p class="muted">No seasons yet.</p></div>`;
  }

  // Redraw the race chart at the new width when a phone is turned.
  let resized;
  window.addEventListener("resize", () => {
    clearTimeout(resized);
    resized = setTimeout(() => { if (data && view.tab === "race" && view.player == null) render(); }, 250);
  });

  start();
})();
