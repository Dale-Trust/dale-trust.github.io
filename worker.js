// Dale Trust — Join Worker v4
// Endpoints:
//   POST /            join application (public)
//   POST /webhook     SumUp payment notification → auto-activation (verified via API)
//   GET  /pending     admin: open applications        (requires ?key=ADMIN_KEY)
//   POST /activate    admin: manual activation        {app_ref} (requires ?key=)
//   POST /import      admin: bulk member import       [rows]    (requires ?key=)
//   GET  /health      status
//
// BINDINGS:  D1 → DB → daletrust-members
// VARIABLES: LINK_750 LINK_1000 LINK_1250 LINK_1750   (fallback payment links)
// SECRETS:   ADMIN_KEY            (long random string — vault it; protects admin endpoints)
//            RESEND_KEY           (email; optional until set)
//            TURNSTILE_SECRET     (optional until set)
//            SUMUP_KEY            (secret API key — enables checkout automation when set)
//            SUMUP_MERCHANT       (merchant code, with SUMUP_KEY)

const DEFAULT_ORIGINS = [
  'https://dale-trust.github.io',
  'https://www.daletrust.co.uk', 'https://daletrust.co.uk',
  'https://daletrust.uk', 'https://www.daletrust.uk',
];

function corsHeaders(origin, env) {
  const allowed = DEFAULT_ORIGINS.concat((env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean));
  return {
    'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : allowed[0],
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Type': 'application/json',
  };
}
const json = (o, s, h) => new Response(JSON.stringify(o), { status: s, headers: h });
const authed = (url, env) => env.ADMIN_KEY && url.searchParams.get('key') === env.ADMIN_KEY;
const authedRead = (url, env) => authed(url, env) || (env.REPORT_KEY && url.searchParams.get('key') === env.REPORT_KEY);
const authedBoard = (url, env) => authedRead(url, env) || (env.BOARD_KEY && url.searchParams.get('key') === env.BOARD_KEY);

// ---------- session auth (magic links) ----------
function randToken() {
  const b = new Uint8Array(32); crypto.getRandomValues(b);
  return [...b].map(x => x.toString(16).padStart(2, '0')).join('');
}
async function audit(env, officer, action, detail) {
  try { await env.DB.prepare('INSERT INTO audit_log (officer, action, detail) VALUES (?1,?2,?3)')
    .bind(officer || 'system', action, detail || null).run(); } catch (e) {}
}
async function sessionOfficer(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const tok = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!tok) return null;
  const s = await env.DB.prepare(
    "SELECT o.* FROM sessions s JOIN officers o ON o.id = s.officer_id WHERE s.token = ?1 AND s.expires_at > datetime('now') AND o.active = 1"
  ).bind(tok).first();
  return s || null;
}

async function nextMemberNo(env) {
  const m = await env.DB.prepare('SELECT COUNT(*) AS n FROM members WHERE member_no IS NOT NULL').first();
  return 'DT-2026-' + String(1000 + m.n + 1);
}

async function activate(env, app_ref, payment_ref) {
  const row = await env.DB.prepare('SELECT * FROM members WHERE app_ref=?1').bind(app_ref).first();
  if (!row) return { ok: false, error: 'Unknown reference ' + app_ref };
  if (row.member_no) return { ok: true, member_no: row.member_no, already: true };
  const member_no = await nextMemberNo(env);
  await env.DB.prepare(
    "UPDATE members SET member_no=?1, payment_status='paid', payment_ref=?2, activated_at=?3 WHERE app_ref=?4"
  ).bind(member_no, payment_ref || null, new Date().toISOString(), app_ref).run();
  if (env.RESEND_KEY) await sendWelcome(env, row, member_no);
  return { ok: true, member_no };
}

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '';
    const h = corsHeaders(origin, env);
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: h });

    try {

    // ---------- auth: request a magic link ----------
    if (request.method === 'POST' && url.pathname === '/auth/request') {
      const b = await request.json().catch(() => ({}));
      const email = String(b.email || '').trim().toLowerCase();
      if (!email) return json({ ok: false, error: 'Email required' }, 400, h);
      let off = await env.DB.prepare('SELECT * FROM officers WHERE email = ?1 AND active = 1').bind(email).first();
      // bootstrap: first-ever officer enrols as admin using the admin key
      if (!off) {
        const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM officers').first();
        if (n.n === 0 && b.setup_key && env.ADMIN_KEY && b.setup_key === env.ADMIN_KEY) {
          await env.DB.prepare("INSERT INTO officers (email, name, role_title, is_admin, can_members, can_posts, can_board) VALUES (?1, ?2, 'Digital Officer', 1, 1, 1, 1)")
            .bind(email, b.name || 'Admin').run();
          off = await env.DB.prepare('SELECT * FROM officers WHERE email = ?1').bind(email).first();
        }
      }
      // always claim success (no account enumeration); only send if officer exists
      if (off && env.RESEND_KEY) {
        const tok = randToken();
        await env.DB.prepare("INSERT INTO login_tokens (token, email, expires_at) VALUES (?1, ?2, datetime('now', '+15 minutes'))").bind(tok, email).run();
        const link = 'https://daletrust.uk/admin.html#login=' + tok;
        await sendEmail(env, email, 'Your Dale Trust sign-in link',
          '<p>Hi ' + off.name.split(' ')[0] + ',</p>' +
          '<p>Tap below to sign in to the Dale Trust admin. The link works once and expires in 15 minutes.</p>' +
          '<p style="margin:18px 0"><a href="' + link + '" style="background:#0057A7;color:#fff;text-decoration:none;font-weight:700;padding:14px 26px;border-radius:9px;display:inline-block">Sign in to Dale Trust admin</a></p>' +
          '<p style="color:#666;font-size:13px">Didn\u2019t request this? You can safely ignore it.</p>');
      }
      return json({ ok: true, sent: true }, 200, h);
    }

    // ---------- auth: exchange login token for a session ----------
    if (request.method === 'POST' && url.pathname === '/auth/verify') {
      const b = await request.json().catch(() => ({}));
      const lt = await env.DB.prepare("SELECT * FROM login_tokens WHERE token = ?1 AND used = 0 AND expires_at > datetime('now')").bind(String(b.token || '')).first();
      if (!lt) return json({ ok: false, error: 'Link expired or already used \u2014 request a fresh one' }, 400, h);
      const off = await env.DB.prepare('SELECT * FROM officers WHERE email = ?1 AND active = 1').bind(lt.email).first();
      if (!off) return json({ ok: false, error: 'No active officer for this link' }, 400, h);
      await env.DB.prepare('UPDATE login_tokens SET used = 1 WHERE token = ?1').bind(lt.token).run();
      const st = randToken();
      await env.DB.prepare("INSERT INTO sessions (token, officer_id, expires_at) VALUES (?1, ?2, datetime('now', '+30 days'))").bind(st, off.id).run();
      return json({ ok: true, session: st, officer: { name: off.name, email: off.email, role_title: off.role_title, is_admin: !!off.is_admin, can_members: !!off.can_members, can_posts: !!off.can_posts, can_board: !!off.can_board } }, 200, h);
    }

    // ---------- auth: who am I ----------
    if (request.method === 'GET' && url.pathname === '/auth/me') {
      const off = await sessionOfficer(request, env);
      if (!off) return json({ ok: false }, 401, h);
      return json({ ok: true, officer: { name: off.name, email: off.email, role_title: off.role_title, is_admin: !!off.is_admin, can_members: !!off.can_members, can_posts: !!off.can_posts, can_board: !!off.can_board } }, 200, h);
    }

    // ---------- auth: officer management (admins only) ----------
    if (url.pathname === '/auth/officers') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.is_admin) return json({ ok: false, error: 'Admins only' }, 403, h);
      if (request.method === 'GET') {
        const rows = await env.DB.prepare('SELECT id, email, name, role_title, is_admin, can_members, can_posts, can_board, active FROM officers ORDER BY name').all();
        return json({ ok: true, officers: rows.results }, 200, h);
      }
      if (request.method === 'POST') {
        const b = await request.json();
        if (b.remove_id) {
          if (b.remove_id === me.id) return json({ ok: false, error: 'You cannot deactivate yourself' }, 400, h);
          await env.DB.prepare('UPDATE officers SET active = 0 WHERE id = ?1').bind(b.remove_id).run();
          return json({ ok: true }, 200, h);
        }
        if (b.update_id) {
          await env.DB.prepare('UPDATE officers SET is_admin=?1, can_members=?2, can_posts=?3, can_board=?4, active=1 WHERE id=?5')
            .bind(b.is_admin ? 1 : 0, b.can_members ? 1 : 0, b.can_posts ? 1 : 0, b.can_board ? 1 : 0, b.update_id).run();
          return json({ ok: true }, 200, h);
        }
        const email = String(b.email || '').trim().toLowerCase();
        if (!email || !b.name) return json({ ok: false, error: 'Name and email required' }, 400, h);
        await env.DB.prepare('INSERT INTO officers (email, name, role_title, is_admin, can_members, can_posts, can_board) VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(email) DO UPDATE SET active=1, name=?2, role_title=?3')
          .bind(email, b.name, b.role_title || null, b.is_admin ? 1 : 0, b.can_members ? 1 : 0, b.can_posts ? 1 : 0, b.can_board ? 1 : 0).run();
        return json({ ok: true }, 200, h);
      }
    }

    // ---------- public: published posts (for the website) ----------
    if (request.method === 'GET' && url.pathname === '/posts') {
      const slug = url.searchParams.get('slug');
      if (slug) {
        const p = await env.DB.prepare("SELECT slug,title,category,author,body,summary,publish_at FROM posts WHERE slug=?1 AND status='published' AND publish_at<=datetime('now')").bind(slug).first();
        return p ? json({ ok: true, post: p }, 200, h) : json({ ok: false, error: 'Not found' }, 404, h);
      }
      const rows = await env.DB.prepare("SELECT slug,title,category,author,summary,body,publish_at FROM posts WHERE status='published' AND publish_at<=datetime('now') ORDER BY publish_at DESC LIMIT 40").all();
      const posts = rows.results.map(p => {
        const m = String(p.body || '').match(/https?:\/\/[^\s"'<)]+\.(?:jpg|jpeg|png|webp)/i);
        const { body, ...rest } = p;
        return { ...rest, image: m ? m[0] : null };
      });
      return json({ ok: true, posts }, 200, h);
    }

    // ---------- officer: list all posts (any status) ----------
    if (request.method === 'GET' && url.pathname === '/posts/all') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.can_posts) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      const q = (url.searchParams.get('q') || '').trim();
      const status = url.searchParams.get('status') || '';
      const limit = Math.min(100, parseInt(url.searchParams.get('limit') || '25', 10));
      const offset = parseInt(url.searchParams.get('offset') || '0', 10);
      const where = [], binds = [];
      if (q) { where.push('(title LIKE ?' + (binds.length+1) + ' OR body LIKE ?' + (binds.length+1) + ')'); binds.push('%' + q + '%'); }
      if (status) { where.push('status = ?' + (binds.length+1)); binds.push(status); }
      const clause = where.length ? ' WHERE ' + where.join(' AND ') : '';
      const cnt = await env.DB.prepare('SELECT COUNT(*) AS n FROM posts' + clause).bind(...binds).first();
      const rows = await env.DB.prepare(
        'SELECT id,slug,title,category,author,status,publish_at,emailed_at,summary FROM posts' + clause +
        ' ORDER BY COALESCE(publish_at, created_at) DESC LIMIT ' + limit + ' OFFSET ' + offset).bind(...binds).all();
      return json({ ok: true, total: cnt.n, limit, offset, posts: rows.results }, 200, h);
    }

    // single post for editing (any status)
    if (request.method === 'GET' && url.pathname === '/posts/one') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.can_posts) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      const p = await env.DB.prepare('SELECT * FROM posts WHERE id=?1').bind(url.searchParams.get('id')).first();
      return p ? json({ ok: true, post: p }, 200, h) : json({ ok: false, error: 'Not found' }, 404, h);
    }

    // ---------- officer: save / publish / schedule a post ----------
    if (request.method === 'POST' && url.pathname === '/posts/save') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.can_posts) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      const b = await request.json();
      if (!b.title || !b.body) return json({ ok: false, error: 'Title and words are required' }, 400, h);
      const base = String(b.title).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
      const status = ['scheduled','published','draft','archived'].includes(b.status) ? b.status : 'draft';
      const publish_at = b.publish_at || new Date().toISOString();
      const summary = String(b.body).replace(/[#*]/g, '').split('\n').filter(Boolean)[0] || '';
      if (b.id) {
        await env.DB.prepare("UPDATE posts SET title=?1,category=?2,body=?3,summary=?4,status=?5,publish_at=?6,updated_at=datetime('now') WHERE id=?7")
          .bind(b.title, b.category || 'Trust News', b.body, summary.slice(0, 220), status, publish_at, b.id).run();
        await audit(env, me.email, 'post.update', b.title);
        return json({ ok: true, id: b.id, slug: b.slug }, 200, h);
      }
      let slug = base, n = 1;
      while (await env.DB.prepare('SELECT 1 FROM posts WHERE slug=?1').bind(slug).first()) slug = base + '-' + (++n);
      const r = await env.DB.prepare('INSERT INTO posts (slug,title,category,author,body,summary,status,publish_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)')
        .bind(slug, b.title, b.category || 'Trust News', me.name, b.body, summary.slice(0, 220), status, publish_at).run();
      await audit(env, me.email, 'post.create', b.title);
      return json({ ok: true, id: r.meta.last_row_id, slug }, 200, h);
    }

    // ---------- officer: bulk import posts (from the old WordPress site) ----------
    if (request.method === 'POST' && url.pathname === '/posts/import') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.can_posts) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      const rows = await request.json();
      if (!Array.isArray(rows)) return json({ ok: false, error: 'Expected an array' }, 400, h);
      let imported = 0, skipped = 0;
      for (const r of rows) {
        try {
          if (!r.title || !r.body) { skipped++; continue; }
          const base = String(r.slug || r.title).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60) || 'post';
          const exists = await env.DB.prepare('SELECT 1 FROM posts WHERE slug=?1').bind(base).first();
          if (exists) { skipped++; continue; }
          const summary = String(r.body).replace(/[#*]/g, '').split('\n').filter(Boolean)[0] || '';
          await env.DB.prepare("INSERT INTO posts (slug,title,category,author,body,summary,status,publish_at,emailed_at) VALUES (?1,?2,?3,?4,?5,?6,'published',?7,?8)")
            .bind(base, r.title, r.category || 'Trust News', r.author || 'Dale Trust', r.body,
                  summary.slice(0, 220), r.publish_at || new Date().toISOString(), r.publish_at || null).run();
          imported++;
        } catch (e) { skipped++; }
      }
      await audit(env, me.email, 'posts.import', 'imported ' + imported + ', skipped ' + skipped);
      return json({ ok: true, imported, skipped }, 200, h);
    }

    // ---------- officer: archive a post (never deleted) ----------
    if (request.method === 'POST' && url.pathname === '/posts/archive') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.can_posts) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      const b = await request.json();
      await env.DB.prepare("UPDATE posts SET status='archived', updated_at=datetime('now') WHERE id=?1").bind(b.id).run();
      await audit(env, me.email, 'post.archive', 'post ' + b.id);
      return json({ ok: true }, 200, h);
    }

    // ---------- officer: audience counts ----------
    if (request.method === 'GET' && url.pathname === '/audience') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.can_posts) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      const members = await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE season='2026/27' AND payment_status<>'cancelled' AND newsletter_optin=1 AND email<>'none@daletrust.uk'").first();
      const lapsed = await env.DB.prepare(`SELECT COUNT(*) AS n FROM members a WHERE a.season='2025/26' AND a.payment_status<>'cancelled' AND a.email<>'none@daletrust.uk'
        AND NOT EXISTS (SELECT 1 FROM members b WHERE b.season='2026/27' AND lower(b.first_name)=lower(a.first_name) AND lower(b.last_name)=lower(a.last_name) AND b.postcode=a.postcode)`).first();
      return json({ ok: true, members: members.n, lapsed: lapsed.n }, 200, h);
    }

    // ---------- officer: send a mailshot (short email → traffic to the site) ----------
    if (request.method === 'POST' && url.pathname === '/mailshot') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.can_posts) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      if (!env.RESEND_KEY) return json({ ok: false, error: 'Email sending is not configured' }, 400, h);
      const b = await request.json();
      const post = await env.DB.prepare('SELECT * FROM posts WHERE id=?1').bind(b.post_id).first();
      if (!post) return json({ ok: false, error: 'Post not found' }, 400, h);
      const segment = b.segment === 'lapsed' ? 'lapsed' : 'members';
      const rows = segment === 'members'
        ? await env.DB.prepare("SELECT first_name, email FROM members WHERE season='2026/27' AND payment_status<>'cancelled' AND newsletter_optin=1 AND email<>'none@daletrust.uk'").all()
        : await env.DB.prepare(`SELECT a.first_name, a.email FROM members a WHERE a.season='2025/26' AND a.payment_status<>'cancelled' AND a.email<>'none@daletrust.uk'
            AND NOT EXISTS (SELECT 1 FROM members b WHERE b.season='2026/27' AND lower(b.first_name)=lower(a.first_name) AND lower(b.last_name)=lower(a.last_name) AND b.postcode=a.postcode)`).all();
      const seen = new Set(); const list = [];
      for (const r of rows.results) { const e = (r.email || '').toLowerCase(); if (e && !seen.has(e)) { seen.add(e); list.push(r); } }
      if (b.test_to) { list.length = 0; list.push({ first_name: 'there', email: b.test_to }); }
      const readUrl = 'https://daletrust.uk/news.html?p=' + post.slug;
      let sent = 0;
      for (const r of list) {
        const inner = '<p>Hi ' + (r.first_name || 'there') + ',</p>' +
          '<h2 style="font-family:Arial;color:#0E1F3D;font-size:20px;margin:14px 0 8px">' + post.title + '</h2>' +
          '<p>' + (post.summary || '') + '</p>' +
          '<p style="margin:20px 0"><a href="' + readUrl + '" style="background:#0057A7;color:#fff;text-decoration:none;font-weight:700;padding:14px 26px;border-radius:9px;display:inline-block">Read it on the Trust website</a></p>' +
          (segment === 'lapsed' ? '<p style="color:#666;font-size:13px">You\u2019re receiving this because you were a Dale Trust member last season. Reply with \u201cstop\u201d and we won\u2019t contact you again.</p>' : '') +
          '<p>Up the Dale!<br><strong>The Dale Trust</strong></p>';
        try { await sendEmail(env, r.email, post.title, inner); sent++; } catch (e) {}
      }
      if (!b.test_to) {
        await env.DB.prepare("UPDATE posts SET emailed_at=datetime('now') WHERE id=?1").bind(post.id).run();
        await env.DB.prepare('INSERT INTO mailshots (post_id, segment, subject, recipients, sent_by) VALUES (?1,?2,?3,?4,?5)')
          .bind(post.id, segment, post.title, sent, me.email).run();
        await audit(env, me.email, 'mailshot.send', segment + ' \u00d7' + sent + ' \u2014 ' + post.title);
      }
      return json({ ok: true, sent, test: !!b.test_to }, 200, h);
    }

    // ---------- admin: retention (anonymise old seasons, keep the statistics) ----------
    if (url.pathname === '/retention') {
      const me = await sessionOfficer(request, env);
      if (!me || !me.is_admin) return json({ ok: false, error: 'Admins only' }, 403, h);

      // what would be affected? (default: anything not in the current season, older than 12 months)
      if (request.method === 'GET') {
        const before = url.searchParams.get('before') || new Date(Date.now() - 365 * 864e5).toISOString().slice(0, 10);
        const rows = await env.DB.prepare(
          `SELECT season, COUNT(*) AS total,
                  SUM(CASE WHEN anonymised_at IS NULL THEN 1 ELSE 0 END) AS still_personal
           FROM members WHERE season <> '2026/27' AND date(COALESCE(activated_at, created_at)) < date(?1)
           GROUP BY season ORDER BY season`).bind(before).all();
        return json({ ok: true, before, seasons: rows.results }, 200, h);
      }

      // do it: snapshot the numbers first, then strip the personal fields
      if (request.method === 'POST') {
        const b = await request.json().catch(() => ({}));
        const before = b.before || new Date(Date.now() - 365 * 864e5).toISOString().slice(0, 10);
        if (b.confirm !== 'ANONYMISE') return json({ ok: false, error: 'Confirmation phrase required' }, 400, h);

        await env.DB.prepare(
          `INSERT OR REPLACE INTO season_stats (season, membership_type, gender, members, snapshot_at)
           SELECT season, membership_type, COALESCE(gender,'Unknown'), COUNT(*), datetime('now')
           FROM members GROUP BY season, membership_type, COALESCE(gender,'Unknown')`).run();

        const res = await env.DB.prepare(
          `UPDATE members SET
             first_name='(removed)', last_name='(removed)', email='removed@daletrust.uk',
             mobile=NULL, home_tel=NULL, address1='(removed)', address2=NULL,
             postcode=substr(COALESCE(postcode,''),1,4), dob=NULL,
             comments=NULL, misc=NULL, payment_ref=NULL,
             anonymised_at=datetime('now')
           WHERE season <> '2026/27' AND anonymised_at IS NULL
             AND date(COALESCE(activated_at, created_at)) < date(?1)`).bind(before).run();

        await audit(env, me.email, 'retention.anonymise', 'before ' + before + ', rows ' + res.meta.changes);
        return json({ ok: true, anonymised: res.meta.changes, before }, 200, h);
      }
    }

    // ---------- board/officer: year-on-year figures (survives anonymisation) ----------
    if (request.method === 'GET' && url.pathname === '/history') {
      const so = await sessionOfficer(request, env);
      if (!authedBoard(url, env) && !(so && so.can_board)) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const live = await env.DB.prepare(
        "SELECT season, membership_type, COUNT(*) AS n FROM members WHERE payment_status<>'cancelled' GROUP BY season, membership_type").all();
      const snap = await env.DB.prepare('SELECT season, membership_type, SUM(members) AS n FROM season_stats GROUP BY season, membership_type').all();
      return json({ ok: true, live: live.results, snapshots: snap.results }, 200, h);
    }

    // ---------- official season history (the Membership Analysis table) ----------
    if (url.pathname === '/official') {
      if (request.method === 'GET') {
        const rows = await env.DB.prepare('SELECT * FROM official_history ORDER BY season').all();
        return json({ ok: true, history: rows.results }, 200, h);
      }
      if (request.method === 'POST') {
        const me = await sessionOfficer(request, env);
        if (!me || !me.can_members) return json({ ok: false, error: 'Unauthorised' }, 403, h);
        const rows = await request.json();
        if (!Array.isArray(rows)) return json({ ok: false, error: 'Expected an array' }, 400, h);
        let saved = 0;
        for (const r of rows) {
          if (!r.season) continue;
          await env.DB.prepare(`INSERT INTO official_history (season, adult, exile, junior, other, total, avg_attendance, pct, updated_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,datetime('now'))
            ON CONFLICT(season) DO UPDATE SET adult=?2, exile=?3, junior=?4, other=?5, total=?6, avg_attendance=?7, pct=?8, updated_at=datetime('now')`)
            .bind(r.season, r.adult|0, r.exile|0, r.junior|0, r.other|0, r.total|0,
                  r.avg_attendance ? Math.round(r.avg_attendance) : null,
                  r.pct != null ? Number(r.pct) : null).run();
          saved++;
        }
        await audit(env, me.email, 'official.import', saved + ' seasons');
        return json({ ok: true, saved }, 200, h);
      }
    }

    // ---------- decisions & tasks board ----------
    if (request.method === 'GET' && url.pathname === '/tasks') {
      const me = await sessionOfficer(request, env);
      const keyed = env.TASKS_KEY && url.searchParams.get('key') === env.TASKS_KEY;
      if (!me && !keyed) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const rows = await env.DB.prepare('SELECT * FROM tasks ORDER BY sort_order').all();
      const reps = await env.DB.prepare('SELECT * FROM task_responses ORDER BY at').all();
      const byTask = {};
      reps.results.forEach(r => { (byTask[r.task_id] = byTask[r.task_id] || []).push(r); });
      const tasks = rows.results.map(t => ({ ...t, responses: byTask[t.id] || [] }));
      return json({ ok: true, tasks, me: me ? { name: me.name, email: me.email, is_admin: !!me.is_admin } : null }, 200, h);
    }

    if (request.method === 'POST' && url.pathname === '/tasks/respond') {
      const me = await sessionOfficer(request, env);
      const keyed = env.TASKS_KEY && url.searchParams.get('key') === env.TASKS_KEY;
      if (!me && !keyed) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const b = await request.json();
      if (!b.task_id || !String(b.body || '').trim()) return json({ ok: false, error: 'Nothing to save' }, 400, h);
      const t = await env.DB.prepare('SELECT status FROM tasks WHERE id=?1').bind(b.task_id).first();
      if (t && t.status !== 'open') {
        return json({ ok: false, error: 'This one already has an answer \u2014 reopen it first if it needs revisiting' }, 400, h);
      }
      const who = me ? me.name : String(b.author || 'Unknown').slice(0, 60);
      await env.DB.prepare('INSERT INTO task_responses (task_id, author, body) VALUES (?1,?2,?3)')
        .bind(b.task_id, who, String(b.body).trim()).run();
      const cur = await env.DB.prepare('SELECT status FROM tasks WHERE id=?1').bind(b.task_id).first();
      if (cur && cur.status === 'open') {
        await env.DB.prepare("UPDATE tasks SET status='answered', updated_at=datetime('now') WHERE id=?1").bind(b.task_id).run();
      }
      await audit(env, me ? me.email : 'page:' + (b.author || '?'), 'task.respond', 'task ' + b.task_id);
      return json({ ok: true }, 200, h);
    }

    if (request.method === 'POST' && url.pathname === '/tasks/status') {
      const me = await sessionOfficer(request, env);
      const keyed = env.TASKS_KEY && url.searchParams.get('key') === env.TASKS_KEY;
      if (!(me && me.is_admin) && !keyed) return json({ ok: false, error: 'Unauthorised' }, 403, h);
      const b = await request.json();
      if (!['open','answered','confirmed','live','parked'].includes(b.status)) return json({ ok: false, error: 'Bad status' }, 400, h);
      await env.DB.prepare("UPDATE tasks SET status=?1, updated_at=datetime('now') WHERE id=?2").bind(b.status, b.task_id).run();
      await audit(env, me ? me.email : 'page:' + (b.author || '?'), 'task.status', 'task ' + b.task_id + ' -> ' + b.status);
      return json({ ok: true }, 200, h);
    }

    // ================= MEMBERS' AREA =================
    // Season handling: CURRENT_SEASON variable, defaults to 2026/27
    const CURRENT = env.CURRENT_SEASON || '2026/27';

    // ---- member: request a sign-in link ----
    if (request.method === 'POST' && url.pathname === '/member/request') {
      const b = await request.json().catch(() => ({}));
      const email = String(b.email || '').trim().toLowerCase();
      if (!email) return json({ ok: false, error: 'Email required' }, 400, h);
      const row = await env.DB.prepare(
        "SELECT first_name FROM members WHERE lower(email)=?1 AND email<>'none@daletrust.uk' ORDER BY season DESC LIMIT 1"
      ).bind(email).first();
      if (row && env.RESEND_KEY) {
        const tok = randToken();
        await env.DB.prepare("INSERT INTO member_tokens (token, email, expires_at) VALUES (?1,?2,datetime('now','+30 minutes'))").bind(tok, email).run();
        const link = 'https://daletrust.uk/members.html#in=' + tok;
        await sendEmail(env, email, 'Your Dale Trust sign-in link',
          '<p>Hi ' + row.first_name + ',</p>' +
          '<p>Tap below to open your Dale Trust membership. The link works once and lasts 30 minutes.</p>' +
          '<p style="margin:18px 0"><a href="' + link + '" style="background:#0057A7;color:#fff;text-decoration:none;font-weight:700;padding:14px 26px;border-radius:9px;display:inline-block">Open my membership</a></p>' +
          '<p style="color:#666;font-size:13px">Didn\u2019t ask for this? You can ignore it.</p>' +
          '<p>Up the Dale!<br><strong>The Dale Trust</strong></p>');
      }
      return json({ ok: true, sent: true }, 200, h);   // never reveal whether the address is known
    }

    // ---- member: exchange link for a session ----
    if (request.method === 'POST' && url.pathname === '/member/verify') {
      const b = await request.json().catch(() => ({}));
      const t = await env.DB.prepare("SELECT * FROM member_tokens WHERE token=?1 AND used=0 AND expires_at>datetime('now')").bind(String(b.token || '')).first();
      if (!t) return json({ ok: false, error: 'That link has expired or been used \u2014 please ask for a new one' }, 400, h);
      await env.DB.prepare('UPDATE member_tokens SET used=1 WHERE token=?1').bind(t.token).run();
      const st = randToken();
      await env.DB.prepare("INSERT INTO member_sessions (token, email, expires_at) VALUES (?1,?2,datetime('now','+90 days'))").bind(st, t.email).run();
      return json({ ok: true, session: st }, 200, h);
    }

    // ---- member: my record ----
    async function memberFromSession(req) {
      const auth = req.headers.get('Authorization') || '';
      const tok = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      if (!tok) return null;
      const s = await env.DB.prepare("SELECT email FROM member_sessions WHERE token=?1 AND expires_at>datetime('now')").bind(tok).first();
      if (!s) return null;
      const rows = await env.DB.prepare(
        "SELECT * FROM members WHERE lower(email)=?1 ORDER BY season DESC, id DESC"
      ).bind(s.email).all();
      return rows.results.length ? { email: s.email, records: rows.results } : null;
    }

    if (request.method === 'GET' && url.pathname === '/member/me') {
      const m = await memberFromSession(request);
      if (!m) return json({ ok: false }, 401, h);
      const strip = r => r && ({
        id: r.id, app_ref: r.app_ref, member_no: r.member_no, season: r.season, membership_type: r.membership_type,
        first_name: r.first_name, last_name: r.last_name, dob: r.dob, email: r.email, mobile: r.mobile,
        address1: r.address1, address2: r.address2, town: r.town, county: r.county, postcode: r.postcode,
        country: r.country, newsletter_optin: r.newsletter_optin, exile_transport_share: r.exile_transport_share,
        payment_status: r.payment_status, details_confirmed_at: r.details_confirmed_at, activated_at: r.activated_at
      });
      // one email can cover a household — group the records by person
      const byPerson = {};
      m.records.forEach(r => {
        const key = (r.first_name + '|' + r.last_name).toLowerCase().trim();
        (byPerson[key] = byPerson[key] || []).push(r);
      });
      const people = Object.values(byPerson).map(recs => {
        const current = recs.find(r => r.season === CURRENT && r.payment_status !== 'cancelled');
        const seasons = [...new Set(recs.map(r => r.season))].sort();
        return {
          name: (recs[0].first_name + ' ' + recs[0].last_name).trim(),
          isMember: !!current,
          record: strip(current || recs[0]),
          seasons,
          since: seasons[0]
        };
      }).sort((a, b) => (b.isMember ? 1 : 0) - (a.isMember ? 1 : 0));
      return json({ ok: true, season: CURRENT, people }, 200, h);
    }

    // ---- member: save corrected details ----
    if (request.method === 'POST' && url.pathname === '/member/update') {
      const m = await memberFromSession(request);
      if (!m) return json({ ok: false, error: 'Please sign in again' }, 401, h);
      const b = await request.json();
      const target = (b.record_id && m.records.find(r => r.id === b.record_id)) ||
                     m.records.find(r => r.season === CURRENT) || m.records[0];
      await env.DB.prepare(`UPDATE members SET
          first_name=?1, last_name=?2, dob=?3, mobile=?4, address1=?5, address2=?6,
          town=?7, county=?8, postcode=?9, country=?10, newsletter_optin=?11,
          exile_transport_share=?12, details_confirmed_at=datetime('now')
        WHERE id=?13`)
        .bind(
          String(b.first_name || target.first_name).trim(), String(b.last_name || target.last_name).trim(),
          b.dob || null, b.mobile || null,
          String(b.address1 || target.address1).trim(), b.address2 || null,
          String(b.town || target.town).trim(), b.county || null,
          String(b.postcode || target.postcode).trim().toUpperCase(), b.country || null,
          b.newsletter_optin ? 1 : 0,
          target.membership_type === 'Exile' ? (b.exile_transport_share || 'No') : null,
          target.id
        ).run();
      return json({ ok: true }, 200, h);
    }

    // ---- member: renew / rejoin for the current season ----
    if (request.method === 'POST' && url.pathname === '/member/renew') {
      const m = await memberFromSession(request);
      if (!m) return json({ ok: false, error: 'Please sign in again' }, 401, h);
      const b = await request.json().catch(() => ({}));
      const prev = (b.record_id && m.records.find(r => r.id === b.record_id)) || m.records[0];
      const already = m.records.find(r => r.season === CURRENT && r.payment_status !== 'cancelled'
        && r.first_name.toLowerCase() === prev.first_name.toLowerCase()
        && r.last_name.toLowerCase() === prev.last_name.toLowerCase());
      if (already) return json({ ok: false, error: prev.first_name + ' is already a member for ' + CURRENT }, 400, h);
      const donation = Math.max(0, Number(b.donation) || 0);
      const type = ['Adult','Exile','Junior'].includes(b.membership_type) ? b.membership_type : prev.membership_type;
      const base = type === 'Junior' ? 0 : 7.5;
      const total = base + donation;
      const status = total > 0 ? 'pending' : 'free';

      const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM members').first();
      const app_ref = 'REF-' + String(1000 + c.n + 1);
      let member_no = null, activated_at = null;
      if (status === 'free') { member_no = await nextMemberNo(env); activated_at = new Date().toISOString(); }

      await env.DB.prepare(`INSERT INTO members
        (app_ref, member_no, season, membership_type, new_or_renewal, first_name, last_name, gender, dob,
         email, mobile, home_tel, address1, address2, town, county, postcode, country,
         exile_transport_share, newsletter_optin, auto_renew_pref, gdpr_consent_at,
         donation, amount_due, payment_status, activated_at, details_confirmed_at, joined_via)
        VALUES (?1,?2,?3,?4,'Rpt',?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,0,?20,?21,?22,?23,?24,datetime('now'),'renewal')`)
        .bind(app_ref, member_no, CURRENT, type,
          b.first_name || prev.first_name, b.last_name || prev.last_name, prev.gender, b.dob || prev.dob,
          m.email, b.mobile || prev.mobile, prev.home_tel,
          b.address1 || prev.address1, b.address2 || prev.address2, b.town || prev.town,
          b.county || prev.county, (b.postcode || prev.postcode || '').toUpperCase(), b.country || prev.country,
          type === 'Exile' ? (b.exile_transport_share || 'No') : null,
          b.newsletter_optin ? 1 : 0, new Date().toISOString(),
          donation, total, status, activated_at).run();

      let pay_url = null;
      if (total > 0) {
        if (env.SUMUP_KEY && env.SUMUP_MERCHANT) {
          const chk = await fetch('https://api.sumup.com/v0.1/checkouts', {
            method: 'POST',
            headers: { Authorization: 'Bearer ' + env.SUMUP_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ checkout_reference: app_ref, amount: total, currency: 'GBP',
              merchant_code: env.SUMUP_MERCHANT, description: 'Dale Trust membership ' + CURRENT + ' (' + app_ref + ')',
              return_url: 'https://join.daletrust.uk/webhook', hosted_checkout: { enabled: true } })
          }).then(r => r.json()).catch(() => null);
          pay_url = chk && (chk.hosted_checkout_url || (chk.hosted_checkout && chk.hosted_checkout.url)) || null;
        }
        if (!pay_url) {
          const links = { 7.5: env.LINK_750, 10: env.LINK_1000, 12.5: env.LINK_1250, 17.5: env.LINK_1750 };
          pay_url = links[total] || env.LINK_750;
        }
      }
      await audit(env, m.email, 'member.renew', app_ref + ' ' + CURRENT + ' \u00a3' + total);
      return json({ ok: true, app_ref, member_no, amount: total, pay_url }, 200, h);
    }

    // ================= COACH TRAVEL =================
    async function tripWithSeats(t) {
      const b = await env.DB.prepare(
        "SELECT COALESCE(SUM(seats),0) AS taken FROM coach_bookings WHERE trip_id=?1 AND payment_status<>'cancelled'"
      ).bind(t.id).first();
      return { ...t, taken: b.taken, remaining: Math.max(0, t.seats - b.taken) };
    }

    // ---- public: open trips ----
    if (request.method === 'GET' && url.pathname === '/coach/trips') {
      const rows = await env.DB.prepare(
        "SELECT * FROM coach_trips WHERE status='open' AND date(match_date) >= date('now','-1 day') ORDER BY match_date"
      ).all();
      const trips = [];
      for (const t of rows.results) trips.push(await tripWithSeats(t));
      return json({ ok: true, trips }, 200, h);
    }

    // ---- public: book a seat ----
    if (request.method === 'POST' && url.pathname === '/coach/book') {
      const b = await request.json().catch(() => ({}));
      const trip = await env.DB.prepare("SELECT * FROM coach_trips WHERE id=?1 AND status='open'").bind(b.trip_id).first();
      if (!trip) return json({ ok: false, error: 'That coach is not open for booking' }, 400, h);
      const name = String(b.name || '').trim(), mobile = String(b.mobile || '').trim();
      const email = String(b.email || '').trim().toLowerCase();
      if (!name || !mobile) return json({ ok: false, error: 'Name and mobile number are needed' }, 400, h);
      const seats = Math.max(1, Math.min(10, parseInt(b.seats, 10) || 1));
      const withSeats = await tripWithSeats(trip);
      if (seats > withSeats.remaining) return json({ ok: false, error: 'Only ' + withSeats.remaining + ' seat(s) left on that coach' }, 400, h);

      if (env.TURNSTILE_SECRET && !b.member_no) {
        const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
          method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: b.turnstile_token || '' }),
        }).then(x => x.json());
        if (!r.success) return json({ ok: false, error: 'Human check failed — please try again' }, 400, h);
      }

      const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM coach_bookings').first();
      const booking_ref = 'CT-' + String(1000 + c.n + 1);
      const amount = Math.round(trip.price * seats * 100) / 100;
      await env.DB.prepare(`INSERT INTO coach_bookings (booking_ref, trip_id, name, email, mobile, seats, amount, member_no, payment_status, taken_by)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'pending','online')`)
        .bind(booking_ref, trip.id, name, email || null, mobile, seats, amount, b.member_no || null).run();

      let pay_url = null;
      if (env.SUMUP_KEY && env.SUMUP_MERCHANT) {
        const chk = await fetch('https://api.sumup.com/v0.1/checkouts', {
          method: 'POST', headers: { Authorization: 'Bearer ' + env.SUMUP_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({ checkout_reference: booking_ref, amount, currency: 'GBP',
            merchant_code: env.SUMUP_MERCHANT,
            description: 'Dale Trust coach — ' + trip.opponent + ' (' + booking_ref + ')',
            return_url: 'https://join.daletrust.uk/webhook', hosted_checkout: { enabled: true } })
        }).then(r => r.json()).catch(() => null);
        pay_url = chk && (chk.hosted_checkout_url || (chk.hosted_checkout && chk.hosted_checkout.url)) || null;
      }
      if (env.RESEND_KEY && email) {
        ctx.waitUntil(sendEmail(env, email, 'Your Dale Trust coach booking — ' + trip.opponent,
          '<p>Hi ' + name.split(' ')[0] + ',</p>' +
          '<p>Your seat' + (seats > 1 ? 's are' : ' is') + ' reserved for <strong>' + trip.opponent + '</strong>.</p>' +
          '<p><strong>Booking reference:</strong> ' + booking_ref + '<br>' +
          '<strong>Departs:</strong> ' + trip.depart_time + ' from ' + trip.depart_from + '<br>' +
          '<strong>Seats:</strong> ' + seats + '<br><strong>Total:</strong> \u00a3' + amount.toFixed(2) + '</p>' +
          (pay_url ? '<p style="margin:18px 0"><a href="' + pay_url + '" style="background:#1E8E5A;color:#fff;text-decoration:none;font-weight:700;padding:14px 26px;border-radius:9px;display:inline-block">Pay \u00a3' + amount.toFixed(2) + ' to confirm your seat</a></p>' : '') +
          '<p style="color:#666;font-size:13px">Please arrive ten minutes before departure. Your coach seat does not include a match ticket.</p>' +
          '<p>Up the Dale!<br><strong>The Dale Trust</strong></p>'));
      }
      return json({ ok: true, booking_ref, amount, seats, pay_url }, 200, h);
    }

    // ---- officer: trips with bookings ----
    if (request.method === 'GET' && url.pathname === '/coach/admin') {
      const me = await sessionOfficer(request, env);
      if (!me) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const rows = await env.DB.prepare('SELECT * FROM coach_trips ORDER BY match_date DESC').all();
      const trips = [];
      for (const t of rows.results) trips.push(await tripWithSeats(t));
      const tripId = url.searchParams.get('trip_id');
      let bookings = [];
      if (tripId) {
        const bk = await env.DB.prepare('SELECT * FROM coach_bookings WHERE trip_id=?1 ORDER BY created_at').bind(tripId).all();
        bookings = bk.results;
      }
      return json({ ok: true, trips, bookings, me: { name: me.name } }, 200, h);
    }

    // ---- officer: create or update a trip ----
    if (request.method === 'POST' && url.pathname === '/coach/trip') {
      const me = await sessionOfficer(request, env);
      if (!me) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const b = await request.json();
      if (b.id) {
        await env.DB.prepare(`UPDATE coach_trips SET opponent=?1, venue=?2, match_date=?3, kickoff=?4,
          depart_time=?5, depart_from=?6, price=?7, seats=?8, status=?9, notes=?10 WHERE id=?11`)
          .bind(b.opponent, b.venue || null, b.match_date, b.kickoff || null, b.depart_time,
            b.depart_from || 'Crown Oil Arena', Number(b.price) || 0, parseInt(b.seats, 10) || 49,
            b.status || 'open', b.notes || null, b.id).run();
        await audit(env, me.email, 'coach.trip.update', b.opponent);
        return json({ ok: true, id: b.id }, 200, h);
      }
      if (!b.opponent || !b.match_date || !b.depart_time) return json({ ok: false, error: 'Opponent, date and departure time are needed' }, 400, h);
      const r = await env.DB.prepare(`INSERT INTO coach_trips (opponent, venue, match_date, kickoff, depart_time, depart_from, price, seats, notes)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)`)
        .bind(b.opponent, b.venue || null, b.match_date, b.kickoff || null, b.depart_time,
          b.depart_from || 'Crown Oil Arena', Number(b.price) || 35, parseInt(b.seats, 10) || 49, b.notes || null).run();
      await audit(env, me.email, 'coach.trip.create', b.opponent);
      return json({ ok: true, id: r.meta.last_row_id }, 200, h);
    }

    // ---- officer: add a booking taken by phone or at the desk ----
    if (request.method === 'POST' && url.pathname === '/coach/manual') {
      const me = await sessionOfficer(request, env);
      if (!me) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const b = await request.json();
      const trip = await env.DB.prepare('SELECT * FROM coach_trips WHERE id=?1').bind(b.trip_id).first();
      if (!trip) return json({ ok: false, error: 'Trip not found' }, 400, h);
      if (!String(b.name || '').trim()) return json({ ok: false, error: 'A name is needed' }, 400, h);
      const seats = Math.max(1, Math.min(10, parseInt(b.seats, 10) || 1));
      const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM coach_bookings').first();
      const booking_ref = 'CT-' + String(1000 + c.n + 1);
      const amount = Math.round(trip.price * seats * 100) / 100;
      const status = ['pending','paid','cash','free'].includes(b.payment_status) ? b.payment_status : 'pending';
      await env.DB.prepare(`INSERT INTO coach_bookings (booking_ref, trip_id, name, email, mobile, seats, amount, payment_status, taken_by, notes)
        VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)`)
        .bind(booking_ref, trip.id, String(b.name).trim(), b.email || null, b.mobile || null,
          seats, amount, status, me.name, b.notes || null).run();
      await audit(env, me.email, 'coach.manual', booking_ref + ' ' + trip.opponent);
      return json({ ok: true, booking_ref }, 200, h);
    }

    // ---- officer: change a booking ----
    if (request.method === 'POST' && url.pathname === '/coach/booking') {
      const me = await sessionOfficer(request, env);
      if (!me) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const b = await request.json();
      if (b.payment_status) {
        await env.DB.prepare('UPDATE coach_bookings SET payment_status=?1 WHERE id=?2').bind(b.payment_status, b.id).run();
      }
      if (b.notes !== undefined) {
        await env.DB.prepare('UPDATE coach_bookings SET notes=?1 WHERE id=?2').bind(b.notes, b.id).run();
      }
      await audit(env, me.email, 'coach.booking.update', 'booking ' + b.id);
      return json({ ok: true }, 200, h);
    }

    // ---------- health ----------
    if (request.method === 'GET' && url.pathname === '/health') {
      const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM members').first();
      return json({ ok: true, members: c.n, automation: !!env.SUMUP_KEY }, 200, h);
    }

    // ---------- read-only: full register export (CSV) ----------
    if (request.method === 'GET' && url.pathname === '/export') {
      const so = await sessionOfficer(request, env);
      if (!authedRead(url, env) && !(so && so.can_members)) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const season = url.searchParams.get('season') || '2026/27';
      const rows = season === 'all'
        ? await env.DB.prepare("SELECT season, first_name, last_name, membership_type, new_or_renewal, gender, dob, email, mobile, home_tel, town, county, postcode, country, activated_at, joined_via, newsletter_optin, member_no, payment_status, payment_method, donation FROM members ORDER BY season, id").all()
        : await env.DB.prepare("SELECT season, first_name, last_name, membership_type, new_or_renewal, gender, dob, email, mobile, home_tel, town, county, postcode, country, activated_at, joined_via, newsletter_optin, member_no, payment_status, payment_method, donation FROM members WHERE season=?1 ORDER BY id").bind(season).all();
      const esc = v => { v = (v == null ? '' : String(v)); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
      const head = 'Season,First Name,Last Name,Membership Type,New/Rpt,Gender,DOB,Email,Mobile,Home Tel,Town,County,Post Code,Country,Date Joined,Newsletter,Method,Donation,Member No,Status';
      const body = rows.results.map(r => [
        r.season, r.first_name, r.last_name, r.membership_type,
        r.new_or_renewal || (r.joined_via === 'online' ? 'New' : 'Rpt'),
        r.gender, (r.dob || '').slice(0,10), r.email, r.mobile, r.home_tel,
        r.town, r.county, r.postcode, r.country, (r.activated_at || '').slice(0,10),
        r.newsletter_optin ? 'Yes' : 'No', r.payment_method, r.donation || '', r.member_no, r.payment_status
      ].map(esc).join(',')).join('\n');
      return new Response(head + '\n' + body, { status: 200, headers: { ...h, 'Content-Type': 'text/csv' } });
    }

    // ---------- board: aggregate stats, zero PII ----------
    if (request.method === 'GET' && url.pathname === '/stats') {
      const so = await sessionOfficer(request, env);
      if (!authedBoard(url, env) && !(so && so.can_board)) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const q = sql => env.DB.prepare(sql).all().then(r => r.results);
      const [byType, bySeason, nvr, news, chase] = await Promise.all([
        q("SELECT membership_type AS k, COUNT(*) AS n FROM members WHERE season='2026/27' AND payment_status<>'cancelled' GROUP BY membership_type"),
        q("SELECT season AS k, COUNT(*) AS n FROM members WHERE payment_status<>'cancelled' GROUP BY season ORDER BY season"),
        q("SELECT COALESCE(new_or_renewal, CASE WHEN joined_via='online' THEN 'New' ELSE 'Rpt' END) AS k, COUNT(*) AS n FROM members WHERE season='2026/27' AND payment_status<>'cancelled' GROUP BY k"),
        q("SELECT newsletter_optin AS k, COUNT(*) AS n FROM members WHERE season='2026/27' AND payment_status<>'cancelled' GROUP BY newsletter_optin"),
        q(`SELECT COUNT(*) AS n FROM members a WHERE a.season='2025/26' AND a.payment_status<>'cancelled'
           AND NOT EXISTS (SELECT 1 FROM members b WHERE b.season='2026/27'
             AND lower(b.first_name)=lower(a.first_name) AND lower(b.last_name)=lower(a.last_name) AND b.postcode=a.postcode)`),
      ]);
      const pend = await env.DB.prepare("SELECT COUNT(*) AS n FROM members WHERE payment_status='pending'").first();
      return json({ ok: true, generated: new Date().toISOString(),
        byType, bySeason, newVsRenewal: nvr, newsletter: news,
        chase: chase[0] ? chase[0].n : 0, pendingApplications: pend.n }, 200, h);
    }

    // ---------- read-only: chase list (lapsed vs current season) ----------
    if (request.method === 'GET' && url.pathname === '/chase') {
      const so = await sessionOfficer(request, env);
      if (!authedRead(url, env) && !(so && so.can_members)) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const from = url.searchParams.get('from') || '2025/26';
      const rows = await env.DB.prepare(
        `SELECT a.first_name, a.last_name, a.membership_type, a.email, a.town, a.postcode
         FROM members a
         WHERE a.season = ?1 AND a.payment_status <> 'cancelled'
           AND NOT EXISTS (SELECT 1 FROM members b WHERE b.season = '2026/27'
             AND lower(b.first_name) = lower(a.first_name)
             AND lower(b.last_name) = lower(a.last_name)
             AND b.postcode = a.postcode)
         ORDER BY a.last_name`
      ).bind(from).all();
      const esc = v => { v = (v == null ? '' : String(v)); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
      const csv = 'First Name,Last Name,Type,Email,Town,Postcode\n' +
        rows.results.map(r => [r.first_name, r.last_name, r.membership_type, r.email, r.town, r.postcode].map(esc).join(',')).join('\n');
      return new Response(csv, { status: 200, headers: { ...h, 'Content-Type': 'text/csv' } });
    }

    // ---------- admin: pending list ----------
    if (request.method === 'GET' && url.pathname === '/pending') {
      const so = await sessionOfficer(request, env);
      if (!authed(url, env) && !(so && so.can_members)) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const rows = await env.DB.prepare(
        "SELECT app_ref, first_name, last_name, membership_type, email, amount_due, created_at FROM members WHERE payment_status='pending' ORDER BY created_at DESC"
      ).all();
      return json({ ok: true, pending: rows.results }, 200, h);
    }

    // ---------- admin: manual activation ----------
    if (request.method === 'POST' && url.pathname === '/activate') {
      if (!authed(url, env)) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const b = await request.json();
      return json(await activate(env, b.app_ref, b.payment_ref || 'manual'), 200, h);
    }

    // ---------- admin: bulk import ----------
    if (request.method === 'POST' && url.pathname === '/import') {
      const so = await sessionOfficer(request, env);
      if (!authed(url, env) && !(so && so.can_members)) return json({ ok: false, error: 'Unauthorised' }, 401, h);
      const rows = await request.json();
      if (!Array.isArray(rows)) return json({ ok: false, error: 'Expected an array' }, 400, h);
      let imported = 0, skipped = 0, errors = [];
      for (const r of rows) {
        try {
          if (!r.first_name || !r.last_name || !r.membership_type) { skipped++; continue; }
          const season = r.season || '2026/27';
          const dupe = await env.DB.prepare(
            "SELECT id FROM members WHERE lower(first_name)=lower(?1) AND lower(last_name)=lower(?2) AND postcode=?3 AND season=?4"
          ).bind(r.first_name, r.last_name, (r.postcode || '').toUpperCase(), season).first();
          if (dupe) { skipped++; continue; }
          const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM members').first();
          const app_ref = 'REF-' + String(1000 + c.n + 1);
          const isCurrent = season === '2026/27' && (r.payment_status || 'desk') !== 'cancelled';
          const member_no = isCurrent ? (r.member_no || await nextMemberNo(env)) : null;
          await env.DB.prepare(`INSERT INTO members
            (app_ref, member_no, season, membership_type, new_or_renewal, first_name, last_name, gender, dob,
             email, mobile, home_tel, address1, address2, town, county, postcode, country,
             exile_transport_share, newsletter_optin, auto_renew_pref, gdpr_consent_at,
             annual_fee, donation, amount_due, payment_status, payment_method,
             letter_confirmed, misc, comments, activated_at, joined_via, created_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33)`)
            .bind(
              app_ref, member_no, season, r.membership_type, r.new_or_renewal || null,
              r.first_name, r.last_name, r.gender || null, r.dob || null,
              (r.email || '').toLowerCase() || 'none@daletrust.uk', r.mobile || null, r.home_tel || null,
              r.address1 || 'Not recorded', r.address2 || null, r.town || 'Not recorded',
              r.county || null, (r.postcode || '').toUpperCase() || 'N/A', r.country || null,
              r.exile_transport_share || null, r.newsletter_optin ? 1 : 0, 0,
              r.consent_date || r.date_joined || new Date().toISOString(),
              r.annual_fee != null && r.annual_fee !== '' ? Number(r.annual_fee) : null,
              Number(r.donation) || 0, 0,
              r.payment_status || 'desk', r.payment_method || null,
              r.letter_confirmed || null, r.misc || null, r.comments || null,
              r.date_joined || new Date().toISOString(),
              'import', r.date_joined || new Date().toISOString()
            ).run();
          imported++;
        } catch (e) { errors.push((r.last_name || '?') + ': ' + e.message); }
      }
      return json({ ok: true, imported, skipped, errors: errors.slice(0, 10) }, 200, h);
    }

    // ---------- SumUp webhook: verify then activate ----------
    if (request.method === 'POST' && url.pathname === '/webhook') {
      if (!env.SUMUP_KEY) return json({ ok: false, error: 'Automation not enabled' }, 400, h);
      const evt = await request.json().catch(() => ({}));
      const checkoutId = evt.id || evt.checkout_id || (evt.payload && evt.payload.checkout_id);
      if (!checkoutId) return json({ ok: true, ignored: true }, 200, h);
      // never trust the webhook body — confirm with SumUp directly
      const chk = await fetch('https://api.sumup.com/v0.1/checkouts/' + checkoutId, {
        headers: { Authorization: 'Bearer ' + env.SUMUP_KEY },
      }).then(r => r.json());
      if (chk && chk.status === 'PAID' && chk.checkout_reference) {
        const ref = chk.checkout_reference;
        if (ref.startsWith('CT-')) {
          await env.DB.prepare("UPDATE coach_bookings SET payment_status='paid', payment_ref=?1 WHERE booking_ref=?2")
            .bind('sumup:' + checkoutId, ref).run();
          await audit(env, 'sumup', 'coach.paid', ref);
          return json({ ok: true, coach: ref }, 200, h);
        }
        const res = await activate(env, ref, 'sumup:' + checkoutId);
        return json(res, 200, h);
      }
      return json({ ok: true, status: chk && chk.status }, 200, h);
    }

    if (request.method !== 'POST') return json({ ok: false, error: 'Not found' }, 404, h);

    // ---------- join application ----------
    const b = await request.json().catch(() => null);
    if (!b) return json({ ok: false, error: 'Bad JSON' }, 400, h);

    const need = ['first_name','last_name','email','address1','town','postcode','membership_type'];
    for (const f of need) if (!String(b[f] || '').trim()) return json({ ok: false, error: `Missing ${f.replace('_',' ')}` }, 400, h);
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(b.email)) return json({ ok: false, error: 'Invalid email' }, 400, h);
    if (!['Adult','Exile','Junior'].includes(b.membership_type)) return json({ ok: false, error: 'Invalid membership type' }, 400, h);
    if (!b.gdpr_consent) return json({ ok: false, error: 'Privacy agreement is required' }, 400, h);

    if (env.TURNSTILE_SECRET) {
      const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: b.turnstile_token || '' }),
      }).then(x => x.json());
      if (!r.success) return json({ ok: false, error: 'Human check failed — please try again' }, 400, h);
    }

    const donation = Math.max(0, Number(b.donation) || 0);
    const base = b.membership_type === 'Junior' ? 0 : 7.5;
    const total = base + donation;
    let status = total > 0 ? 'pending' : 'free';

    const dupe = await env.DB.prepare(
      "SELECT app_ref, member_no FROM members WHERE email=?1 AND lower(last_name)=lower(?2) AND lower(first_name)=lower(?3) AND season='2026/27'"
    ).bind(b.email.trim(), b.last_name.trim(), b.first_name.trim()).first();

    const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM members').first();
    const app_ref = dupe ? dupe.app_ref : 'REF-' + String(1000 + c.n + 1);

    // ---- payment URL: SumUp checkout API when enabled; static links otherwise ----
    let pay_url = null;
    if (total > 0) {
      if (env.SUMUP_KEY && env.SUMUP_MERCHANT) {
        const chk = await fetch('https://api.sumup.com/v0.1/checkouts', {
          method: 'POST',
          headers: { Authorization: 'Bearer ' + env.SUMUP_KEY, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            checkout_reference: app_ref,
            amount: total, currency: 'GBP',
            merchant_code: env.SUMUP_MERCHANT,
            return_url: 'https://join.daletrust.uk/webhook',
            description: 'Dale Trust membership 2026/27 (' + app_ref + ')',
            hosted_checkout: { enabled: true },
          }),
        }).then(r => r.json()).catch(() => null);
        pay_url = chk && (chk.hosted_checkout_url || (chk.hosted_checkout && chk.hosted_checkout.url)) || null;
      }
      if (!pay_url) {
        const links = { 7.5: env.LINK_750, 10: env.LINK_1000, 12.5: env.LINK_1250, 17.5: env.LINK_1750 };
        pay_url = links[total] || env.LINK_750;
      }
    }

    if (dupe) return json({ ok: true, app_ref, member_no: dupe.member_no, pay_url, amount: total, duplicate: true }, 200, h);

    let member_no = null, activated_at = null;
    if (status === 'free') { member_no = await nextMemberNo(env); activated_at = new Date().toISOString(); }

    await env.DB.prepare(`INSERT INTO members
      (app_ref, member_no, membership_type, first_name, last_name, dob, email, mobile,
       address1, address2, town, postcode, exile_transport_share,
       newsletter_optin, auto_renew_pref, gdpr_consent_at, donation, amount_due, payment_status, activated_at)
      VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)`)
      .bind(
        app_ref, member_no, b.membership_type, b.first_name.trim(), b.last_name.trim(),
        b.dob || null, b.email.trim().toLowerCase(), b.mobile || null,
        b.address1.trim(), b.address2 || null, b.town.trim(), b.postcode.trim().toUpperCase(),
        b.membership_type === 'Exile' ? (b.exile_transport_share || 'No') : null,
        b.newsletter ? 1 : 0, b.auto_renew ? 1 : 0,
        new Date().toISOString(), donation, total, status, activated_at
      ).run();

    if (env.RESEND_KEY) ctx.waitUntil(sendConfirmation(env, b, member_no, app_ref, total, pay_url));
    return json({ ok: true, app_ref, member_no, pay_url, amount: total }, 200, h);

    } catch (err) {
      return json({ ok: false, error: 'Server error: ' + (err && err.message || String(err)) }, 500, h);
    }
  },
};

// ---------- emails ----------
function shell(inner) {
  return '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#333">' +
    '<div style="background:#0E1F3D;padding:22px 26px;border-bottom:5px solid #0057A7">' +
      '<span style="color:#fff;font-size:20px;font-weight:800;letter-spacing:.5px">DALE SUPPORTERS TRUST</span><br>' +
      '<span style="color:#8FC1FF;font-size:12px;letter-spacing:2px">MEMBERSHIP 2026/27</span>' +
    '</div>' +
    '<div style="padding:26px">' + inner + '</div>' +
    '<div style="background:#F2F5F9;padding:14px 26px;font-size:11.5px;color:#7A8AA5">' +
      'Dale Trust is the trading name of Rochdale Supporters Club Limited, a registered society (IP29690R).' +
    '</div></div>';
}
async function sendEmail(env, to, subject, inner) {
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + env.RESEND_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'Dale Trust <membership@daletrust.uk>', to: [to], subject, html: shell(inner) }),
  });
}
async function sendConfirmation(env, b, member_no, app_ref, total, pay_url) {
  const first = b.first_name.trim();
  if (total > 0) {
    await sendEmail(env, b.email.trim(),
      'Complete your Dale Trust application \u2014 ' + app_ref,
      '<p>Hi ' + first + ',</p>' +
      '<p>Your Dale Trust application is in \u2014 one step left. Your application reference:</p>' +
      '<p style="font-size:26px;font-weight:800;color:#0E1F3D;letter-spacing:2px;margin:12px 0">' + app_ref + '</p>' +
      '<p style="margin:18px 0"><a href="' + pay_url + '" style="background:#1E8E5A;color:#fff;text-decoration:none;font-weight:700;padding:14px 26px;border-radius:9px;display:inline-block">Pay \u00A3' + total.toFixed(2) + ' to complete your membership</a></p>' +
      '<p style="color:#666;font-size:13px">Card, Apple Pay or Google Pay \u2014 no account needed. Your membership number arrives with your welcome email as soon as payment completes.</p>' +
      '<p>Up the Dale!<br><strong>The Dale Trust</strong></p>');
  } else {
    await sendEmail(env, b.email.trim(),
      'Welcome to the Dale Trust \u2014 ' + member_no,
      '<p>Hi ' + first + ',</p>' +
      '<p>Welcome to the Dale Trust \u2014 junior membership is free, and you\u2019re all set. Your membership number:</p>' +
      '<p style="font-size:26px;font-weight:800;color:#0E1F3D;letter-spacing:2px;margin:12px 0">' + member_no + '</p>' +
      '<p>Your membership includes Partners of the Trust discounts, free entry to both prediction leagues, coach travel priority, and a real voice in Rochdale AFC.</p>' +
      '<p>Up the Dale!<br><strong>The Dale Trust</strong></p>');
  }
}
async function sendWelcome(env, row, member_no) {
  await sendEmail(env, row.email,
    'Welcome to the Dale Trust \u2014 ' + member_no,
    '<p>Hi ' + row.first_name + ',</p>' +
    '<p>Payment received \u2014 you\u2019re a Dale Trust member. Your membership number:</p>' +
    '<p style="font-size:26px;font-weight:800;color:#0E1F3D;letter-spacing:2px;margin:12px 0">' + member_no + '</p>' +
    '<p>Your membership includes Partners of the Trust discounts at nine local businesses, free entry to both prediction leagues, coach travel priority, and a real voice in Rochdale AFC.</p>' +
    '<p>Up the Dale!<br><strong>The Dale Trust</strong></p>');
}
