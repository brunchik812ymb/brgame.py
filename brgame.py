"""
brgame: демо-букмекер на Flask + SQLite (виртуальные монеты, не реальные деньги).

Запуск:
    pip install flask
    python brgame.py
Открыть: http://127.0.0.1:5000

Администратор: аккаунт с именем ADMIN_NAME (см. ниже) получает права при регистрации.
"""
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "bookmaker.db")
PICKS = {"1": "П1", "x": "Х", "2": "П2"}
ODDCOL = {"1": "o1", "x": "ox", "2": "o2"}
START_BALANCE, MAX_STAKE = 1000, 10000
ADMIN_NAME = "admin"  # <-- впишите сюда своё имя: зарегистрируйтесь под ним и станете админом

SECRET_FILE = os.path.join(BASE_DIR, ".secret")
if not os.path.exists(SECRET_FILE):
    with open(SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(secrets.token_hex(32))
with open(SECRET_FILE, encoding="utf-8") as f:
    SECRET_KEY = f.read().strip()

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ---------- база данных ----------
@contextmanager
def tx():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def init_db():
    with tx() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, name TEXT UNIQUE, pw TEXT,
            balance INTEGER DEFAULT %d, is_admin INTEGER DEFAULT 0, last_bonus TEXT);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY, sport TEXT, title TEXT, starts TEXT,
            o1 REAL, ox REAL, o2 REAL, result TEXT);
        CREATE TABLE IF NOT EXISTS bets(
            id INTEGER PRIMARY KEY, user_id INT, event_id INT, pick TEXT,
            stake INT, odds REAL, status TEXT DEFAULT 'open', created TEXT);
        """ % START_BALANCE)
        if c.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0:
            t = datetime.now()
            seed = [("Футбол", "Спартак - Зенит", 5, 2.40, 3.20, 2.90),
                    ("Футбол", "Реал - Барселона", 26, 2.10, 3.50, 3.10),
                    ("Футбол", "Ливерпуль - Арсенал", 30, 2.60, 3.40, 2.50),
                    ("Хоккей", "ЦСКА - СКА", 8, 2.20, 4.10, 2.70),
                    ("Хоккей", "Авангард - Ак Барс", 52, 2.50, 4.00, 2.35),
                    ("Баскетбол", "Лейкерс - Бостон", 12, 2.30, 15.0, 1.62)]
            c.executemany(
                "INSERT INTO events(sport,title,starts,o1,ox,o2) VALUES(?,?,?,?,?,?)",
                [(s, n, (t + timedelta(hours=h)).strftime("%Y-%m-%d %H:%M"), a, b, d)
                 for s, n, h, a, b, d in seed])


# ---------- сессия, CSRF, доступ ----------
@app.before_request
def load_user():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        token = request.form.get("_csrf") or request.headers.get("X-CSRF")
        if not token or not secrets.compare_digest(token, session["csrf"]):
            abort(400)
    g.user = None
    if session.get("uid"):
        with tx() as c:
            g.user = c.execute("SELECT * FROM users WHERE id=?",
                               (session["uid"],)).fetchone()


@app.context_processor
def inject():
    return dict(user=g.user, csrf=session.get("csrf"), PICKS=PICKS, now=now_str())


@app.template_filter("fmt")
def fmt(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M").strftime("%d.%m, %H:%M")


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not g.user:
            if request.path.startswith("/api/"):
                return jsonify(error="Войдите в аккаунт"), 401
            return redirect("/login")
        return f(*a, **k)
    return w


def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if not g.user["is_admin"]:
            abort(403)
        return f(*a, **k)
    return w


# ---------- страницы ----------
@app.route("/")
def index():
    sport = request.args.get("sport", "")
    with tx() as c:
        sports = [r[0] for r in c.execute("SELECT DISTINCT sport FROM events ORDER BY sport")]
        q = "SELECT * FROM events" + (" WHERE sport=?" if sport else "")
        events = c.execute(q + " ORDER BY result IS NOT NULL, starts",
                           (sport,) if sport else ()).fetchall()
    return render_template("index.html", events=events, sports=sports, sport=sport)


@app.route("/register", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"], endpoint="login")
def auth():
    reg = request.path == "/register"
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        pw = request.form.get("pw", "")
        with tx() as c:
            if reg:
                if not 3 <= len(name) <= 20 or len(pw) < 6:
                    flash("Имя: 3-20 символов, пароль: не короче 6.", "err")
                    return redirect("/register")
                first = name.lower() == ADMIN_NAME.lower()
                try:
                    cur = c.execute("INSERT INTO users(name,pw,is_admin) VALUES(?,?,?)",
                                    (name, generate_password_hash(pw), int(first)))
                except sqlite3.IntegrityError:
                    flash("Это имя уже занято.", "err")
                    return redirect("/register")
                uid = cur.lastrowid
            else:
                u = c.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
                if not u or not check_password_hash(u["pw"], pw):
                    flash("Неверное имя или пароль.", "err")
                    return redirect("/login")
                uid = u["id"]
        session.clear()
        session["uid"] = uid
        flash("Добро пожаловать!")
        return redirect("/")
    return render_template("auth.html", reg=reg)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


@app.route("/bets")
@login_required
def my_bets():
    with tx() as c:
        bets = c.execute(
            """SELECT b.*, e.title, e.sport FROM bets b JOIN events e ON e.id=b.event_id
               WHERE b.user_id=? ORDER BY b.id DESC""", (g.user["id"],)).fetchall()
    return render_template("bets.html", bets=bets)


@app.route("/bonus", methods=["POST"])
@login_required
def bonus():
    today = datetime.now().strftime("%Y-%m-%d")
    with tx() as c:
        if g.user["balance"] < 100 and g.user["last_bonus"] != today:
            c.execute("UPDATE users SET balance=balance+500,last_bonus=? WHERE id=?",
                      (today, g.user["id"]))
            flash("Начислено 500 монет.")
        else:
            flash("Бонус доступен раз в день, когда на балансе меньше 100 монет.", "err")
    return redirect(request.referrer or "/")


@app.route("/api/bet", methods=["POST"])
@login_required
def api_bet():
    items = (request.get_json(silent=True) or {}).get("bets")
    if not isinstance(items, list) or not 0 < len(items) <= 20:
        return jsonify(error="Купон пуст"), 400
    rows, seen, total = [], set(), 0
    with tx() as c:
        for it in items:
            try:
                eid, stake, pick = int(it["event_id"]), int(it["stake"]), it["pick"]
            except (KeyError, TypeError, ValueError):
                return jsonify(error="Неверные данные купона"), 400
            ev = c.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
            if pick not in PICKS or eid in seen or not 1 <= stake <= MAX_STAKE:
                return jsonify(error="Сумма ставки: от 1 до %d монет" % MAX_STAKE), 400
            if not ev or ev["result"] or ev["starts"] <= now_str():
                return jsonify(error="Приём ставок на «%s» закрыт" % (ev["title"] if ev else "?")), 400
            seen.add(eid)
            total += stake
            rows.append((g.user["id"], eid, pick, stake, ev[ODDCOL[pick]], now_str()))
        cur = c.execute("UPDATE users SET balance=balance-? WHERE id=? AND balance>=?",
                        (total, g.user["id"], total))
        if cur.rowcount == 0:
            return jsonify(error="Недостаточно монет"), 400
        c.executemany("INSERT INTO bets(user_id,event_id,pick,stake,odds,created) "
                      "VALUES(?,?,?,?,?,?)", rows)
    flash("Ставок принято: %d" % len(rows))
    return jsonify(ok=True)


# ---------- админка ----------
@app.route("/admin")
@admin_required
def admin():
    with tx() as c:
        events = c.execute("SELECT * FROM events ORDER BY result IS NOT NULL, starts").fetchall()
    return render_template("admin.html", events=events)


@app.route("/admin/event", methods=["POST"])
@admin_required
def admin_event():
    f = request.form
    try:
        o = [round(float(f[k]), 2) for k in ("o1", "ox", "o2")]
        starts = datetime.strptime(f["starts"], "%Y-%m-%dT%H:%M").strftime("%Y-%m-%d %H:%M")
        assert all(x > 1 for x in o) and f["title"].strip() and f["sport"].strip()
    except (KeyError, ValueError, AssertionError):
        flash("Проверьте поля: коэффициенты должны быть больше 1.", "err")
        return redirect("/admin")
    with tx() as c:
        c.execute("INSERT INTO events(sport,title,starts,o1,ox,o2) VALUES(?,?,?,?,?,?)",
                  (f["sport"].strip(), f["title"].strip(), starts, *o))
    flash("Событие добавлено.")
    return redirect("/admin")


@app.route("/admin/settle/<int:eid>", methods=["POST"])
@admin_required
def admin_settle(eid):
    result = request.form.get("result")
    if result not in PICKS:
        abort(400)
    with tx() as c:
        cur = c.execute("UPDATE events SET result=? WHERE id=? AND result IS NULL", (result, eid))
        if cur.rowcount:
            for b in c.execute("SELECT * FROM bets WHERE event_id=? AND status='open'",
                               (eid,)).fetchall():
                if b["pick"] == result:
                    c.execute("UPDATE users SET balance=balance+? WHERE id=?",
                              (round(b["stake"] * b["odds"]), b["user_id"]))
                    c.execute("UPDATE bets SET status='won' WHERE id=?", (b["id"],))
                else:
                    c.execute("UPDATE bets SET status='lost' WHERE id=?", (b["id"],))
            flash("Событие закрыто, ставки рассчитаны.")
    return redirect("/admin")


# ---------- шаблоны ----------
T = {}
T["base.html"] = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="csrf" content="{{ csrf }}">
<title>brgame</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;800&family=Unbounded:wght@500;700&display=swap&subset=cyrillic" rel="stylesheet">
<style>
:root{--bg:#F2F4F8;--card:#fff;--ink:#0F1729;--mut:#667085;--line:#E1E5EC;--acc:#2B4EFF;--win:#0E9F6E;--lose:#D92D20}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 Manrope,system-ui,sans-serif}
a{color:inherit}
:focus-visible{outline:3px solid #8fa3ff;outline-offset:2px}
header{background:var(--ink);color:#fff}
.bar{max-width:1100px;margin:auto;padding:12px 16px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.logo{font:700 20px Unbounded,sans-serif;text-decoration:none}
nav{display:flex;gap:16px;flex:1}
nav a{color:#c9d1e6;text-decoration:none}
nav a:hover{color:#fff}
.right{display:flex;align-items:center;gap:8px}
.chip{background:#1d2a4a;border-radius:99px;padding:6px 14px;font-weight:800}
main{max-width:1100px;margin:20px auto;padding:0 16px}
footer{max-width:1100px;margin:40px auto 24px;padding:0 16px;color:var(--mut);font-size:14px}
h1{font:700 26px Unbounded,sans-serif;margin:0 0 16px}
.grid{display:grid;grid-template-columns:1fr 330px;gap:20px;align-items:start}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:12px}
.card h3{margin:0 0 2px;font-size:17px}
.mut{color:var(--mut);font-size:14px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.filters a{padding:6px 14px;border-radius:99px;border:1px solid var(--line);background:#fff;text-decoration:none;font-weight:600}
.filters a.on{background:var(--ink);color:#fff;border-color:var(--ink)}
.odds{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:12px}
.odd{border:1.5px solid var(--line);background:#fff;border-radius:10px;padding:10px 4px;cursor:pointer;font:inherit;color:inherit;display:flex;flex-direction:column;align-items:center}
.odd small{color:var(--mut);font-weight:600}
.odd b{font:500 20px Unbounded,sans-serif}
.odd:hover:not(:disabled){border-color:var(--acc)}
.odd.sel{background:var(--acc);border-color:var(--acc);color:#fff}
.odd.sel small{color:#dfe5ff}
.odd:disabled{opacity:.5;cursor:default}
.odd.win{opacity:1;border-color:var(--win);background:#e8f7f0}
.btn{background:var(--acc);color:#fff;border:0;border-radius:10px;padding:10px 16px;font:800 15px Manrope,sans-serif;cursor:pointer;text-decoration:none;display:inline-block}
.btn.ghost{background:transparent;color:inherit;border:1px solid var(--line)}
.btn.sm{padding:6px 12px;font-size:14px}
header .btn.ghost{border-color:#33415f;color:#fff}
.btn:disabled{opacity:.5;cursor:default}
input,select{font:inherit;padding:9px 12px;border:1px solid var(--line);border-radius:10px;width:100%;background:#fff}
label{display:block;font-weight:600;margin:12px 0 4px}
.msg{padding:10px 14px;border-radius:10px;margin-bottom:12px;background:#e8edff;font-weight:600}
.msg.err{background:#fde8e6;color:#9a1c12}
.badge{padding:2px 10px;border-radius:99px;font-size:13px;font-weight:800;background:#eef0f4}
.badge.won{background:#e8f7f0;color:var(--win)}.badge.lost{background:#fde8e6;color:var(--lose)}
.slip{position:sticky;top:16px;margin:0}
.slip-head{display:flex;justify-content:space-between;align-items:center;height:28px;cursor:pointer;font-weight:800}
.slip-item{border-top:1px solid var(--line);padding:10px 0}
.si-top{display:flex;justify-content:space-between;gap:8px}
.x{border:0;background:none;font-size:20px;cursor:pointer;color:var(--mut)}
.quick{display:flex;gap:6px;margin:6px 0 2px}
.sum{display:flex;justify-content:space-between;margin:12px 0}
table{width:100%;border-collapse:collapse}
td,th{text-align:left;padding:10px 6px;border-top:1px solid var(--line);font-size:15px}
.narrow{max-width:400px;margin:40px auto}
@media(max-width:900px){
 .grid{grid-template-columns:1fr}
 .slip{position:fixed;left:0;right:0;bottom:0;z-index:5;margin:0;border-radius:16px 16px 0 0;max-height:75vh;overflow:auto;transform:translateY(calc(100% - 60px));transition:transform .2s}
 .slip.open{transform:none}
 main{padding-bottom:80px}
}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body>
<header><div class="bar">
 <a class="logo" href="/">brgame</a>
 <nav><a href="/">События</a>{% if user %}<a href="/bets">Мои ставки</a>{% endif %}{% if user and user['is_admin'] %}<a href="/admin">Админ</a>{% endif %}</nav>
 <div class="right">
 {% if user %}
  <span class="chip" id="bal">{{ user['balance'] }} монет</span>
  {% if user['balance'] < 100 %}<form method="post" action="/bonus"><input type="hidden" name="_csrf" value="{{ csrf }}"><button class="btn sm ghost">Взять бонус</button></form>{% endif %}
  <form method="post" action="/logout"><input type="hidden" name="_csrf" value="{{ csrf }}"><button class="btn sm ghost">Выйти</button></form>
 {% else %}
  <a class="btn sm ghost" href="/login">Войти</a><a class="btn sm" href="/register">Регистрация</a>
 {% endif %}
 </div></div></header>
<main>
{% for cat, m in get_flashed_messages(with_categories=true) %}<div class="msg {{ 'err' if cat == 'err' }}">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}
</main>
<footer>Демо-проект. Ставки делаются виртуальными монетами, реальные деньги не используются.</footer>
{% block script %}{% endblock %}
</body></html>"""

T["index.html"] = """{% extends "base.html" %}
{% block body %}
<h1>События</h1>
<div class="filters">
 <a href="/" class="{{ 'on' if not sport }}">Все</a>
 {% for s in sports %}<a href="/?sport={{ s }}" class="{{ 'on' if s == sport }}">{{ s }}</a>{% endfor %}
</div>
<div class="grid"><section>
{% for e in events %}
 {% set live = not e['result'] and e['starts'] <= now %}
 <article class="card">
  <h3>{{ e['title'] }}</h3>
  <div class="mut">{{ e['sport'] }}, {{ e['starts']|fmt }}
   {% if e['result'] %}<span class="badge">Завершено</span>{% elif live %}<span class="badge">Приём ставок закрыт</span>{% endif %}</div>
  <div class="odds">
  {% for k, col in (('1','o1'),('x','ox'),('2','o2')) %}
   <button type="button" class="odd {{ 'win' if e['result'] == k }}" {{ 'disabled' if e['result'] or live }}
     data-id="{{ e['id'] }}" data-pick="{{ k }}" data-odds="{{ e[col] }}" data-title="{{ e['title'] }}">
    <small>{{ PICKS[k] }}</small><b>{{ '%.2f'|format(e[col]) }}</b></button>
  {% endfor %}
  </div>
 </article>
{% else %}<p class="mut">Событий пока нет.</p>{% endfor %}
</section>
<aside class="card slip" id="slip">
 <div class="slip-head" id="slip-toggle"><span>Купон</span><span id="slip-count">0</span></div>
 <div id="slip-items"></div>
 <div class="sum"><span class="mut">Возможный выигрыш</span><b id="win">0</b></div>
 <p class="mut" id="slip-err" style="color:var(--lose)" role="alert"></p>
 {% if user %}<button class="btn" id="go" style="width:100%" disabled>Поставить <span id="tot"></span></button>
 {% else %}<a class="btn" style="width:100%;text-align:center" href="/login">Войдите, чтобы поставить</a>{% endif %}
</aside></div>
{% endblock %}
{% block script %}<script>
const slip={}, $=s=>document.querySelector(s), MAX=10000;
const csrf=document.querySelector('meta[name=csrf]').content;
const names={'1':'П1','x':'Х','2':'П2'};
function totals(){
  let t=0,w=0;
  Object.values(slip).forEach(s=>{const v=parseInt(s.stake)||0;t+=v;w+=Math.round(v*s.odds)});
  $('#win').textContent=w;
  const go=$('#go'); if(go){$('#tot').textContent=t?'('+t+')':'';go.disabled=!t}
}
function render(){
  const ids=Object.keys(slip), box=$('#slip-items');
  $('#slip-count').textContent=ids.length; box.innerHTML='';
  if(!ids.length){const p=document.createElement('p');p.className='mut';p.textContent='Выберите исход, и он появится в купоне.';box.append(p)}
  ids.forEach(id=>{
    const s=slip[id], el=document.createElement('div'); el.className='slip-item';
    el.innerHTML='<div class="si-top"><b></b><button type="button" class="x" aria-label="Убрать из купона">×</button></div><div class="mut"></div><input type="number" min="1" max="'+MAX+'" inputmode="numeric" placeholder="Сумма ставки"><div class="quick"></div>';
    el.querySelector('b').textContent=s.title;
    el.querySelector('.mut').textContent=names[s.pick]+', коэффициент '+s.odds.toFixed(2);
    const inp=el.querySelector('input'); inp.value=s.stake||'';
    inp.oninput=()=>{s.stake=inp.value;totals()};
    [50,100,500].forEach(n=>{const b=document.createElement('button');b.type='button';b.className='btn sm ghost';b.textContent=n;b.onclick=()=>{s.stake=n;inp.value=n;totals()};el.querySelector('.quick').append(b)});
    el.querySelector('.x').onclick=()=>{delete slip[id];sync();};
    box.append(el);
  });
  totals();
}
function sync(){
  document.querySelectorAll('.odd').forEach(b=>{const s=slip[b.dataset.id];b.classList.toggle('sel',!!s&&s.pick===b.dataset.pick)});
  render();
}
document.querySelectorAll('.odd').forEach(b=>b.onclick=()=>{
  const id=b.dataset.id, cur=slip[id];
  if(cur&&cur.pick===b.dataset.pick) delete slip[id];
  else slip[id]={pick:b.dataset.pick,odds:parseFloat(b.dataset.odds),title:b.dataset.title,stake:cur?cur.stake:''};
  sync();
});
$('#slip-toggle').onclick=()=>$('#slip').classList.toggle('open');
const go=$('#go');
if(go) go.onclick=async()=>{
  const bets=Object.entries(slip).map(([id,s])=>({event_id:id,pick:s.pick,stake:parseInt(s.stake)||0}));
  go.disabled=true; $('#slip-err').textContent='';
  try{
    const r=await fetch('/api/bet',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':csrf},body:JSON.stringify({bets})});
    const d=await r.json();
    if(d.ok) location.reload(); else {$('#slip-err').textContent=d.error||'Ошибка';go.disabled=false}
  }catch(e){$('#slip-err').textContent='Нет соединения с сервером';go.disabled=false}
};
render();
</script>{% endblock %}"""

T["auth.html"] = """{% extends "base.html" %}
{% block body %}
<form class="card narrow" method="post">
 <h1>{{ 'Регистрация' if reg else 'Вход' }}</h1>
 <input type="hidden" name="_csrf" value="{{ csrf }}">
 <label for="n">Имя</label><input id="n" name="name" required minlength="3" maxlength="20" autocomplete="username">
 <label for="p">Пароль</label><input id="p" name="pw" type="password" required minlength="{{ 6 if reg else 1 }}" autocomplete="{{ 'new-password' if reg else 'current-password' }}">
 <p><button class="btn" style="width:100%">{{ 'Создать аккаунт' if reg else 'Войти' }}</button></p>
 <p class="mut">{% if reg %}Уже есть аккаунт? <a href="/login">Войти</a>{% else %}Нет аккаунта? <a href="/register">Зарегистрироваться</a>{% endif %}</p>
</form>
{% endblock %}"""

T["bets.html"] = """{% extends "base.html" %}
{% block body %}
<h1>Мои ставки</h1>
<div class="card" style="overflow-x:auto">
{% if bets %}<table>
 <tr><th>Событие</th><th>Исход</th><th>Ставка</th><th>Коэф.</th><th>Статус</th></tr>
 {% for b in bets %}<tr>
  <td>{{ b['title'] }}<div class="mut">{{ b['sport'] }}</div></td>
  <td>{{ PICKS[b['pick']] }}</td><td>{{ b['stake'] }}</td><td>{{ '%.2f'|format(b['odds']) }}</td>
  <td>{% if b['status'] == 'won' %}<span class="badge won">Выигрыш +{{ (b['stake'] * b['odds'])|round|int }}</span>
   {% elif b['status'] == 'lost' %}<span class="badge lost">Проигрыш</span>
   {% else %}<span class="badge">Ожидает</span>{% endif %}</td></tr>{% endfor %}
</table>{% else %}<p class="mut">Ставок пока нет. <a href="/">Выберите событие</a>.</p>{% endif %}
</div>
{% endblock %}"""

T["admin.html"] = """{% extends "base.html" %}
{% block body %}
<h1>Админка</h1>
<form class="card" method="post" action="/admin/event">
 <h3>Новое событие</h3><input type="hidden" name="_csrf" value="{{ csrf }}">
 <label for="s">Вид спорта</label><input id="s" name="sport" list="sp" required>
 <datalist id="sp"><option>Футбол</option><option>Хоккей</option><option>Баскетбол</option></datalist>
 <label for="t">Название (Команда А - Команда Б)</label><input id="t" name="title" required>
 <label for="d">Начало</label><input id="d" name="starts" type="datetime-local" required>
 <div class="odds"><div><label for="a">П1</label><input id="a" name="o1" type="number" step="0.01" min="1.01" required></div>
 <div><label for="b">Х</label><input id="b" name="ox" type="number" step="0.01" min="1.01" required></div>
 <div><label for="c">П2</label><input id="c" name="o2" type="number" step="0.01" min="1.01" required></div></div>
 <p><button class="btn">Добавить событие</button></p>
</form>
{% for e in events %}
<div class="card"><b>{{ e['title'] }}</b> <span class="mut">{{ e['sport'] }}, {{ e['starts']|fmt }}</span>
 {% if e['result'] %}<p>Результат: <span class="badge won">{{ PICKS[e['result']] }}</span></p>
 {% else %}<form method="post" action="/admin/settle/{{ e['id'] }}" style="display:flex;gap:8px;margin-top:10px">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  {% for k in ('1','x','2') %}<button class="btn sm ghost" name="result" value="{{ k }}">Закрыть: {{ PICKS[k] }}</button>{% endfor %}
 </form>{% endif %}</div>
{% endfor %}
{% endblock %}"""

app.jinja_env.loader = DictLoader(T)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
