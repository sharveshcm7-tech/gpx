from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, Response
import sqlite3
import hashlib
import os
import json
import csv
import io
import random
import string
import time
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'grandprix_secret_key_2024'
DB_PATH = 'grandprix.db'

# ─── DB HELPERS ──────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'member',
            email_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            reset_token TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS teams (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            team_code TEXT UNIQUE NOT NULL,
            invite_code TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'pending',
            score INTEGER DEFAULT 0,
            penalty INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS team_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            user_id INTEGER,
            role TEXT DEFAULT 'member',
            FOREIGN KEY(team_id) REFERENCES teams(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS problems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            constraints TEXT,
            sample_input TEXT,
            sample_output TEXT,
            difficulty TEXT DEFAULT 'Medium',
            points INTEGER DEFAULT 100,
            category TEXT DEFAULT 'Arrays',
            visible INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            user_id INTEGER,
            problem_id INTEGER,
            code TEXT NOT NULL,
            language TEXT DEFAULT 'python',
            status TEXT DEFAULT 'Pending',
            score INTEGER DEFAULT 0,
            admin_notes TEXT,
            submitted_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(team_id) REFERENCES teams(id),
            FOREIGN KEY(problem_id) REFERENCES problems(id)
        );
        CREATE TABLE IF NOT EXISTS announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS clarifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            user_id INTEGER,
            problem_id INTEGER,
            question TEXT NOT NULL,
            answer TEXT,
            is_public INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(team_id) REFERENCES teams(id)
        );
        CREATE TABLE IF NOT EXISTS contest_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id INTEGER,
            badge_type TEXT,
            awarded_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(team_id) REFERENCES teams(id)
        );
    ''')
    # Insert default contest settings
    defaults = [
        ('contest_status', 'upcoming'),
        ('contest_start', (datetime.now() + timedelta(days=1)).isoformat()),
        ('contest_end', (datetime.now() + timedelta(days=1, hours=3)).isoformat()),
        ('leaderboard_frozen', '0'),
        ('event_name', 'CODE GRAND PRIX 2024'),
        ('event_tagline', 'Race to the Algorithm'),
    ]
    for key, value in defaults:
        c.execute('INSERT OR IGNORE INTO contest_settings (key, value) VALUES (?, ?)', (key, value))
    # Create default admin
    admin_pw = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute('INSERT OR IGNORE INTO users (username, email, password, role, email_verified) VALUES (?, ?, ?, ?, ?)',
              ('admin', 'admin@grandprix.com', admin_pw, 'admin', 1))
    conn.commit()
    conn.close()

def get_setting(key):
    conn = get_db()
    row = conn.execute('SELECT value FROM contest_settings WHERE key=?', (key,)).fetchone()
    conn.close()
    return row['value'] if row else None

def set_setting(key, value):
    conn = get_db()
    conn.execute('INSERT OR REPLACE INTO contest_settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

# ─── AUTH DECORATORS ──────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            # Team member tried to access an admin page — send them home
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def gen_code(n=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=n))

# ─── ROUTES: PUBLIC ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    settings = {}
    conn = get_db()
    for row in conn.execute('SELECT key, value FROM contest_settings'):
        settings[row['key']] = row['value']
    sponsors = ['TechCorp', 'CodeLabs', 'AlgoAI', 'DevHub', 'ByteForce']
    conn.close()
    return render_template('landing.html', settings=settings, sponsors=sponsors)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.get_json() or request.form
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE email=? OR username=?', (email, username)).fetchone()
        if existing:
            conn.close()
            return jsonify({'success': False, 'message': 'Username or email already exists'})
        token = gen_code(32)
        conn.execute('INSERT INTO users (username, email, password, verification_token, email_verified) VALUES (?,?,?,?,1)',
                     (username, email, hash_pw(password), token))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Registration successful! Please login.'})
    return render_template('auth.html', page='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() or request.form
        email = data.get('email', '').strip()
        password = data.get('password', '')
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email=? AND password=?', (email, hash_pw(password))).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return jsonify({'success': True, 'redirect': '/admin'})
            return jsonify({'success': True, 'redirect': '/dashboard'})
        return jsonify({'success': False, 'message': 'Invalid credentials'})
    return render_template('auth.html', page='login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ─── TEAM ROUTES ──────────────────────────────────────────────────────────────

@app.route('/team/create', methods=['POST'])
@login_required
def create_team():
    data = request.get_json()
    name = data.get('name', '').strip()
    conn = get_db()
    existing_member = conn.execute('SELECT t.id FROM teams t JOIN team_members tm ON t.id=tm.team_id WHERE tm.user_id=?', (session['user_id'],)).fetchone()
    if existing_member:
        conn.close()
        return jsonify({'success': False, 'message': 'You are already in a team'})
    existing_team = conn.execute('SELECT id FROM teams WHERE name=?', (name,)).fetchone()
    if existing_team:
        conn.close()
        return jsonify({'success': False, 'message': 'Team name already taken'})
    team_code = 'GP-' + gen_code(6)
    invite_code = gen_code(10)
    conn.execute('INSERT INTO teams (name, team_code, invite_code) VALUES (?,?,?)', (name, team_code, invite_code))
    team_id = conn.execute('SELECT id FROM teams WHERE name=?', (name,)).fetchone()['id']
    conn.execute('INSERT INTO team_members (team_id, user_id, role) VALUES (?,?,?)', (team_id, session['user_id'], 'leader'))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Team created! Code: {team_code}'})

@app.route('/team/join', methods=['POST'])
@login_required
def join_team():
    data = request.get_json()
    invite_code = data.get('invite_code', '').strip()
    conn = get_db()
    existing_member = conn.execute('SELECT t.id FROM teams t JOIN team_members tm ON t.id=tm.team_id WHERE tm.user_id=?', (session['user_id'],)).fetchone()
    if existing_member:
        conn.close()
        return jsonify({'success': False, 'message': 'You are already in a team'})
    team = conn.execute('SELECT * FROM teams WHERE invite_code=?', (invite_code,)).fetchone()
    if not team:
        conn.close()
        return jsonify({'success': False, 'message': 'Invalid invite code'})
    conn.execute('INSERT INTO team_members (team_id, user_id) VALUES (?,?)', (team['id'], session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Joined team {team["name"]}!'})

# ─── DASHBOARD ──────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    team_row = conn.execute('''
        SELECT t.*, tm.role as member_role FROM teams t 
        JOIN team_members tm ON t.id=tm.team_id 
        WHERE tm.user_id=?
    ''', (session['user_id'],)).fetchone()
    team = dict(team_row) if team_row else None
    members = []
    if team:
        members = conn.execute('''
            SELECT u.username, tm.role FROM users u 
            JOIN team_members tm ON u.id=tm.user_id 
            WHERE tm.team_id=?
        ''', (team['id'],)).fetchall()
    problems = conn.execute('SELECT * FROM problems WHERE visible=1 ORDER BY difficulty').fetchall()
    announcements = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 5').fetchall()
    settings = {}
    for row in conn.execute('SELECT key, value FROM contest_settings'):
        settings[row['key']] = row['value']
    
    # Get team submissions summary
    solved_ids = set()
    if team:
        solved = conn.execute('''
            SELECT DISTINCT problem_id FROM submissions 
            WHERE team_id=? AND status="Accepted"
        ''', (team['id'],)).fetchall()
        solved_ids = {r['problem_id'] for r in solved}
    conn.close()
    return render_template('dashboard.html', user=user, team=team, members=members,
                           problems=problems, announcements=announcements, settings=settings,
                           solved_ids=solved_ids)

@app.route('/contest')
@login_required
def contest():
    conn = get_db()
    problems = conn.execute('SELECT * FROM problems WHERE visible=1 ORDER BY difficulty').fetchall()
    team_row = conn.execute('''
        SELECT t.* FROM teams t JOIN team_members tm ON t.id=tm.team_id WHERE tm.user_id=?
    ''', (session['user_id'],)).fetchone()
    team = dict(team_row) if team_row else None
    solved_ids = set()
    if team:
        solved = conn.execute('SELECT DISTINCT problem_id FROM submissions WHERE team_id=? AND status="Accepted"', (team['id'],)).fetchall()
        solved_ids = {r['problem_id'] for r in solved}
    settings = {}
    for row in conn.execute('SELECT key, value FROM contest_settings'):
        settings[row['key']] = row['value']
    conn.close()
    return render_template('contest.html', problems=problems, team=team, solved_ids=solved_ids, settings=settings)

@app.route('/problem/<int:pid>')
@login_required
def problem_detail(pid):
    conn = get_db()
    problem = conn.execute('SELECT * FROM problems WHERE id=? AND visible=1', (pid,)).fetchone()
    if not problem:
        conn.close()
        return redirect('/contest')
    team_row = conn.execute('SELECT t.* FROM teams t JOIN team_members tm ON t.id=tm.team_id WHERE tm.user_id=?', (session['user_id'],)).fetchone()
    team = dict(team_row) if team_row else None
    past_submissions = []
    if team:
        past_submissions = conn.execute('''
            SELECT * FROM submissions WHERE team_id=? AND problem_id=? ORDER BY submitted_at DESC
        ''', (team['id'], pid)).fetchall()
    clarifications = conn.execute('''
        SELECT c.*, u.username FROM clarifications c 
        JOIN users u ON c.user_id=u.id 
        WHERE c.problem_id=? AND (c.team_id=? OR c.is_public=1) 
        ORDER BY c.created_at DESC
    ''', (pid, team['id'] if team else 0)).fetchall()
    conn.close()
    return render_template('problem.html', problem=problem, team=team, past_submissions=past_submissions, clarifications=clarifications)

@app.route('/submit', methods=['POST'])
@login_required
def submit():
    data = request.get_json()
    conn = get_db()
    status = get_setting('contest_status')
    if status != 'active':
        conn.close()
        return jsonify({'success': False, 'message': 'Contest is not active'})
    team_row = conn.execute('SELECT t.* FROM teams t JOIN team_members tm ON t.id=tm.team_id WHERE tm.user_id=?', (session['user_id'],)).fetchone()
    if not team_row:
        conn.close()
        return jsonify({'success': False, 'message': 'You must be in a team to submit'})
    if team_row['status'] != 'approved':
        conn.close()
        return jsonify({'success': False, 'message': 'Your team is not approved'})
    conn.execute('''
        INSERT INTO submissions (team_id, user_id, problem_id, code, language, status)
        VALUES (?,?,?,?,?,?)
    ''', (team_row['id'], session['user_id'], data['problem_id'], data['code'], data.get('language','python'), 'Pending'))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Solution submitted! Awaiting admin review.'})

# ─── LEADERBOARD ──────────────────────────────────────────────────────────────

@app.route('/leaderboard')
def leaderboard():
    conn = get_db()
    frozen = get_setting('leaderboard_frozen') == '1'
    teams = conn.execute('''
        SELECT t.id, t.name, t.team_code, t.score, t.penalty,
               COUNT(DISTINCT s.problem_id) as solved
        FROM teams t
        LEFT JOIN submissions s ON t.id=s.team_id AND s.status="Accepted"
        WHERE t.status="approved"
        GROUP BY t.id
        ORDER BY t.score DESC, t.penalty ASC
    ''').fetchall()
    settings = {}
    for row in conn.execute('SELECT key, value FROM contest_settings'):
        settings[row['key']] = row['value']
    conn.close()
    return render_template('leaderboard.html', teams=teams, frozen=frozen, settings=settings)

@app.route('/api/leaderboard')
def api_leaderboard():
    conn = get_db()
    teams = conn.execute('''
        SELECT t.id, t.name, t.team_code, t.score, t.penalty,
               COUNT(DISTINCT s.problem_id) as solved
        FROM teams t
        LEFT JOIN submissions s ON t.id=s.team_id AND s.status="Accepted"
        WHERE t.status="approved"
        GROUP BY t.id
        ORDER BY t.score DESC, t.penalty ASC
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in teams])

# ─── SUBMISSIONS ──────────────────────────────────────────────────────────────

@app.route('/submissions')
@login_required
def submissions():
    conn = get_db()
    team_row = conn.execute('SELECT t.* FROM teams t JOIN team_members tm ON t.id=tm.team_id WHERE tm.user_id=?', (session['user_id'],)).fetchone()
    subs = []
    if team_row:
        subs = conn.execute('''
            SELECT s.*, p.title as problem_title FROM submissions s
            JOIN problems p ON s.problem_id=p.id
            WHERE s.team_id=?
            ORDER BY s.submitted_at DESC
        ''', (team_row['id'],)).fetchall()
    conn.close()
    return render_template('submissions.html', submissions=subs)

@app.route('/clarify', methods=['POST'])
@login_required
def clarify():
    data = request.get_json()
    conn = get_db()
    team_row = conn.execute('SELECT t.* FROM teams t JOIN team_members tm ON t.id=tm.team_id WHERE tm.user_id=?', (session['user_id'],)).fetchone()
    if not team_row:
        conn.close()
        return jsonify({'success': False, 'message': 'Must be in a team'})
    conn.execute('INSERT INTO clarifications (team_id, user_id, problem_id, question) VALUES (?,?,?,?)',
                 (team_row['id'], session['user_id'], data.get('problem_id'), data['question']))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Question submitted!'})

@app.route('/api/announcements')
def api_announcements():
    conn = get_db()
    ann = conn.execute('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 10').fetchall()
    conn.close()
    return jsonify([dict(a) for a in ann])

# ─── ADMIN ROUTES ──────────────────────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin():
    conn = get_db()
    stats = {
        'teams': conn.execute('SELECT COUNT(*) as c FROM teams').fetchone()['c'],
        'users': conn.execute('SELECT COUNT(*) as c FROM users WHERE role!="admin"').fetchone()['c'],
        'problems': conn.execute('SELECT COUNT(*) as c FROM problems').fetchone()['c'],
        'submissions': conn.execute('SELECT COUNT(*) as c FROM submissions').fetchone()['c'],
        'pending': conn.execute('SELECT COUNT(*) as c FROM submissions WHERE status="Pending"').fetchone()['c'],
    }
    recent_subs = conn.execute('''
        SELECT s.*, t.name as team_name, p.title as prob_title, u.username
        FROM submissions s
        JOIN teams t ON s.team_id=t.id
        JOIN problems p ON s.problem_id=p.id
        JOIN users u ON s.user_id=u.id
        ORDER BY s.submitted_at DESC LIMIT 20
    ''').fetchall()
    settings = {}
    for row in conn.execute('SELECT key, value FROM contest_settings'):
        settings[row['key']] = row['value']
    conn.close()
    return render_template('admin.html', stats=stats, recent_subs=recent_subs, settings=settings)

@app.route('/admin/teams')
@admin_required
def admin_teams():
    conn = get_db()
    teams = conn.execute('''
        SELECT t.*, COUNT(tm.user_id) as member_count 
        FROM teams t LEFT JOIN team_members tm ON t.id=tm.team_id
        GROUP BY t.id ORDER BY t.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('admin_teams.html', teams=teams)

@app.route('/admin/team/<int:tid>/action', methods=['POST'])
@admin_required
def admin_team_action(tid):
    data = request.get_json()
    action = data.get('action')
    conn = get_db()
    if action == 'approve':
        conn.execute('UPDATE teams SET status="approved" WHERE id=?', (tid,))
    elif action == 'reject':
        conn.execute('UPDATE teams SET status="rejected" WHERE id=?', (tid,))
    elif action == 'disqualify':
        conn.execute('UPDATE teams SET status="disqualified" WHERE id=?', (tid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/problems')
@admin_required
def admin_problems():
    conn = get_db()
    problems = [dict(r) for r in conn.execute('SELECT * FROM problems ORDER BY created_at DESC').fetchall()]
    conn.close()
    return render_template('admin_problems.html', problems=problems)

@app.route('/admin/problem/add', methods=['POST'])
@admin_required
def admin_add_problem():
    data = request.get_json() or request.form
    conn = get_db()
    conn.execute('''
        INSERT INTO problems (title, description, constraints, sample_input, sample_output, difficulty, points, category, visible)
        VALUES (?,?,?,?,?,?,?,?,?)
    ''', (data['title'], data['description'], data.get('constraints',''), data.get('sample_input',''),
          data.get('sample_output',''), data.get('difficulty','Medium'), int(data.get('points',100)),
          data.get('category','Arrays'), int(data.get('visible',0))))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Problem added!'})

@app.route('/admin/problem/<int:pid>/edit', methods=['POST'])
@admin_required
def admin_edit_problem(pid):
    data = request.get_json()
    conn = get_db()
    # Load existing row so partial updates (e.g. visibility toggle) don't wipe other fields
    existing = conn.execute('SELECT * FROM problems WHERE id=?', (pid,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({'success': False, 'message': 'Problem not found'})
    # Merge: incoming data overrides existing values
    title       = data.get('title',        existing['title'])
    description = data.get('description',  existing['description'])
    constraints = data.get('constraints',  existing['constraints'])
    sample_in   = data.get('sample_input', existing['sample_input'])
    sample_out  = data.get('sample_output',existing['sample_output'])
    difficulty  = data.get('difficulty',   existing['difficulty'])
    points      = int(data.get('points',   existing['points']))
    category    = data.get('category',     existing['category'])
    visible     = int(data.get('visible',  existing['visible']))
    conn.execute('''
        UPDATE problems SET title=?, description=?, constraints=?, sample_input=?, sample_output=?,
        difficulty=?, points=?, category=?, visible=? WHERE id=?
    ''', (title, description, constraints, sample_in, sample_out, difficulty, points, category, visible, pid))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/problem/<int:pid>/delete', methods=['POST'])
@admin_required
def admin_delete_problem(pid):
    conn = get_db()
    conn.execute('DELETE FROM problems WHERE id=?', (pid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/problem/upload_csv', methods=['POST'])
@admin_required
def admin_upload_csv():
    file = request.files.get('file')
    if not file:
        return jsonify({'success': False, 'message': 'No file uploaded'})
    content = file.read().decode('utf-8')
    reader = csv.DictReader(io.StringIO(content))
    conn = get_db()
    count = 0
    for row in reader:
        conn.execute('''
            INSERT INTO problems (title, description, constraints, sample_input, sample_output, difficulty, points, category, visible)
            VALUES (?,?,?,?,?,?,?,?,?)
        ''', (row.get('title',''), row.get('description',''), row.get('constraints',''),
              row.get('sample_input',''), row.get('sample_output',''),
              row.get('difficulty','Medium'), int(row.get('points',100)),
              row.get('category','Arrays'), 0))
        count += 1
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'{count} problems imported!'})

@app.route('/admin/submissions')
@admin_required
def admin_submissions():
    conn = get_db()
    team_filter = request.args.get('team', '')
    prob_filter = request.args.get('problem', '')
    status_filter = request.args.get('status', '')
    query = '''
        SELECT s.*, t.name as team_name, p.title as prob_title, u.username
        FROM submissions s
        JOIN teams t ON s.team_id=t.id
        JOIN problems p ON s.problem_id=p.id
        JOIN users u ON s.user_id=u.id
        WHERE 1=1
    '''
    params = []
    if team_filter:
        query += ' AND t.name LIKE ?'; params.append(f'%{team_filter}%')
    if prob_filter:
        query += ' AND p.title LIKE ?'; params.append(f'%{prob_filter}%')
    if status_filter:
        query += ' AND s.status=?'; params.append(status_filter)
    query += ' ORDER BY s.submitted_at DESC'
    subs = conn.execute(query, params).fetchall()
    teams = conn.execute('SELECT DISTINCT name FROM teams').fetchall()
    problems = conn.execute('SELECT DISTINCT title FROM problems').fetchall()
    conn.close()
    return render_template('admin_submissions.html', submissions=subs, teams=teams, problems=problems,
                           team_filter=team_filter, prob_filter=prob_filter, status_filter=status_filter)

@app.route('/admin/submission/<int:sid>/judge', methods=['POST'])
@admin_required
def admin_judge(sid):
    data = request.get_json()
    status = data.get('status')
    score = int(data.get('score', 0))
    notes = data.get('notes', '')
    conn = get_db()
    conn.execute('UPDATE submissions SET status=?, score=?, admin_notes=? WHERE id=?', (status, score, notes, sid))
    # Update team score
    sub = conn.execute('SELECT * FROM submissions WHERE id=?', (sid,)).fetchone()
    if status == 'Accepted':
        # Check if first accepted for this problem
        first = conn.execute('SELECT id FROM submissions WHERE team_id=? AND problem_id=? AND status="Accepted" AND id!=?', 
                             (sub['team_id'], sub['problem_id'], sid)).fetchone()
        if not first:
            conn.execute('UPDATE teams SET score=score+? WHERE id=?', (score, sub['team_id']))
            # Check for first blood globally
            any_first = conn.execute('SELECT id FROM submissions WHERE problem_id=? AND status="Accepted" AND id!=?', 
                                     (sub['problem_id'], sid)).fetchone()
            if not any_first:
                conn.execute('INSERT INTO badges (team_id, badge_type) VALUES (?,?)', (sub['team_id'], 'First Blood'))
    elif status == 'Wrong Answer':
        conn.execute('UPDATE teams SET penalty=penalty+20 WHERE id=?', (sub['team_id'],))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/announce', methods=['POST'])
@admin_required
def admin_announce():
    data = request.get_json()
    conn = get_db()
    conn.execute('INSERT INTO announcements (title, message, type) VALUES (?,?,?)',
                 (data['title'], data['message'], data.get('type','info')))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/contest/control', methods=['POST'])
@admin_required
def admin_contest_control():
    data = request.get_json()
    action = data.get('action')
    if action == 'start':
        set_setting('contest_status', 'active')
        set_setting('contest_start', datetime.now().isoformat())
    elif action == 'pause':
        set_setting('contest_status', 'paused')
    elif action == 'end':
        set_setting('contest_status', 'ended')
    elif action == 'freeze':
        set_setting('leaderboard_frozen', '1')
    elif action == 'unfreeze':
        set_setting('leaderboard_frozen', '0')
    elif action == 'update_settings':
        for key in ['event_name', 'event_tagline', 'contest_start', 'contest_end']:
            if key in data:
                set_setting(key, data[key])
    return jsonify({'success': True, 'status': get_setting('contest_status')})

@app.route('/admin/leaderboard/export')
@admin_required
def export_leaderboard():
    conn = get_db()
    teams = conn.execute('''
        SELECT t.team_code, t.name, t.score, t.penalty,
               COUNT(DISTINCT s.problem_id) as solved
        FROM teams t
        LEFT JOIN submissions s ON t.id=s.team_id AND s.status="Accepted"
        WHERE t.status="approved"
        GROUP BY t.id
        ORDER BY t.score DESC, t.penalty ASC
    ''').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Rank', 'Team Code', 'Team Name', 'Score', 'Problems Solved', 'Penalty'])
    for i, t in enumerate(teams, 1):
        writer.writerow([i, t['team_code'], t['name'], t['score'], t['solved'], t['penalty']])
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=leaderboard.csv'})

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    conn = get_db()
    total_subs = conn.execute('SELECT COUNT(*) as c FROM submissions').fetchone()['c']
    accepted = conn.execute('SELECT COUNT(*) as c FROM submissions WHERE status="Accepted"').fetchone()['c']
    most_solved = conn.execute('''
        SELECT p.title, COUNT(DISTINCT s.team_id) as c FROM submissions s
        JOIN problems p ON s.problem_id=p.id WHERE s.status="Accepted"
        GROUP BY s.problem_id ORDER BY c DESC LIMIT 5
    ''').fetchall()
    hardest = conn.execute('''
        SELECT p.title, 
               SUM(CASE WHEN s.status="Wrong Answer" THEN 1 ELSE 0 END) as wrong,
               SUM(CASE WHEN s.status="Accepted" THEN 1 ELSE 0 END) as correct
        FROM submissions s JOIN problems p ON s.problem_id=p.id
        GROUP BY s.problem_id ORDER BY wrong DESC LIMIT 5
    ''').fetchall()
    team_perf = conn.execute('''
        SELECT t.name, t.score, COUNT(DISTINCT s.problem_id) as solved
        FROM teams t LEFT JOIN submissions s ON t.id=s.team_id AND s.status="Accepted"
        WHERE t.status="approved" GROUP BY t.id ORDER BY t.score DESC LIMIT 10
    ''').fetchall()
    conn.close()
    return render_template('admin_analytics.html', total_subs=total_subs, accepted=accepted,
                           most_solved=most_solved, hardest=hardest, team_perf=team_perf)

@app.route('/admin/clarifications')
@admin_required
def admin_clarifications():
    conn = get_db()
    clarifications = conn.execute('''
        SELECT c.*, t.name as team_name, p.title as prob_title, u.username
        FROM clarifications c
        JOIN teams t ON c.team_id=t.id
        JOIN users u ON c.user_id=u.id
        LEFT JOIN problems p ON c.problem_id=p.id
        ORDER BY c.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('admin_clarifications.html', clarifications=clarifications)

@app.route('/admin/clarification/<int:cid>/answer', methods=['POST'])
@admin_required
def admin_answer_clarification(cid):
    data = request.get_json()
    conn = get_db()
    conn.execute('UPDATE clarifications SET answer=?, is_public=? WHERE id=?',
                 (data['answer'], int(data.get('is_public', 0)), cid))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/contest/status')
def api_contest_status():
    return jsonify({
        'status': get_setting('contest_status'),
        'start': get_setting('contest_start'),
        'end': get_setting('contest_end'),
        'frozen': get_setting('leaderboard_frozen'),
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)