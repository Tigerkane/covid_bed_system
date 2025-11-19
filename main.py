# redeploy-fix 2025-11-19T22:23:12.9352629+05:30
import os
import sys
import logging
from flask import Flask, redirect, render_template, flash, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, logout_user, login_user, LoginManager, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql

# ensure pymysql is available for SQLAlchemy when using mysql
pymysql.install_as_MySQLdb()

# basic logging to stdout (Render shows stdout/stderr in logs)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# Application config
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "shreyas")

# Prefer a single DATABASE_URL env var. If absent, try DB_USER/DB_PASS/DB_HOST/DB_NAME.
db_url = os.environ.get("DATABASE_URL") or os.environ.get("SQLALCHEMY_DATABASE_URI")

if not db_url:
    db_user = os.environ.get("DB_USER")
    db_pass = os.environ.get("DB_PASS")
    db_host = os.environ.get("DB_HOST")
    db_name = os.environ.get("DB_NAME")

    # If user provided individual DB_* vars, build a mysql connection string.
    if db_user and db_pass and db_host and db_name:
        # make sure pymysql dialect is included
        db_url = f"mysql+pymysql://{db_user}:{db_pass}@{db_host}/{db_name}"
    else:
        # fallback to sqlite for quick demo (ephemeral on Render)
        db_url = "sqlite:///data.db"
        log.info("No DATABASE_URL or DB_* env vars found â€” falling back to sqlite (data is ephemeral).")

# If someone provided a mysql URL without driver, ensure pymysql is present
if db_url.startswith("mysql://"):
    db_url = "mysql+pymysql://" + db_url[len("mysql://"):]

# Store in Flask config
app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Log non-sensitive connection info (mask credentials)
def masked_db_info(url: str) -> str:
    try:
        # very small parser â€” only for logging; doesn't expose password
        if "@" in url:
            left, right = url.split("@", 1)
            if "://" in left:
                proto, creds = left.split("://", 1)
                if ":" in creds:
                    user, _ = creds.split(":", 1)
                    return f"{proto}://{user}:***@{right}"
        return url
    except Exception:
        return "unknown"

log.info(f"Using database: {masked_db_info(db_url)}")
log.info(f"Python executable: {sys.executable}")

# check cryptography presence (auth plugin issues)
try:
    import cryptography  # noqa: F401
    log.info("cryptography available")
except Exception:
    log.info("cryptography not available (may be required for some MySQL auth methods)")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Models (same as your original)
class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    srfid = db.Column(db.String(20), unique=True, nullable=True)
    email = db.Column(db.String(50), nullable=True)
    dob = db.Column(db.String(1000), nullable=True)

class Hospitaluser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hcode = db.Column(db.String(20), nullable=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Hospitaldata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hcode = db.Column(db.String(20), unique=True, nullable=False)
    hname = db.Column(db.String(100), nullable=True)
    normalbed = db.Column(db.Integer, default=0)
    hicubed = db.Column(db.Integer, default=0)
    icubed = db.Column(db.Integer, default=0)
    vbed = db.Column(db.Integer, default=0)

class Trig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hcode = db.Column(db.String(20))
    normalbed = db.Column(db.Integer)
    hicubed = db.Column(db.Integer)
    icubed = db.Column(db.Integer)
    vbed = db.Column(db.Integer)
    querys = db.Column(db.String(50))
    date = db.Column(db.String(50))

class Bookingpatient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    srfid = db.Column(db.String(20), nullable=False)
    bedtype = db.Column(db.String(100), nullable=True)
    hcode = db.Column(db.String(20), nullable=True)
    spo2 = db.Column(db.Integer, nullable=True)
    pname = db.Column(db.String(100), nullable=True)
    pphone = db.Column(db.String(100), nullable=True)
    paddress = db.Column(db.String(100), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    try:
        uid = int(user_id)
    except Exception:
        return None
    user = User.query.get(uid)
    if user:
        return user
    return Hospitaluser.query.get(uid)

# All your routes (copied with no logic changes)
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/trigers")
def trigers():
    q = Trig.query.all()
    return render_template("trigers.html", query=q)

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        srfid = (request.form.get('srf') or "").strip()
        email = (request.form.get('email') or "").strip()
        dob = (request.form.get('dob') or "").strip()
        if not srfid or not email:
            flash("SRF and Email required", "warning")
            return render_template("usersignup.html")
        if User.query.filter_by(srfid=srfid).first() or User.query.filter_by(email=email).first():
            flash("Email or SRF ID already taken", "warning")
            return render_template("usersignup.html")
        new_user = User(srfid=srfid, email=email, dob=dob)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful. Please log in", "success")
        return redirect(url_for('login'))
    return render_template("usersignup.html")

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        srfid = (request.form.get('srf') or "").strip()
        dob = (request.form.get('dob') or "").strip()
        user = User.query.filter_by(srfid=srfid).first()
        if user and user.dob == dob:
            login_user(user)
            flash("Login successful", "info")
            return redirect(url_for('home'))
        flash("Invalid credentials", "danger")
        return render_template("userlogin.html")
    return render_template("userlogin.html")

@app.route('/hospitallogin', methods=['POST', 'GET'])
def hospitallogin():
    if request.method == "POST":
        email = (request.form.get('email') or "").strip()
        password = (request.form.get('password') or "").strip()
        user = Hospitaluser.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful", "info")
            return redirect(url_for('home'))
        flash("Invalid credentials", "danger")
        return render_template("hospitallogin.html")
    return render_template("hospitallogin.html")

@app.route('/admin', methods=['POST', 'GET'])
def admin():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        if username == "admin" and password == "admin":
            session['user'] = username
            flash("Login successful", "info")
            return render_template("addHosUser.html")
        flash("Invalid credentials", "danger")
    return render_template("admin.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout successful", "warning")
    return redirect(url_for('login'))

@app.route('/addHospitalUser', methods=['POST', 'GET'])
def hospitalUser():
    if 'user' in session and session['user'] == "admin":
        if request.method == "POST":
            hcode = (request.form.get('hcode') or "").strip().upper()
            email = (request.form.get('email') or "").strip()
            password = (request.form.get('password') or "").strip()
            if Hospitaluser.query.filter_by(email=email).first():
                flash("Email already exists", "warning")
                return render_template("addHosUser.html")
            hashed = generate_password_hash(password)
            u = Hospitaluser(hcode=hcode, email=email, password=hashed)
            db.session.add(u)
            db.session.commit()
            flash("Data inserted", "success")
            return render_template("addHosUser.html")
        return render_template("addHosUser.html")
    flash("Please login as admin", "warning")
    return redirect(url_for('admin'))

@app.route("/test")
def test():
    try:
        a = Test.query.all()
        log.info(f"Test rows: {len(a)}")
        return 'My database is connected'
    except Exception as e:
        log.exception("DB connection test failed")
        return f"My database is not connected: {e}"

@app.route("/logoutadmin")
def logoutadmin():
    session.pop('user', None)
    flash("Admin logged out", "primary")
    return redirect('/admin')

@app.route("/addhospitalinfo", methods=['POST', 'GET'])
@login_required
def addhospitalinfo():
    if not isinstance(current_user._get_current_object(), Hospitaluser):
        flash("Please login as hospital user", "warning")
        return redirect(url_for('hospitallogin'))
    posts = Hospitaluser.query.filter_by(email=current_user.email).first()
    code = posts.hcode if posts else None
    postsdata = Hospitaldata.query.filter_by(hcode=code).first() if code else None
    if request.method == "POST":
        hcode = (request.form.get('hcode') or "").strip().upper()
        hname = (request.form.get('hname') or "").strip()
        try:
            nbed = int(request.form.get('normalbed') or 0)
            hbed = int(request.form.get('hicubeds') or 0)
            ibed = int(request.form.get('icubeds') or 0)
            vbed = int(request.form.get('ventbeds') or 0)
        except ValueError:
            flash("Bed counts must be numbers", "warning")
            return render_template("hospitaldata.html", postsdata=postsdata)
        if Hospitaldata.query.filter_by(hcode=hcode).first():
            flash("Data already exists. You can update it", "primary")
            return render_template("hospitaldata.html", postsdata=postsdata)
        if not Hospitaluser.query.filter_by(hcode=hcode).first():
            flash("Invalid hospital code", "warning")
            return redirect(url_for('addhospitalinfo'))
        query = Hospitaldata(hcode=hcode, hname=hname, normalbed=nbed, hicubed=hbed, icubed=ibed, vbed=vbed)
        db.session.add(query)
        db.session.commit()
        flash("Data added", "primary")
        return redirect(url_for('addhospitalinfo'))
    return render_template("hospitaldata.html", postsdata=postsdata)

@app.route("/hedit/<int:id>", methods=['POST', 'GET'])
@login_required
def hedit(id):
    post = Hospitaldata.query.filter_by(id=id).first()
    if request.method == "POST":
        hcode = (request.form.get('hcode') or "").strip().upper()
        hname = (request.form.get('hname') or "").strip()
        try:
            nbed = int(request.form.get('normalbed') or 0)
            hbed = int(request.form.get('hicubeds') or 0)
            ibed = int(request.form.get('icubeds') or 0)
            vbed = int(request.form.get('ventbeds') or 0)
        except ValueError:
            flash("Bed counts must be numbers", "warning")
            return render_template("hedit.html", posts=post)
        if not post:
            flash("Record not found", "danger")
            return redirect(url_for('addhospitalinfo'))
        post.hcode = hcode
        post.hname = hname
        post.normalbed = nbed
        post.hicubed = hbed
        post.icubed = ibed
        post.vbed = vbed
        db.session.commit()
        flash("Slot updated", "info")
        return redirect(url_for('addhospitalinfo'))
    return render_template("hedit.html", posts=post)

@app.route("/hdelete/<int:id>", methods=['POST', 'GET'])
@login_required
def hdelete(id):
    post = Hospitaldata.query.filter_by(id=id).first()
    if post:
        db.session.delete(post)
        db.session.commit()
        flash("Data deleted", "danger")
    else:
        flash("Record not found", "warning")
    return redirect(url_for('addhospitalinfo'))

@app.route("/pdetails", methods=['GET'])
@login_required
def pdetails():
    if not hasattr(current_user, 'srfid') or not current_user.srfid:
        flash("Access denied", "warning")
        return redirect(url_for('login'))
    code = current_user.srfid
    data = Bookingpatient.query.filter_by(srfid=code).first()
    return render_template("detials.html", data=data)

@app.route("/slotbooking", methods=['POST', 'GET'])
@login_required
def slotbooking():
    hospitals = Hospitaldata.query.all()
    if request.method == "POST":
        srfid = (request.form.get('srfid') or "").strip()
        bedtype = (request.form.get('bedtype') or "").strip()
        hcode = (request.form.get('hcode') or "").strip().upper()
        spo2 = (request.form.get('spo2') or "").strip()
        pname = (request.form.get('pname') or "").strip()
        pphone = (request.form.get('pphone') or "").strip()
        paddress = (request.form.get('paddress') or "").strip()
        if not hcode:
            flash("Please select a hospital", "warning")
            return render_template("booking.html", hospitals=hospitals)
        hospital_row = Hospitaldata.query.filter_by(hcode=hcode).first()
        if not hospital_row:
            flash(f"Invalid hospital code: {hcode}", "warning")
            return render_template("booking.html", hospitals=hospitals)
        if Bookingpatient.query.filter_by(srfid=srfid).first():
            flash("SRF ID already registered", "warning")
            return render_template("booking.html", hospitals=hospitals)
        if bedtype == "NormalBed":
            available = hospital_row.normalbed or 0
        elif bedtype == "HICUBed":
            available = hospital_row.hicubed or 0
        elif bedtype == "ICUBed":
            available = hospital_row.icubed or 0
        elif bedtype == "VENTILATORBed":
            available = hospital_row.vbed or 0
        else:
            available = 0
        if available <= 0:
            flash("No available beds of that type", "danger")
            return render_template("booking.html", hospitals=hospitals)
        try:
            if bedtype == "NormalBed":
                hospital_row.normalbed -= 1
            elif bedtype == "HICUBed":
                hospital_row.hicubed -= 1
            elif bedtype == "ICUBed":
                hospital_row.icubed -= 1
            elif bedtype == "VENTILATORBed":
                hospital_row.vbed -= 1
            booking = Bookingpatient(
                srfid=srfid,
                bedtype=bedtype,
                hcode=hcode,
                spo2=int(spo2) if spo2.isdigit() else None,
                pname=pname,
                pphone=pphone,
                paddress=paddress
            )
            db.session.add(booking)
            db.session.commit()
            flash("Slot booked. Visit hospital for further steps", "success")
            return redirect(url_for('slotbooking'))
        except Exception as e:
            db.session.rollback()
            log.exception("Error while booking")
            flash("Something went wrong while booking. Try again.", "danger")
            return render_template("booking.html", hospitals=hospitals)
    return render_template("booking.html", hospitals=hospitals)

# Create tables at import time inside an app context so gunicorn workers have schema available.
# This is safe for small apps and avoids relying on __main__ or decorators that may behave differently
# in different WSGI import paths.
try:
    with app.app_context():
        db.create_all()
        log.info("Database tables created/checked (import-time).")
except Exception:
    log.exception("Error creating database tables at import-time")

# Startup: also attempt to create tables when running directly (keeps local dev behaviour).
if __name__ == "__main__":
    try:
        with app.app_context():
            db.create_all()
            log.info("Database tables created/checked.")
    except Exception:
        log.exception("Error creating database tables")

    # If running the file directly, bind to PORT env var (Render uses $PORT). In production use Procfile + gunicorn.
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)




