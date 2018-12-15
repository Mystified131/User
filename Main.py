from flask import Flask, request, render_template, session, redirect, flash
from flask_sqlalchemy import SQLAlchemy
import datetime, os, cgi, hashlib, random

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://UserTemplate:Jackson1313@localhost:8889/UserTemplate'
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)
app.secret_key = os.urandom(24)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(120))
    email = db.Column(db.String(120))
    password = db.Column(db.String(120))

    def __init__(self, timestamp, email, password):
        self.timestamp = timestamp
        self.email = email
        self.password = password

def make_salt():
    sal = ""
    for elem in range(5):
        num1 = random.randrange(9)
        num2 = str(num1)
        sal += num2
    return sal
    
def make_pw_hash(password, keynum):
    hashlist = []
    hashlist.append(hashlib.md5(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha1(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha224(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha256(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha384(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha512(str.encode(password)).hexdigest())
    hashlist.append(hashlib.md5(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha224(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha512(str.encode(password)).hexdigest())
    hashlist.append(hashlib.sha1(str.encode(password)).hexdigest())
    hash = hashlist[keynum]
    return hash

def check_pw_hash(password, hash, key):
    hash2 = hash[5:]
    if make_pw_hash(password, key) == hash2:
        return True
    else:
        return False

@app.before_request
def require_login():
    allowed_routes = ['login', 'signup']
    if request.endpoint not in allowed_routes and 'email' not in session:
        return redirect('/login')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        timestr = user.timestamp
        xnum = timestr[19]
        key = int(xnum)
        if user and check_pw_hash(password, user.password, key):
            session['email'] = email
            #flash("Logged in")
            return redirect('/index')
        elif not user:
            flash("User does not exist")
            return redirect('/signup')
        else:
            flash('User password incorrect')
    return render_template('login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        verify = request.form['verify']
        if not email or not password or not verify:
            flash("Please fill in all form spaces")
            return redirect('/signup')
        if password != verify:
            flash("Password and Password Verify fields do not match")
            return redirect('/signup')
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            right_now = datetime.datetime.now().isoformat()
            list = []
            for i in right_now:
                if i.isnumeric():
                    list.append(i)
            timestam = "".join(list)
            timestamp = str(timestam)
            key = list[19]
            salt = make_salt()
            keynm = random.randrange(6)
            hash = make_pw_hash(password, keynm)
            keyst = str(keynm)
            password = salt + hash
            new_user = User(timestamp, email, password)
            db.session.add(new_user)
            db.session.commit()
            session['email'] = email
            flash("Signed In")
            return redirect('/index')
        else:
            flash('Duplicate User')
            return redirect('/signup')

    return render_template('signup.html')

@app.route('/logout')
def logout():
    del session['email']
    return redirect('/login')

@app.route("/index", methods =['GET', 'POST'])
def index():
    right_now = datetime.datetime.now().isoformat()
    list = []

    for i in right_now:
        if i.isnumeric():
           list.append(i)

    tim = "".join(list)
    session['timestamp'] = tim
    return render_template('index.html', time = tim)

@app.route("/login", methods =['GET', 'POST'])
def frontpage():
    return render_template('login.html')

## THE GHOST OF THE SHADOW ##

if __name__ == '__main__':
    app.run()



