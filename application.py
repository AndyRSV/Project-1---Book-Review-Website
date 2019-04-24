import os

from flask import Flask, session
from flask_session import Session
from sqlalchemy import create_engine, select
from sqlalchemy.orm import scoped_session, sessionmaker
from flask import render_template, flash, redirect, url_for, logging, request
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))


# App index
@app.route("/")
def index():
    return render_template('home.html')

# Register form class


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators. DataRequired(),
        validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')


# user register function
@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # insert data in db
        db.execute(
            "INSERT INTO users (name, username, password) VALUES (:n, :u, :p)",
            {"n": name, "u": username, "p": password})

        print("New user created")
        db.commit()

        flash("You are now registered and can log in!", "success")
        return redirect(url_for('index'))

    return render_template('register.html', form=form)


# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # if is submitted, get the username & pass from form
        username = request.form['username']
        password_candidate = request.form['password']

        result = db.execute(
            "SELECT * FROM users WHERE username = :u", {"u": username}
        )

        # for row in result:
        #     print(row)

        # print(result.keys())
        # print(result.fetchone()['password'])

        # get the number of rows
        if result.rowcount > 0:
            # get stored hash
            data = result.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_candidate, password):
                app.logger.info("Password matched")
                print(f"user {username} selected!")

                # Passed, we session variable for information about the user
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))

            else:
                app.logger.info("Password not matched")
                error = 'Invalid login, password did not matched'
                return render_template('login.html', error=error)

            db.commit()
            # db.close()

        else:
            app.logger.info("No user")
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Decorator (special function to be add to any route): check if user logged in
# in this case we want to use it on the Dashboard function/route
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unothorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap


# User logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# User Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


@app.route("/<string:name>")
def hello(name):
    return f"hello {name}"
