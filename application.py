import os

from flask import Flask, session
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from flask import render_template, flash, redirect, url_for, logging, request
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt


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


@app.route("/")
def index():
    return render_template('home.html')


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [
        validators. DataRequired(),
        validators.EqualTo('confirm', message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')


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

        if len(list(result)) > 0:
            # get stored hash
            data = result.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_candidate, password):
                app.logger.info("Password matched")

        else:
            app.logger.info("No user")

        print(f"user {username} selected!")
        db.commit()

    return render_template('login.html')


@app.route("/<string:name>")
def hello(name):
    return f"hello {name}"
