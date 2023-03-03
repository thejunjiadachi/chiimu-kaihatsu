import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import login_required

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Log user in
@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget any user_id
    session.clear()

    # Ensure user reached route via POST
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username / password were submitted
        if not username:
            flash("ユーザーネームを入力してください")
            return render_template("login.html")
        elif not password:
            flash("パスワードを入力してください")
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 1:
            flash("存在しないユーザーネームです")
            return render_template("login.html")
        elif not check_password_hash(rows[0]["password"], password):
            flash("パスワードが一致しませんでした")
            return render_template("login.html")

        # Remember who has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to top page
        return redirect("/")

    else:
        return render_template("login.html")


# Log user out
@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()

    # Redirect user to top page
    return redirect("/")


# Register user
@app.route("/register", methods=["GET", "POST"])
def register():
    # Ensure user reached route via POST
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username / password / confirmation were submitted
        if not username:
            flash("ユーザーネームを入力してください")
            return render_template("login.html")
        elif not password or not confirmation:
            flash("パスワードを入力してください")
            return render_template("login.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure username exists and password is correct
        if len(rows) != 0:
            flash("既に存在しているユーザーネームです")
            return render_template("login.html")
        elif password != confirmation:
            flash("再入力したパスワードと一致していません")
            return render_template("login.html")

        # Convert password into hashed one and Register user in database
        hash = generate_password_hash(password)
        user_id = db.execute("INSERT INTO users (username, password) VALUES (?, ?)", username, hash)

        # Keep login
        session["user_id"] = user_id

        # Redirect user to top page
        return redirect("/")

    else:
        return render_template("login.html")


# Look up cafes which matched the conditions
@app.route("/", methods=["GET", "POST"])
def lookup():
    # Ensure user reached route via POST
    if request.method == "POST":
        prefecture = request.form.get("prefectures")

        # Query database for prefecture
        rows = db.execute("SELECT * FROM cafes WHERE prefecture = ?", prefecture)

        return render_template("index.html", rows=rows)
    else:
        return render_template("index.html")
