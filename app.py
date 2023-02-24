import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

import datetime
from flask import *

# Configure application
app = Flask(__name__)

@app.route('/')
def hello():
    return render_template("index.html")

