from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Database Configuration (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


# Log Function
def log_action(action, username):
    with open("log.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} - {action} - {username}\n")

@app.route("/view-log")
def view_log():
    try:
        with open("log.txt", "r") as f:
            logs = f.readlines()
        return render_template("view_log.html", logs=logs)
    except FileNotFoundError:
        return "Log file not found."


# Route: Home Page
@app.route("/")
def home():
    return render_template("index.html")


# Route: Sign-Up
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("User already exists!", "danger")
            return redirect(url_for("signup"))

        # Hash password and store user
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        log_action("SIGN-UP", username)
        flash("Sign-up successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")


# Route: Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if user exists
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["user"] = username
            log_action("LOGIN SUCCESS", username)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            log_action("LOGIN FAILED", username)
            flash("Invalid username or password", "danger")

    return render_template("login.html")


# Route: Dashboard (After Login)
@app.route("/dashboard")
def dashboard():
    if "user" in session:
        return f"Welcome, {session['user']}! <br><a href='/logout'>Logout</a>"
    return redirect(url_for("login"))


# Route: Logout
@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully", "info")
    return redirect(url_for("login"))


# Run the App
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database if not exists
    app.run(debug=True)
