from flask import Flask, render_template, request, jsonify, session, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from decouple import config

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/login_system'
app.secret_key = config('APP_SECRET_KEY')
db = SQLAlchemy(app)

class Users(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime(), nullable=False, default=datetime.now())

    def __init__(self, email, password):
        self.email = email
        self.password = password

@app.route("/")
def home():
    if 'user' in session:
        return redirect('/welcome')
    else:
        return render_template("index.html")

@app.route("/login")
def login():
    if 'user' in session:
        return redirect('/welcome')
    else:
        return render_template("login.html")

@app.route("/welcome")
def welcome():
    if 'user' in session:
        return render_template("welcome.html")
    else:
        return redirect("/login")

@app.route("/logout")
def logout():
    if 'user' in session:
        session.pop('user')
        return redirect("/login")
    else:
        return redirect("/login")

@app.route("/handlesignup", methods=["GET", "POST"])
def handlesignup():
    if request.method == "POST":
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        if len(email) < 5:
            return jsonify({"status": "error", "message": "Please enter a valid email!"})

        elif Users.query.filter_by(email=email).first():
            return jsonify({"status": "error", "message": "This email is already in use!"})

        elif len(password1) < 8:
            return jsonify({"status": "error", "message": "Password must contain atleast 8 characters!"})

        elif password1.isalnum() or password1.isalpha() or password1.isnumeric():
            return jsonify({"status": "error", "message": "Password must contain alphabets, numbers and special characters!"})

        elif (password1!= password2):
            return jsonify({"status": "error", "message": "Password and confirm password should match!"})

        else:
            hashed_password = generate_password_hash(password1, method='sha256')
            new_user = Users(email, hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"status": "success", "message": "Your account has been created successfully!"})
    else:
        return "<h1>(400) Bad Request</h1>"

@app.route("/handlelogin", methods=["GET", "POST"])
def handlelogin():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = Users.query.filter_by(email=email).first()

        if not email or not password:
            return jsonify({"status": "error", "message": "Please enter your credential details!"})
        if not user or not check_password_hash(user.password, password):
            return jsonify({"status": "error", "message": "Invalid credentials!"})
        else:
            session['user'] = email
            return jsonify({"status": "success", "message": "You have been loggedin successfully!"})
    else:
        return "<h1>(400) Bad Request</h1>"

if __name__ == "__main__":
    app.run(debug=True)