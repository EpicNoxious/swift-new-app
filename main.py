from flask import Flask, request, render_template, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import smtplib
import os

EMAIL = os.environ.get('email')
PASSWORD = os.environ.get('password')

app = Flask(__name__)
app.secret_key = 'DEMO_SWIFT'


##CONNECT TO DB
uri = os.getenv("DATABASE_URL")
if uri and uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)



#LOAD USERS FROM THE TABLE
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    fname = db.Column(db.String(100))
    lname = db.Column(db.String(100))
    contact = db.Column(db.Integer, unique=True)
    address = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(100))

class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    email_id = db.Column(db.String(200), db.ForeignKey('users.email'), nullable=False)
    message = db.Column(db.String(100), nullable=False)

db.create_all()


#MAIN PAGE WITH SIGN UP BUTTON
@app.route("/", methods=['GET', 'POST'])
def home():
    if request.method == "POST" and "index_button" in request.form:
        pass
    if request.method == "POST" and "contact_form" in request.form:
        def send_email(fname, lname, email, contact_number):
            with smtplib.SMTP("smtp.gmail.com", 587) as connection:
                connection.ehlo()
                connection.starttls()
                connection.ehlo()
                connection.login(EMAIL, PASSWORD)
                subject = 'Received your request'
                body = f'Hi! {fname} {lname}, We have received your request and our team will contact you shortly on this number: {contact_number}.'

                msg = f"Subject: {subject}\n\n{body}"
                connection.sendmail(EMAIL, email, msg)
                flash("Your request has been sent successfully")

        fname = request.form["fname"]
        lname = request.form["lname"]
        email = request.form["email"]
        contact_number = request.form["contact_number"]
        send_email(fname, lname, email, contact_number)

    return render_template("index.html")


#SIGN UP PAGE
@app.route("/signup", methods=['GET', 'POST'])
def signup():
    # IF NEW USER
    if request.method == 'POST' and "sign_up_form" in request.form:
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        contact = request.form['contact']
        address = request.form['address']
        email_id = request.form['email_id']
        password = request.form['password']

        if User.query.filter_by(email=email_id).first():
            print(User.query.filter_by(email=email_id).first())
            # User already exists
            # print("You've already signed up with that email, log in instead!")
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('signup'))
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            fname=first_name,
            lname=last_name,
            contact=contact,
            address=address,
            email=email_id,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('select'))
    return render_template("sign_up_login.html")



# LOGIN PAGE
@app.route("/login", methods=['GET', 'POST'])
def login():
    # IF USER EXISTS IN DATABASE
    if request.method == 'POST' and "sign_in_form" in request.form:
        email_id = request.form['email_id']
        password = request.form['password']
        # print(email_id, password)
        user = User.query.filter_by(email=email_id).first()
        if not user:
            flash("That email does not exist, please sign in.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            # print(user.password, password)
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            # print(3)
            login_user(user)
        return redirect(url_for('select'))
    return render_template("login.html")



# SELECT THE REGION AND CATEGORY OF NEWS
@app.route("/select", methods=['GET', 'POST'])
def select():
    # API KEY AND PARAMETERS OF API
    if request.method == 'POST' and "api_form" in request.form:
        API_KEY = os.environ.get('API')
        country = request.form["country"]
        category = request.form["category"]
        return redirect(url_for('api_comment', API_KEY=API_KEY, country=country, category=category))
    return render_template("selection.html")



@app.route("/select/<API_KEY>/<country>/<category>", methods=['GET', 'POST'])
def api_comment(API_KEY, country, category):
    response = requests.get(url=f'https://newsapi.org/v2/top-headlines/sources?category={category}&country={country}&apiKey={API_KEY}')
    articles_data = response.json()["sources"]
    if request.method == 'POST' and "comment_form" in request.form:
        comment = request.form["comment"]
        new_comment = Comment(
            email_id=str(current_user.email),
            message=comment
        )
        db.session.add(new_comment)
        db.session.commit()

        all_comments = Comment.query.all()
        return render_template("news_page.html", articles_data=articles_data, all_comments=all_comments, category=category)
    return render_template("news_page.html", articles_data=articles_data, category=category)

if __name__ == "__main__":
    app.run(debug=True)
