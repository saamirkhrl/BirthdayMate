from flask import Flask, render_template, url_for, request, flash, redirect
from wtforms import StringField, PasswordField, EmailField, SubmitField, DateField, MonthField, IntegerField
from flask_sqlalchemy import SQLAlchemy
import os
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Length
from datetime import datetime
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_login import UserMixin, logout_user, login_user, LoginManager, login_required, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.urandom(150)

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'about'
@login_manager.user_loader
def load_user(userid):
    return User.query.get(int(userid))

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    birthdays = db.relationship('Birthday', backref='user', lazy=True)

    def __repr__(self):
        return f'ID: {self.id}, Email: {self.email}, Username: {self.username}'

class Birthday(db.Model):
    __tablename__ = 'birthday'
    id = db.Column(db.Integer, primary_key=True)
    month = db.Column(db.String, nullable=False)
    day = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.String(150), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'ID: {self.id}, Title: {self.title}, Content: {self.content}, Day: {self.day}, Month: {self.month}, Year: {self.year}'

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={'placeholder': "Type your username.."})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'placeholder': "Type your password.."})
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Length(3,50)], render_kw={'placeholder': 'Enter your email..'})
    username = StringField('Username', validators=[DataRequired(), Length(3, 25)], render_kw={'placeholder': "Choose your username.."})
    password = PasswordField('Password', validators=[DataRequired(), Length(7, 150)], render_kw={'placeholder': "Choose a password.."})
    password2 = PasswordField('Confirm password', validators=[DataRequired(), Length(7, 150)], render_kw={'placeholder': "Confirm your password.."})
    submit = SubmitField('Sign up')

from wtforms import StringField, IntegerField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length

class BirthdayForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(1, 20)], render_kw={'placeholder': 'Give your event a name'})
    content = StringField('Content', validators=[Length(1, 150)], render_kw={'placeholder': 'Any notes for this event?'})
    
    month = SelectField('Month', choices=[
        ('1', 'January'), ('2', 'February'), ('3', 'March'), ('4', 'April'),
        ('5', 'May'), ('6', 'June'), ('7', 'July'), ('8', 'August'),
        ('9', 'September'), ('10', 'October'), ('11', 'November'), ('12', 'December')
    ], validators=[DataRequired()])
    day = SelectField('Day', choices=[(str(i), str(i)) for i in range(1, 32)], validators=[DataRequired()])
    year = IntegerField('Year', validators=[DataRequired(), Length(min=4, max=4)], render_kw={'placeholder': 'Year (e.g., 2024)'})
    submit = SubmitField('Add Event!')


@app.route('/dashboard', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
@login_required
def dashboard():
    current_events = Birthday.query.filter_by(user_id=current_user.id).all()

    for event in current_events:
        event_date = datetime(event.year, int(event.month), event.day)
        days_until_event = (event_date - datetime.now()).days
        event.days_until_event = days_until_event

    return render_template('dashboard.html', events=current_events)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form=BirthdayForm()
    if request.method == "POST":
        title = request.form.get('title')
        content = request.form.get('content')
        day = request.form.get('day')
        month = request.form.get('month')
        year = request.form.get('year')

        new_event = Birthday(title=title, content=content, day=day, month=month, year=year, user_id=current_user.id)
        db.session.add(new_event)
        db.session.commit()

        flash('Created a new event!', category='success')
        return redirect(url_for('dashboard'))

    return render_template('create.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in', category='success')
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username or password, try again.', category='danger')

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        password2 = request.form.get('email')
        user = User.query.filter_by(username=username).first()

        if user:
            flash('Username already exists', category='danger')
        elif password != password2:
            flash('Both passwords must match', category='danger')
        elif User.query.filter_by(email=email).first():
            flash('Email is already connected to an account', category='danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(email=email, username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash(f'Account created! Welcome, {username}', category='success')
            return redirect(url_for('login'))
        

    return render_template('register.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash('Logged out', category='success')
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)