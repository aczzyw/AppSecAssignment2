from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, IntegerField, TextAreaField
from wtforms.validators import InputRequired, Length, Optional, NumberRange
from flask_sqlalchemy  import SQLAlchemy
from sqlalchemy import exc
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import phonenumbers
import subprocess
import os
import re


app = Flask(__name__)
app.config['SECRET_KEY'] = 'b_5#y2_^+LF4Q8z#n$xec]/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database table
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(20))
    phone = db.Column(db.String(15), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired(), Length(min=1)])
    pword = PasswordField('password', validators=[InputRequired(), Length(min=8)])
    phone = IntegerField('phone', validators=[Optional()], id='2fa')

class LoginForm(FlaskForm):
    uname = StringField('username', validators=[InputRequired(),Length(min=1)])
    pword = PasswordField('password', validators=[InputRequired(), Length(min=8)])
    phone = IntegerField('phone', validators=[Optional()], id='2fa')

class SpellcheckForm(FlaskForm):
    inputtext = TextAreaField('Input Text', id='inputtext')
    textout = TextAreaField('Output Text', id='textout')
    misspelled = TextAreaField('Misspelled Text', id='misspelled')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    outcome = ''
    if current_user.is_authenticated:
        return redirect(url_for('spell_check'))

    form = RegisterForm()

    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.pword.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User(username=form.uname.data, password=hashed_password, phone=form.phone.data)
            db.session.add(new_user)
            db.session.commit()
            outcome = 'success'
            return render_template('register.html', form=form, outcome=outcome)
            #return redirect(url_for('login'))
        except exc.IntegrityError:
            db.session.rollback()
            outcome = 'failure: user exist'
            return render_template('register.html', form=form, outcome=outcome)
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    outcome = ''
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.uname.data).first()
        if user:
            if check_password_hash(user.password, form.pword.data):
                if (int((user.phone)) == form.phone.data):
                    # outcome = 'success'
                    login_user(user)
                    # return render_template('login.html', form=form, outcome=outcome)
                    return redirect(url_for('spell_check'))
                else:
                    outcome = 'Two-factor failure'
                    return render_template('login.html', form=form, outcome=outcome)
            else:
                outcome = 'Incorrect'
                return render_template('login.html', form=form, outcome=outcome)
        else:
            outcome = 'Incorrect'
            return render_template('login.html', form=form, outcome=outcome)

    return render_template('login.html', form=form, outcome=outcome)

@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    if current_user.is_authenticated:
        form = SpellcheckForm()
        if form.validate_on_submit():
            inputtext = form.inputtext.data

            lines = inputtext.split('\n')
            f = open('check_words.txt', 'w')
            f.writelines(lines)
            f.close()

            p = subprocess.run(['./app/a.out', './app/check_words.txt', './app/wordlist.txt'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            msg = p.stdout.decode('utf-8')
            msg = msg.replace('\n', ', ')
            msg = msg.rstrip(', ')
            
            textout = '\n'.join(lines)
            misspelled = msg
            # print(textout)
            # print(misspelled)
            return render_template('spellcheck.html', form=form, textout=textout, misspelled=misspelled)

        outcome = 'success'
        return render_template('spellcheck.html', form=form, outcome=outcome)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

#if __name__ == '__main__':
#    app.run(debug=True)
