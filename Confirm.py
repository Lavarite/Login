from flask import Flask, render_template, request
from flask_mail import Mail, Message
import random

app = Flask(__name__)

# Configure Flask-Mail settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = '19vasylevskyie@mysandstorm.org'
app.config['MAIL_PASSWORD'] = 'w4A3Yds5'
app.config['MAIL_DEFAULT_SENDER'] = '19vasylevskyie@mysandstorm.org'

mail = Mail(app)

confirmation_links = {}

def generate_confirmation_link():
    link = ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))
    return link

def email_search(email):
    result = [(link ,_) for link, _ in confirmation_links.items() if confirmation_links[link][0] == email]
    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/confirm_email/<link>')
def confirm_email(link):
    if link in confirmation_links.keys():
        confirmation_links[link] = (confirmation_links[link][0], 1)
        return render_template('verification_success.html')
    else:
        return render_template('verification_failure.html')

def request_confirmation(email):
    with app.test_request_context():
        link = generate_confirmation_link()
        confirmation_links[link] = (email, 0)
        msg = Message('Confirm Email', recipients=[email], sender=app.config['MAIL_DEFAULT_SENDER'])
        msg.body = f'Please click the following link to confirm your email: http://127.0.0.1:5000/confirm_email/{link}'
        mail.send(msg)
        return render_template('verification_sent.html')