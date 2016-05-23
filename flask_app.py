import logging
import os
import pyotp
import re
import requests
import sys
from decorators import admin_required, check_bans
from flask import Flask, g, redirect, render_template, request, send_from_directory, session, url_for
from flask.ext.heroku import Heroku
from forms import BanIPForm, FilterForm, LoginForm, SubmissionForm
from models import db, IPBan, Settings, Submission

# Flask initialization and some other config stuff
app = Flask(__name__)
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

if os.environ['PRODUCTION'] == 'TRUE':
    heroku = Heroku(app)
else:
    app.debug=True
    BASE_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = '{0}{1}'.format('sqlite:///', os.path.join(BASE_DIRECTORY, 'app.db'))

db.init_app(app)

@app.before_first_request
def startup():

    # db initializations
    db.create_all()
    settings = Settings(secret_key=pyotp.random_base32())
    db.session.add(settings)
    db.session.commit()

@app.before_request
def load_globals():
    # load admin
    try:
        if session["admin"]:
            g.admin = True
        else:
            g.admin = False
    except KeyError:
        g.admin = False
    # load global settings
    g.settings = Settings.query.limit(1).first()


@app.route('/', methods=['GET', 'POST'])
@check_bans
def submit():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    form = SubmissionForm(request.form)
    if request.method=='POST':
        text = form.body.data

        try:
            if session['qb'] == True:
                status = 'quietbanremoval'
                submission = Submission(body=text, ip=ip, u_a=request.user_agent.string, status=status)
                db.session.add(submission)
                db.session.commit()
        except KeyError: # if a KeyError is thrown, the user is not quietbanned.
            pass

        # search to see if the post contains any filtered expressions
        exp = re.compile(g.settings.regex_filter)
        if exp.search(text):
            status='autoremoval'
        else:
            status = 'unset'

        submission = Submission(body=text, ip=ip, u_a=request.user_agent.string, status=status)
        db.session.add(submission)
        db.session.commit()
        return render_template("submit.html", form=form, admin=g.admin, message=True)
    else:
        return render_template('submit.html', form=form, admin=g.admin)

@app.route('/adminon', methods=['GET', 'POST'])
@check_bans
def admin_on():
    '''turns the admin mode on'''
    form = LoginForm(request.form)
    if request.method == 'GET':
        return render_template("login_form.html", form=form)
    elif request.method == 'POST':
        password = int(form.password.data)
        totp = pyotp.TOTP(g.settings.secret_key)
        if totp.verify(password):
            g.settings.shown = True
            db.session.commit()
            session['admin'] = True
            g.admin = True
            return redirect(url_for('admin'))
        return render_template("login_form.html", form=form, failure=True)

@app.route('/adminoff')
@admin_required
def admin_off():
    '''turns admin mode off'''
    session['admin'] = None
    g.admin = False
    return "admin disabled"

@app.route('/admin')
@admin_required
def admin():
    '''returns a listing of all posts'''
    if request.args.get('status'):
        results = Submission.query.filter_by(status=request.args.get('status'))
    elif request.args.get('ip'):
        results = Submission.query.filter_by(status=request.args.get('ip'))
    else:
        results = Submission.query.all()
    return render_template("admin_view.html", results=results)

@app.route('/approve/<int:post_id>/')
@admin_required
def approve(post_id):
    '''approves a specific post - not meant to be viewed, only for requests'''
    post = Submission.query.filter_by(id = post_id).first()
    post_to_ifttt(post.body)
    post.status='approved'
    db.session.commit()
    return "success"

@app.route('/reject/<int:post_id>/')
@admin_required
def reject(post_id):
    '''rejects a specific post - not meant to be viewed, only for requests'''
    submission = Submission.query.filter_by(id = post_id).first()
    submission.status = "removed"
    db.session.commit()
    return "removed"

@app.route('/iplisting')
def list_ips():
    filter_ip = request.args.get('ip')
    current = request.args.get('active')
    if filter_ip != None:
        results = IPBan.query.filter_by(ip=filter_ip)
    elif current != None:
        results = IPBan.query.filter_by(active=current)
    else:
        results = IPBan.query.all()
    return render_template("ip_listing.html", results=results)

@app.route('/banip', methods=['GET', 'POST'])
def ban_ip():
    form = BanIPForm(request.form)
    if request.method=='GET':
        return render_template("ban_ip.html", form=form)
    else:
        ip = IPBan(ip=form.ip.data, ban_type=form.ban_type.data, ban_note_private=form.private_ban_note.data, ban_note_public=form.public_ban_note.data, duration=form.expiration.data)
        db.session.add(ip)
        db.session.commit()
        return redirect(url_for('list_ips'))

@app.route('/editip/<int:ip_id>/', methods=['GET', 'POST'])
def edit_ip(ip_id):
    form = BanIPForm(request.form)
    if request.method=='GET':
        ip = IPBan.query.filter_by(id=ip_id).first()
        if ip:
            form.ip.data = ip.ip
            form.ban_type.data = ip.ban_type
            form.private_ban_note.data = ip.ban_note_private
            form.public_ban_note.data = ip.ban_note_public
            form.expiration.data = ip.duration
        return render_template("ban_ip.html", form=form)
    elif request.method=='POST':
        item = IPBan.query.filter_by(id=ip_id).first()
        item.ip=form.ip.data
        item.ban_type=form.ban_type.data
        item.ban_note_private=form.private_ban_note.data
        item.ban_note_public=form.public_ban_note.data
        item.duration=form.expiration.data
        db.session.commit()
        return redirect(url_for('list_ips'))

@app.route('/unbanip/<int:ip_id>/')
@admin_required
def unban_ip(ip_id):
    obj = IPBan.query.filter_by(id=ip_id).first()
    obj.active = False
    db.session.commit()
    return "unbanned"

@app.route('/simplebanip/<int:ip_id>/')
@admin_required
def simple_ban_ip(ip_id):
    '''sets a ban as active again for ip listing'''
    obj = IPBan.query.filter_by(id=ip_id).first()
    obj.active = True
    db.session.commit()
    return "banned"

@app.route('/getga')
def get_google_authenticator():
    if g.settings.shown == False:
        totp = pyotp.TOTP(g.settings.secret_key)
        return "<img src='http://chart.apis.google.com/chart?cht=qr&chs=500x500&chl={0}'>".format(totp.provisioning_uri("admin"))
    else:
        return redirect(url_for('admin_on'))

@app.route('/dashboard')
@admin_required
def dashboard():
    totp = pyotp.TOTP(g.settings.secret_key)
    uri = totp.provisioning_uri("admin")
    return render_template("dashboard.html", uri=uri)

@app.route('/filter', methods=["GET", "POST"])
@admin_required
def edit_filter():
    form = FilterForm(request.form)
    settings = Settings.query.limit(1).first()
    if request.method == 'GET':
        form.regex.data = settings.regex_filter
        return render_template("filter.html", form=form)
    else:
        try:
            re.compile(form.regex.data)
            settings.regex_filter = form.regex.data
            db.session.commit()
            return redirect(url_for('dashboard'))
        except re.error:
            return render_template("filter.html", form=form, issue=True)

@app.route('/newga')
@admin_required
def new_google_authentication():
    new_token = pyotp.random_base32()
    g.settings.secret_key = new_token
    db.session.commit()
    totp = pyotp.TOTP(g.settings.secret_key)
    uri = totp.provisioning_uri("admin")
    return uri

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

def post_to_ifttt(post_body):
    requests.post(os.environ['POST_URL'], data = {'value1':post_body})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)