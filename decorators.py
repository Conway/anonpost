import time
from functools import wraps
from flask import abort, render_template, request, session
from models import db, IPBan

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            if not session['admin']:
                return abort(403)
            else:
                return f(*args, **kwargs)
        except KeyError:
            return abort(403)
    return wrapped

def check_bans(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        session['qb'] = None # reset qb variable
        if request.headers.getlist("X-Forwarded-For"):
            ip = request.headers.getlist("X-Forwarded-For")[0]
        else:
            ip = request.remote_addr
        results = IPBan.query.filter_by(ip=ip)
        if results:
            for result in results:
                if time.time() - (int(result.issued) + int(result.duration)) > 0 and int(result.duration) != -1:
                    obj = IPBan.query.filter_by(id=result.id).first()
                    obj.active = False
                    db.session.commit()
                if result.active==True and result.ban_type=='public':
                    return render_template("suspended.html", message=result.ban_note_public, ip=ip, u_a= request.user_agent.string)
                if result.active==True and result.ban_type=='quiet':
                    session['qb'] = True
        else:
            session['qb'] = False
            return f(*args, **kwargs)
        return f(*args, **kwargs)
    return wrapped