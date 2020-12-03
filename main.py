import sqlite3
from flask import Flask, render_template, request, abort, session, send_file, redirect
from google.oauth2 import id_token
from google.auth.transport import requests
import secrets
import json
import time
import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(128)
conn = sqlite3.connect("data.sqlite3", check_same_thread=False)

curs = conn.cursor()
curs.execute('CREATE TABLE IF NOT EXISTS counter (id text, name text, userid text, count int, last text, lastinfo text, url text)')
with open('configs.json') as f:
    cfg = json.load(f)
    CLIENT_ID = cfg['CLIENT_ID']
    URLROOT = cfg['URLROOT']

@app.route('/')
def index():
    return render_template('index.html', CLIENT_ID=CLIENT_ID)


@app.route('/google/callback', methods=['POST'])
def signin_google():
    if 'idtoken' in request.form:
        try:
            idinfo = id_token.verify_oauth2_token(
                request.form.get('idtoken'), requests.Request(), CLIENT_ID)
            # print(idinfo)
            session['id'] = idinfo['sub']
            session['img'] = idinfo['picture']
            session['name'] = idinfo['name']
            session['salt'] = secrets.token_hex(16)
            session['json_auth'] = json.dumps(idinfo)
        except:
            return abort(500)
        return idinfo['sub']
    else:
        return abort(500)


@app.route('/sinfo')
def sessioninfo():
    return '<code>'+session.get('json_auth', "")+'</code>'


@app.route('/api/add', methods=['POST'])
def addcounter():
    if 'name' in request.form and 'img' in request.form and 'id' in session:
        cursor = conn.cursor()
        imgid = secrets.token_urlsafe(16)
        cursor.execute(
            'INSERT INTO counter (id, name, userid, count, last, lastinfo, url) VALUES(?,?,?,?,?,?,?)',
            [
                imgid,
                request.form.get('name'),
                session['id'],
                -2,
                str(datetime.datetime.fromtimestamp(time.time()).strftime(r'%Y-%m-%d %H:%M:%S')),
                "",
                request.form.get('img')
            ]
        )
        conn.commit()
        return render_template('index.html',img=imgid,URLROOT=URLROOT)
    else:
        return abort(500)

@app.route('/img/<imgid>')
def showimage(imgid):
    cursor = conn.cursor()
    cursor.execute('SELECT url FROM counter WHERE id = ?',[imgid])
    url = cursor.fetchall()
    if url:
        cursor.execute('SELECT count FROM counter WHERE id = ?',[imgid])
        count = cursor.fetchall()
        if count:
            count = int(count[0][0])
            cursor.execute('UPDATE counter SET count = ?, last = ? WHERE id = ?',[count+1,str(datetime.datetime.fromtimestamp(time.time()).strftime(r'%Y-%m-%d %H:%M:%S')),imgid])
            conn.commit()
        return redirect(url[0][0])
    else:
        return redirect('https://dummyimage.com/250/ffffff/000000')

@app.route('/count/<imgid>')
def countimage(imgid):

    cursor = conn.cursor()
    cursor.execute('SELECT count FROM counter WHERE id = ?',[imgid])
    count = cursor.fetchall()
    if count and 'id' in session:
        return 'view count:' + str(count[0][0])
    return abort(404)


if __name__ == "__main__":
    app.run('0.0.0.0', 9876, True)
