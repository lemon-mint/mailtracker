import sqlite3
from flask import Flask, render_template, request, abort, session, send_file, redirect, jsonify
from google.oauth2 import id_token
from google.auth.transport import requests
import secrets
import json
import time
import datetime
import hashlib
from flask_cors import CORS, cross_origin


app = Flask(__name__)
app.secret_key = secrets.token_hex(128)
CORS(app)

conn = sqlite3.connect("data.sqlite3", check_same_thread=False)

curs = conn.cursor()
curs.execute('CREATE TABLE IF NOT EXISTS counter (id text, name text, userid text, count int, last text, lastinfo text, url text)')
curs.execute('CREATE TABLE IF NOT EXISTS apikeys (userid text, key text)')
with open('configs.json') as f:
    cfg = json.load(f)
    CLIENT_ID = cfg['CLIENT_ID']
    URLROOT = cfg['URLROOT']


@app.route('/')
def index():
    return render_template('index.html', CLIENT_ID=CLIENT_ID)


@app.route('/key/new')
def New_KEY():
    cursor = conn.cursor()
    if 'id' in session:
        apikey = secrets.token_urlsafe(32)
        cursor.execute('INSERT INTO apikeys (userid, key) VALUES(?, ?)',[session.get('id'),apikey])
        return apikey
    else:
        return abort(403)


@app.route('/google/callback', methods=['POST'])
def signin_google():
    if 'idtoken' in request.form:
        try:
            idinfo = id_token.verify_oauth2_token(
                request.form.get('idtoken'), requests.Request(), CLIENT_ID)
            if cfg.get('WHITELIST_ACTIVE', False):
                if not idinfo['email'] in cfg.get('WHITELIST', []):
                    return abort(500)
            session['id'] = idinfo['sub']
            session['img'] = idinfo['picture']
            session['name'] = idinfo['name']
            session['salt'] = secrets.token_hex(16)
            session['idhash'] = str(hashlib.sha384(str(idinfo['sub']).encode('utf-8')).hexdigest())[2:-1]
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
                str(datetime.datetime.fromtimestamp(
                    time.time()).strftime(r'%Y-%m-%d %H:%M:%S')),
                "",
                request.form.get('img')
            ]
        )
        conn.commit()
        return render_template('index.html', img=imgid, URLROOT=URLROOT)
    else:
        return abort(500)


@app.route('/img/<imgid>')
@cross_origin()
def showimage(imgid):
    cursor = conn.cursor()
    cursor.execute('SELECT url FROM counter WHERE id = ?', [imgid])
    url = cursor.fetchall()
    if url:
        cursor.execute('SELECT count FROM counter WHERE id = ?', [imgid])
        count = cursor.fetchall()
        if count:
            count = int(count[0][0])
            cursor.execute('UPDATE counter SET count = ?, last = ? WHERE id = ?', [
                count+1,
                str(
                    datetime.datetime.fromtimestamp(
                        time.time()
                    ).strftime(r'%Y-%m-%d %H:%M:%S')
                ),
                imgid
            ]
            )
            conn.commit()
        return redirect(url[0][0])
    else:
        return redirect('https://dummyimage.com/250/ffffff/000000')


@app.route('/count/<imgid>')
def countimage(imgid):
    if 'id' in session:
        cursor = conn.cursor()
        cursor.execute('SELECT count FROM counter WHERE id = ? AND userid = ?', [imgid,str(session.get('id'))])
        count = cursor.fetchall()
        if count:
            return 'view count:' + str(count[0][0])
        return abort(404)
    return abort(404)


@app.route('/api/v1/add', methods=['GET', 'POST'])
@cross_origin()
def api_v1_add():
    cursor = conn.cursor()
    if request.method == 'POST' and request.is_json and request.json().get('key'):
        key = str(request.json().get('key'))
        url = request.json().get('url')
        startval = request.json().get('start')
    elif request.method == 'POST' and request.form.get('key'):
        key = str(request.form.get('key'))
        url = request.form.get('url')
        startval = request.form.get('start')
    elif request.method == 'GET' and request.args.get('key'):
        key = str(request.args.get('key'))
        url = request.args.get('url')
        startval = request.args.get('start')
    else:
        return abort(403)
    try:
        if url:
            url = str(url)
            if startval:
                startval = int(startval)
            else:
                startval = -2
        else:
            return abort(400)
    except:
        return abort(400)
    cursor.execute('SELECT userid FROM apikeys WHERE key = ?', [key])
    userid = cursor.fetchall()
    if userid:
        userid = userid[0][0]
        imgid = secrets.token_urlsafe(16)
        name = secrets.token_urlsafe(16)
        cursor.execute(
            'INSERT INTO counter (id, name, userid, count, last, lastinfo, url) VALUES(?,?,?,?,?,?,?)',
            [
                imgid,
                name,
                userid,
                startval,
                str(datetime.datetime.fromtimestamp(
                    time.time()).strftime(r'%Y-%m-%d %H:%M:%S')),
                str(request.headers),
                url
            ]
        )
        conn.commit()
        return jsonify(
            {
                'userid': userid,
                'imgid': imgid,
                'imgname': name,
                'imgurl': URLROOT + 'img/' + imgid,
                'endpoint': url,
                'counturl': URLROOT + 'count/' + imgid
            }
        )
    else:
        return abort(403)
    return abort(500)


@app.route('/api/v1/count')
@cross_origin()
def api_v1_count():
    cursor = conn.cursor()
    if request.method == 'POST' and request.is_json and request.json().get('key'):
        key = str(request.json().get('key'))
        imgid = str(request.json().get('imgid'))
    elif request.method == 'POST' and request.form.get('key'):
        key = str(request.form.get('key'))
        imgid = str(request.form.get('imgid'))
    elif request.method == 'GET' and request.args.get('key'):
        key = str(request.args.get('key'))
        imgid = str(request.args.get('imgid'))
    else:
        return abort(403)
    cursor.execute('SELECT userid FROM apikeys WHERE key = ?', [key])
    userid = cursor.fetchall()
    if userid:
        cursor.execute('SELECT count FROM counter WHERE id = ? AND userid = ?', [imgid,userid[0][0]])
        count = cursor.fetchall()
        if count:
            return jsonify(
                {
                    'imgname': imgid,
                    'count' : count[0][0],
                    'imgurl': URLROOT + 'img/' + imgid,
                    'counturl': URLROOT + 'count/' + imgid
                }
            )
        return abort(403)
    return abort(403)


if __name__ == "__main__":
    app.run('0.0.0.0', 9876, True)
