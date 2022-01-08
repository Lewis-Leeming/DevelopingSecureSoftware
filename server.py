import datetime
import sqlite3
import time
import re
import string
import random, string
import random
import math
import html
from functools import wraps
from random import randrange
from flask import Flask, g, render_template, redirect, request, session, url_for, Response
from flask import flash
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'thisisabadsecretkey'
app.permanent_session_lifetime = datetime.timedelta(minutes=30)
DATABASE = 'database.sqlite'
encrypt_key = 'physicoafd'

B64_CHARS = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u",
             "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
             "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "/",
             "+"]
AUTH_TOKEN_LENGTH = 128

# ref https://flask.palletsprojects.com/en/rtd/security/
# https://www.cookiepro.com/knowledge/httponly-cookie/
# Secure limits cookies to HTTPS traffic only when it turns to TRUE.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'dssmailbot@gmail.com'
app.config['MAIL_PASSWORD'] = 'mailbotpassword123'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

mail = Mail(app)
DATABASE = 'database.sqlite'

# function decorator (middleware), add @auth_required where user MUST be authed
def auth_required(r):
    @wraps(r)
    def decorator(*args, **kwargs):
        #ensure session is active
        if(session):
            # Ensure token in cookies matches one in DB
            if(check_auth_token(session['sid'],request.cookies.get('X-Auth-Token'))):
                #Continue with rest of request
                return r(*args, **kwargs)
            else:
                #Prompt user to login
                return redirect(url_for("login", next=request.url))
        else:
            #Same again
            return redirect(url_for("login", next=request.url))
    return decorator
    #user can be in two states, logged in and navigating site, or sitting at login page!!!


# ------------------------------------------------------------ DATABASE SETUP -----------------------------------------------#
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

    def make_dicts(cursor, row):
        return dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row))

    db.row_factory = make_dicts

    return db


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)

    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def std_context(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        context = {}
        request.context = context

        if 'sid' in session:
            context['loggedin'] = True
            # code for decryption using key from db
            db = get_db()
            sid_decrypted = symmetric_decryption(session['sid'], encrypt_key)
            key = db.execute("SELECT decryptKey FROM session_ WHERE sessionID=?", (sid_decrypted,)).fetchone()
            key_decrypted = symmetric_decryption(splitKey(str(key)), encrypt_key)
            key_to_tuple = reformat(key_decrypted)
            username_decrypted = decrypt(tuple(key_to_tuple), session['username'])
            print("username ",username_decrypted)
            context['username'] = username_decrypted

        else:
            session.clear()
            context['loggedin'] = False
            context['tempuser'] = 'none'

        return f(*args, **kwargs)

    return wrapper


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# ------------------------------------------------------ HTML PAGES SETUP----------------------------------------------#
@app.route("/")
@auth_required
@std_context
def index():
    messages = query_db(
        'SELECT messages.creator,messages.date,messages.title,messages.content,uname.name,uname.username FROM messages JOIN uname ON messages.creator=uname.userid ORDER BY date DESC LIMIT 10')

    def fix(item):
        item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
        item['content'] = '%s...' % (item['content'][:200])
        return item

    context = request.context
    context['messages'] = map(fix, messages)
    return render_template('index.html', **context)


@app.route("/<uname>/")
@std_context
def users_posts(uname=None):
    cid = query_db('SELECT userid FROM uname WHERE username="%s"' % (uname))
    if len(cid) < 1:
        return 'No such user'

    cid = cid[0]['userid']
    query = 'SELECT date,title,content FROM messages WHERE creator=%s ORDER BY date DESC' % (cid)

    context = request.context

    def fix(item):
        item['date'] = datetime.datetime.fromtimestamp(item['date']).strftime('%Y-%m-%d %H:%M')
        return item

    a = query_db(query)
    context['messages'] = map(fix, query_db(query))
    return render_template('user_posts.html', **context)


# pin generator
def generate_string(size):
    randomString = ''
    for index in range(0, size):
        randomString += randomString.join(random.SystemRandom().choice(string.ascii_letters + string.digits))
    return (randomString)


# key generator
def key_generator(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))


@app.route('/register/', methods=['GET', 'POST'])
@std_context
def register():
    ## ALL THE PRINTS FOR TESTING PURPOSES at some point my flash was lagging
    db = get_db()
    # check if sessision exists to prevent register when logged in
    if session.get('sid'):
        return redirect(url_for('index'))
    else:
        if request.method == 'POST':

            newname = request.form['name']
            newusername = request.form['username']
            newpassword = request.form['password']
            confirmpassword = request.form['confirm']
            newemail = request.form['email']

            # ref https://www.regular-expressions.info/email.html for regular expressions
            # email reg. explanation https://www.c-sharpcorner.com/article/how-to-validate-an-email-address-in-python/
            emailreg = "^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
            reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,20}$"
            pat = re.compile(reg)
            mat = re.search(pat, newpassword)

            # check if the field containt email address style e.g something@somethingelse.whatever
            pat1 = re.compile(emailreg)
            mat1 = re.search(pat1, newemail)

            # check if user or email exists
            checkusername = query_db("SELECT userid FROM uname WHERE username=?", (newusername,))
            checkemail = query_db("SELECT userid FROM uname WHERE email=?", (newemail,))

            if newname and newusername and newemail != "" and mat1:
                # check if the username already exists
                if checkusername or checkemail:
                    flash("Something is wrong")
                    # print("The user already exists")
                    return render_template('register.html')
                else:
                    if mat and newpassword == confirmpassword:
                        session.clear()
                        randomString = generate_string(4)
                        newpin = randomString
                        newpin_encrypted = symmetric_encryption(newpin,encrypt_key)
                        newpassword_encrypted = symmetric_encryption(newpassword,encrypt_key)
                        values = [newname, newusername, newpassword_encrypted, newemail, newpin_encrypted]
                        query_db('INSERT INTO uname (name,username,password,email, pin) VALUES ({})'.format(
                            ', '.join('"{}"'.format(str(v)) for v in values)
                        ))
                        db.commit()
                        msg = Message('Your PIN Code', sender='dssmailbot@gmail.com', recipients=[newemail])
                        msg.body = "Your 2FA code is " + newpin
                        mail.send(msg)
                        flash('Account created')
                        return redirect(url_for('login'))
                    else:
                        # print("password do not match")
                        flash("Password do not match")
                        return render_template('register.html')
            else:
                flash("Please enter all fill all fields to register")
                return render_template('register.html')

        return render_template('register.html')


@app.route("/login/", methods=['GET', 'POST'])
@std_context
def login():
    db = get_db()
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        pin = request.form.get('pin', '')
        context = request.context

        query = "SELECT userid FROM uname WHERE username='%s'" % (username)
        account = query_db(query)
        user_exists = len(account) > 0
        # password = rsa.encrypt(pk, password) # hash also maybe to remove possibilty of decrypting
        password_encryption = symmetric_encryption(password,encrypt_key)
        pin_encryption = symmetric_encryption(pin,encrypt_key)

        query = "SELECT userid FROM uname WHERE username='%s' AND password='%s' AND pin='%s'" % (
        username, password_encryption, pin_encryption)
        print(query)
        account2 = query_db(query)
        print(account)
        pass_match = len(account2) > 0

        if username and password and pin != "":
            if user_exists and pass_match:

                # 2fa login code    65  -=/2f
                randomString = generate_string(10)

                public, private = generate_keypair()
                private_to_string = str(private[0]) + "#" + str(private[1])
                private_encrypted = symmetric_encryption(private_to_string, encrypt_key)
                db.execute("INSERT INTO session_ (decryptKey) VALUES ('%s')" % (private_encrypted))
                get_pk_from_db = query_db('SELECT last_insert_rowid()')
                pk_to_string = int(re.search(r'\d+', str(get_pk_from_db)).group())
                db.commit()

                # session hijacking - making sessions timeout if idle
                session.permanent = True
                session.modified = True

                # for accessing database for RSA decryption key
                pk_encrypted = symmetric_encryption(str(pk_to_string), encrypt_key)
                session['sid'] = pk_encrypted

                print("unecrypted username ",username)
                username_encrypted = encrypt(public,username)
                session['username'] = username_encrypted
                print("encrypted username ", username_encrypted)
                print(decrypt(private,username_encrypted))
                print(private)
                userid_encrypted = encrypt(public, str(account[0]['userid']))
                session['userid'] = userid_encrypted

                # send an email containing the code
                email = query_db("SELECT email FROM uname WHERE username='%s'" % (username))
                emailDict = email[0]
                msg = Message('Test Email', sender='dssmailbot@gmail.com', recipients=[emailDict["email"]])
                msg.body = "Your 2FA code is " + randomString
                mail.send(msg)
                random_string_encrypted = encrypt(public, randomString)
                session['twofa'] = random_string_encrypted
                return render_template('twofa.html', **context)

                # return redirect(url_for('index'))

            else:
                # Return wrong password
                flash("Please carefully check your username, password and PIN")
                return render_template('login.html')
        else:
            # Return no such user
            flash("Please fill up all fields user")
            return render_template('login.html')

    return render_template('login.html')


@app.route("/logout/")
def logout():
    db = get_db()
    sid_real = symmetric_decryption(session['sid'], encrypt_key)
    db.execute("DELETE FROM session_ WHERE sessionID=?", (sid_real,))
    db.commit()
    session.clear()
    return redirect('/')


@app.route("/post/", methods=['GET', 'POST'])
@std_context
def new_post():
    if 'sid' not in session:
        return redirect(url_for('login'))

    db = get_db()
    sid_decrypted = symmetric_decryption(session['sid'], encrypt_key)
    key = db.execute("SELECT decryptKey FROM session_ WHERE sessionID=?", (sid_decrypted,)).fetchone()
    key_decrypted = symmetric_decryption(splitKey(str(key)), encrypt_key)
    key_to_tuple = reformat(key_decrypted)
    username_decrypted = decrypt(tuple(key_to_tuple), session['userid'])

    userid = username_decrypted
    print(userid)
    context = request.context
    if request.method == 'GET':
        return render_template('new_post.html', **context)

    date = datetime.datetime.now().timestamp()
    title = make_safe(request.form.get('title'))
    content = make_safe(request.form.get('content'))

    # Finds any URLs in the post and removes the link
    content = re.sub("[^-A-Za-z0-9+&@#/%?=~_|!:,.;\(\)]", "", content)
    title = re.sub("[^-A-Za-z0-9+&@#/%?=~_|!:,.;\(\)]", "", title)

    if title and content != '':
        query_db("INSERT INTO messages (creator, date, title, content) VALUES (?,?,?,?)", (userid, date, title, content))
        get_db().commit()
        return redirect('/')
    else:
        flash('Please fill all fields')
        return render_template('new_post.html', **context)

@app.route("/reset/", methods=['GET', 'POST'])
@std_context
def reset():
    context = request.context

    email = request.form.get('email', '')
    if email == '':
        return render_template('reset_request.html')

    query = 'SELECT email FROM username WHERE email=?', (email)
    exists = query_db(query)
    if len(exists) < 1:
        return render_template('no_email.html', **context)
    else:
        context['email'] = email
        return render_template('sent_reset.html', **context)


@app.route("/search/", methods=['GET', 'POST'])
@std_context
def search_page():
    context = request.context
    search = request.args.get('s', '')

    # if match query get the post
    messages = query_db(
        'SELECT messages.creator,messages.title,messages.content,uname.username FROM messages JOIN uname ON messages.creator=uname.userid WHERE username LIKE (?) ORDER BY date DESC LIMIT 10;',
        [search])
    # block the special characters.

    # limit the content if required
    for message in messages:
        message['content'] = '%s...' % (message['content'][:40])

    return render_template('search_results.html', messages=messages, **context)


# ------------------------------------SECURITY RELATED FUNCTIONS --------------------------------------#
@app.route("/resetdb/<token>")
def resetdb(token=None):
    if token == 'secret42':
        import create_db
        create_db.delete_db()
        create_db.create()
        return 'Database reset'
    else:
        return 'Nope', 401


# XOR cipher
def symmetric_encryption(msg, key):
    hex_string = ""
    key_itr = 0
    for i in range(len(msg)):
        temp = ord(msg[i]) ^ ord(key[key_itr])
        # zfill pads 0 onto hex value to make two letter pair
        hex_string += hex(temp)[2:].zfill(2)
        key_itr += 1
        if key_itr >= len(key):
            key_itr = 0
    return hex_string


def symmetric_decryption(msg, key):
    hex_to_uni = ""
    for i in range(0, len(msg), 2):
        hex_to_uni += bytes.fromhex(msg[i:i + 2]).decode('utf-8')
    back_to_string = ""
    key_itr = 0
    for i in range(len(hex_to_uni)):
        temp = ord(hex_to_uni[i]) ^ ord(key[key_itr])  # ord is unicode representation
        back_to_string += chr(temp)
        key_itr += 1
        if key_itr >= len(key):
            key_itr = 0
    return back_to_string


def splitKey(string):
    stringArray = string.split("'")
    return stringArray[3]


def reformat(key):
    keyArray = key.split('#')
    return (int(keyArray[0]), int(keyArray[1]))


# 2fa
@app.route("/twofa/", methods=['GET', 'POST'])
@std_context
def twofa():
    db = get_db()
    context = request.context
    sid_decrypted = symmetric_decryption(session['sid'], encrypt_key)
    key = db.execute("SELECT decryptKey FROM session_ WHERE sessionID=?", (sid_decrypted,)).fetchone()
    key_decrypted = symmetric_decryption(splitKey(str(key)), encrypt_key)
    key_to_tuple = reformat(key_decrypted)
    print("real key",key_to_tuple)

    tempuser_decrypted = decrypt(tuple(key_to_tuple), session['username'])
    twofa_decrypted = decrypt(tuple(key_to_tuple), session['twofa'])

    tempuser = tempuser_decrypted
    servertwofa = twofa_decrypted
    twofa = str(request.form.get('twofa', ''))
    print("server has: " + servertwofa)
    print("twofa entered is: " + twofa)
    print(servertwofa)
    #flash(servertwofa)
    if len(twofa) == 0:
        return render_template('twofa.html', **context)

    if (twofa == servertwofa):
        twofaMatch = True
    else:
        twofaMatch = False
    if twofaMatch:
        query = "SELECT userid FROM uname WHERE username='%s'" % (tempuser)
        account = query_db(query)
        # user is real
        token = generate_auth_token(AUTH_TOKEN_LENGTH)
        print("token: " + token)
        update_query = "UPDATE uname SET auth_token = \"" + token + "\" where  userid = " + str(account[0]['userid'])
        print("updateQ: " + update_query)
        print(query_db(update_query))
        db.commit()

        redir = redirect(url_for('index'))
        redir.set_cookie("X-Auth-Token", token)
        return redir
    else:
        flash("Incorrect Code")
        session.clear()
        return redirect(url_for('login'))


def escaper(character):
    special_characters = {
        " ": "&%00",
        "!": "&%01",
        '"': "&%02;",
        "#": "&%23",
        "&": "&%06",
        "'": "&%07",
        "(": "&%08",
        ")": "&%09",
        "*": "&%10",
        "+": "&%11",
        ",": "&%12",
        "-": "&%13",
        ".": "&%14",
        "/": "&%15",
        ":": "&%16",
        ";": "&%17",
        "<": "&%18",
        ">": "&%20",
        "?": "&%21",
        "@": "&%22",
        "[": "&%23",
        "\\": "&%24",
        "]": "&%25",
        "^": "&%26",
        "~": "&%32",
        "€": "&%33"
    }
    return special_characters.get(character,character)

# simple randomn string generator
def generate_auth_token(length):
    return_string = ""  # init

    for i in range(length):  # duh
        index = random.randint(0, 63)  # pick element from b64 chars and append
        return_string += B64_CHARS[index]

    return return_string


def check_auth_token(sid, token):
    db = get_db()
    sid_decrypted = symmetric_decryption(session['sid'], encrypt_key)
    key = db.execute("SELECT decryptKey FROM session_ WHERE sessionID=?", (sid_decrypted,)).fetchone()
    key_decrypted = symmetric_decryption(splitKey(str(key)), encrypt_key)
    key_to_tuple = reformat(key_decrypted)
    userid_decrypted = decrypt(tuple(key_to_tuple), session['userid'])

    userid = userid_decrypted
    print("testing ")
    query = "select auth_token from uname where userid = " + userid
    db_token = query_db(query)
    return (db_token[0]["auth_token"] == token)


def make_safe(input):
    not_safe = str(input)
    safe = ""
    for i in range(len(not_safe)):
        safe = safe + html.unescape(str(escaper(not_safe[i])))
    return safe

def key_generator(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

# RSA cryptography - https://gist.github.com/dendisuhubdy/e2e67d796605dbf4860aa6e94201690a - slightly adapted
# to show how assymetric encryption could work
###############################################################################
#Rabinmiller - algorithm to estimate likely prime numbers
#RSA requires two prime numbers in order to generate keys
#algorithm to estimate likely prime numbers
#RSA requires two prime numbers in order to generate keys
def rabinMiller(n, k=10):
    if n == 2:
            return True
    if not n & 1:
            return False
    def check(a, s, d, n):
            x = pow(a, d, n)
            if x == 1:
                    return True
            for i in range(1, s - 1):
                    if x == n - 1:
                            return True
                    x = pow(x, 2, n)
            return x == n - 1
    s = 0
    d = n - 1
    while d % 2 == 0:
            d >>= 1
            s += 1
    for i in range(1, k):
            a = randrange(2, n - 1)
            if not check(a, s, d, n):
                    return False
    return True
#function to return a random prime number
#after low primes, uses rabinMiller as rabinMiller doesnt get all primes
def isPrime(n):
     lowPrimeNumbers =   [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
                   ,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
                   ,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
                   ,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
                   ,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
                   ,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
                   ,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
                   ,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
                   ,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
                   ,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]
     if (n >= 3):
         if (n&1 != 0):
             for p in lowPrimeNumbers:
                 if (n == p):
                    return True
                 if (n % p == 0):
                     return False
             return rabinMiller(n)
     return False
# Larger primes for better security
def generateLargePrime(k):
     r = 100*(math.log(k,2)+1) #number of attempts max
     r_ = r
     while r>0:
         # could change as randrange is bad
         n = random.randrange(2**(k-1),2**(k))
         r -= 1
         if isPrime(n) == True:
             return n
     str_failure = "Failure after" + str(r_) + "tries."
     return str_failure
# greatest common divider (euclids algorithm)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
# gets number^-1 (1/number)
def multiplicative_inverse(a, b):
    # r = gcd(a,b) i = multiplicitive inverse of a mod b
    #      or      j = multiplicitive inverse of b mod a
    x = 0
    y = 1
    lx = 1
    ly = 0
    oa = a
    ob = b
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += ob
    if ly < 0:
        ly += oa
    return lx
def multiply(x, y):
    _CUTOFF = 1536
    if x.bit_length() <= _CUTOFF or y.bit_length() <= _CUTOFF:  # Base case
        return x * y
    else:
        n = max(x.bit_length(), y.bit_length())
        half = (n + 32) // 64 * 32
        mask = (1 << half) - 1
        xlow = x & mask
        ylow = y & mask
        xhigh = x >> half
        yhigh = y >> half
        a = multiply(xhigh, yhigh)
        b = multiply(xlow + xhigh, ylow + yhigh)
        c = multiply(xlow, ylow)
        d = b - a - c
        return (((a << half) + d) << half) + c
def generate_keypair(keySize=10):
    p = generateLargePrime(keySize)
    print(p)
    q = generateLargePrime(keySize)
    print(q)
    if p == q:
        raise ValueError('p and q cannot be equal')
    n = multiply(p, q)
    phi = multiply((p-1),(q-1))
    #same
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        # same
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    key, n = pk
    #converts plaintext to numbers
    cipher = [pow(ord(char),key,n) for char in plaintext]
    return cipher
def decrypt(pk, ciphertext):
    key, n = pk
    #converts back to plaintext
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)





# XOR cipher
def symmetric_encryption(msg, key):
    hex_string = ""
    key_itr = 0
    for i in range(len(msg)):
        temp = ord(msg[i]) ^ ord(key[key_itr])
        # zfill pads 0 onto hex value to make two letter pair
        hex_string += hex(temp)[2:].zfill(2)
        key_itr += 1
        if key_itr >= len(key):
            key_itr = 0
    return hex_string


def symmetric_decryption(msg, key):
    hex_to_uni = ""
    for i in range(0, len(msg), 2):
        hex_to_uni += bytes.fromhex(msg[i:i + 2]).decode('utf-8')
    back_to_string = ""
    key_itr = 0
    for i in range(len(hex_to_uni)):
        temp = ord(hex_to_uni[i]) ^ ord(key[key_itr])  # ord is unicode representation
        back_to_string += chr(temp)
        key_itr += 1
        if key_itr >= len(key):
            key_itr = 0
    return back_to_string

if __name__ == '__main__':
    app.run()