import datetime
import os
import random
import re
import sqlite3
import string

DATABASE = 'database.sqlite'
encrypt_key = 'physicoafd'

# Simple user blog site

# From http://listofrandomnames.com/index.cfm?textarea
uname=map(lambda x:x.strip(), re.split('[\r\n]+','''Akhil Belo
Dionysia Kralj
Ernst Donaghue
Jakob Hadjiev
Jozefína McManus
Kamau Avakian
Pythagoras Armando
Drupada Sydney
Miriam Boer
Alfred Castle
Radovan Gomes
Ausra Popescu
Olympias Crespo
Roslyn Wong
Nkiru Cremona
Vanesa Lupo
Rut Koole
Braiden MacMathan
Elnora Stojanov
Deepak Janda
Patrice Marsden
Vera Royer
Kepheus Prinz
Kristina Yoshino
Maarja Uggeri
Fatma Jans
Bogdana Phelps
Roland Schultheiss
Monat Dumbledore
Inderjeet Farkas
Heraclides Nanni
Daley Kuijpers
Zorana Jordan
Petter Adam
Helga Bray
Alexandre Stern
Farrukh Bentsen
Iuliu Janowski
Kolya Lama
Afroditi Holm
Marcius Dickson
Georgiana Bramson
Lucinde Accardi
Malcolm Stevenson
Lucan Ahearn
Monica Gang
Stone Anand
Metod Cavanah
Aksinia Stanev
Camelia Bleier'''))
def create():
    db = sqlite3.connect(DATABASE)

    c=db.cursor()

    c.execute('''CREATE TABLE uname (userid integer PRIMARY KEY, username VARCHAR(32), name TEXT, password VARCHAR(20), email TEXT, pin VARCHAR(4),lastlogin INTEGER, logincount INTEGER, loginIP INTEGER, auth_token VARCHAR, timebanned INTEGER)''')
    c.execute('''CREATE TABLE messages (creator integer REFERENCES uname(userid), date INTEGER, title TEXT, content TEXT)''')
    c.execute('''CREATE TABLE session_ (sessionID integer PRIMARY KEY, decryptKey VARCHAR(32))''')
    c.execute('''CREATE INDEX user_username on uname (username)''')
    c.execute('''CREATE INDEX user_messages on messages (creator, date)''')
	#c.execute('''CREATE TABLE banned (userid integer PRIMARY KEY, loginIP INTEGER, bannedstatus TEXT,))   

    db.commit()

    id=0
    for user in uname:
        create_content(db, id, user)
        id+=1
    db.commit()


def test_session_table(db):
    key = key_generator(10)
    db.execute('INSERT INTO session_ (sessionID, decryptKey) VALUES (?,?)', (4, key))
    

def create_content(db, id, name):
    password = generate_string(10)
    pin = key_generator(4)
    password_encryption = symmetric_encryption(password,encrypt_key)
    pin_encryption = symmetric_encryption(pin,encrypt_key)
    c=db.cursor()
    username = '%s%s'%(name.lower()[0], name.lower()[name.index(' ')+1:])
    email = '%s.%s@email.com'%((name.lower()[0], name.lower()[name.index(' ')+1:]))
    secret = "KHdmmYhG&%r%D)%£@FGSDK*/~KJ&"
    c.execute('INSERT INTO uname (userid, username, name, password, email, pin) VALUES (?,?,?,?,?,?)',(id,username,name,password_encryption,email,pin_encryption))
    date = datetime.datetime.now() - datetime.timedelta(28)
    
    for i in range( random.randrange(4,8) ):
        content = 'Some random text for item %d'%(i)
        title = 'Item %d'%(i)
        date = date + datetime.timedelta( random.randrange(1,3), minutes=random.randrange(1,120), hours=random.randrange(0,6) )

        c.execute('INSERT INTO messages (creator,date,title,content) VALUES (?,?,?,?)',(
            id, date.timestamp(), title, content
        ))

def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
        
def key_generator(size):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(size))

def generate_string(size):
    randomString = ''
    for index in range(0,size):
        randomString += randomString.join(random.SystemRandom().choice(string.ascii_letters + string.digits))
    return(randomString)

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

if __name__=='__main__':
    delete_db()
    create()