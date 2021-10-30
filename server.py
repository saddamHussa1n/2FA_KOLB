import sqlite3
from string import Template
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import socket
import random
from rc5 import RC5
import md5

conn = sqlite3.connect('example.db')
c = conn.cursor()
c.execute(
    '''CREATE TABLE IF NOT EXISTS account (username TEXT, password TEXT, info TEXT)''')
c.execute(
    '''INSERT INTO account (username,password, info) VALUES (?,?,?)''',
    (md5.md5hash(b'leonid'), md5.md5hash(b'1234'), 'Advertisements want to '
                                                   'persuade us to buy '
                                                   'particular products How '
                                                   'do they do it?'))
c.execute(
    '''INSERT INTO account (username,password, info) VALUES (?,?,?)''',
    (md5.md5hash(b'tuleubay'), md5.md5hash(b'qwer'), 'Let’s imagine …You’re '
                                                     'watching TV. It’s a hot '
                                                     'evening: You feel '
                                                     'thirsty. You see an '
                                                     'advert for a refreshing '
                                                     'drink.'))
c.execute('''SELECT * FROM account''')

block_key = get_random_bytes(16)

sock = socket.socket()
sock.bind(('127.0.0.1', 9090))
sock.listen(5)
conn = sock.accept()[0]

client_public_key = conn.recv(4096)
RSA = PKCS1_OAEP.new(RSA.import_key(client_public_key))
enc_block_key = RSA.encrypt(block_key)
conn.send(enc_block_key)
conn.close()

rc5 = RC5(32, 12, block_key)

z = 1
while z != 0:
    conn = sock.accept()[0]
    login = rc5.decrypt(conn.recv(1024))
    conn.close()
    conn = sock.accept()[0]
    password = rc5.decrypt(conn.recv(1024))
    conn.close()

    hash_login = md5.md5hash(login)
    hash_password = md5.md5hash(password)

    c.execute('''SELECT * FROM account WHERE username LIKE ? AND password LIKE ?''',
              ('%' + hash_login + '%', '%' + hash_password + '%'))
    login_check = c.fetchall()
    conn = sock.accept()[0]
    if not login_check:
        conn.send(b'no')
        conn.close()
        conn = sock.accept()[0]
        new_login = md5.md5hash(rc5.decrypt(conn.recv(1024)))
        conn.close()
        conn = sock.accept()[0]
        new_password = md5.md5hash(rc5.decrypt(conn.recv(1024)))
        conn.close()
        c.execute('''INSERT INTO account (username,password) VALUES (?,?)''', (new_login, new_password))
        c.execute('''SELECT * FROM account''')
    else:
        z -= 1
        conn.send(b'yes')
        conn.close()
        fa_key = str(random.randint(1000, 9999))
        message_template = Template(fa_key)

        s = smtplib.SMTP(host='smtp.gmail.com', port=587)
        s.ehlo()
        s.starttls()

        s.login('tuleubay.safiullin@gmail.com', 'bfujxwbltvzcngkl')

        names = ['Tuleubay']
        emails = ['yzsedu@mailto.plus']

        for name, email in zip(names, emails):
            msg = MIMEMultipart()
            message = message_template.substitute(PERSON_NAME=name.title())
            msg['From'] = 'tuleubay.safiullin@mail.ru'
            msg['To'] = email
            msg['Subject'] = "This is TEST"
            msg.attach(MIMEText(message, 'plain'))
            s.send_message(msg)
            del msg

        conn = sock.accept()[0]
        if rc5.decrypt(conn.recv(200)) == bytes(fa_key, 'utf-8'):
            c.execute('''SELECT * FROM account WHERE username LIKE ? AND password LIKE ?''',
                      ('%' + hash_login + '%', '%' + hash_password + '%'))
            login_check = c.fetchall()
            conn.send(b'ok')
            conn.close()
            while True:
                conn = sock.accept()[0]
                conn.send(rc5.encrypt(str(login_check[0][2])))
                conn.close()
                conn = sock.accept()[0]
                edited_note = rc5.decrypt(conn.recv(4048)).decode('utf-8')
                conn.close()
                c.execute('''UPDATE account SET info = ? WHERE username LIKE ? AND password LIKE ?''',
                          (edited_note, '%' + hash_login + '%', '%' + hash_password + '%'))
                c.execute('''SELECT * FROM account''')
                print(c.fetchall())
        else:
            conn.send(b'nope')
            conn.close()

sock.close()
