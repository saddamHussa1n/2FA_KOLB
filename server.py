import sqlite3
from string import Template
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import socket
import hashlib
import random

conn = sqlite3.connect('example.db')
c = conn.cursor()
c.execute(
    '''CREATE TABLE IF NOT EXISTS account (username TEXT, password TEXT, info TEXT)''')
c.execute('''SELECT * FROM account''')

block_key = get_random_bytes(16)
key = RSA.generate(2048)
server_private_key = key.exportKey()
server_public_key = key.publickey().exportKey()

sock = socket.socket()
sock.bind(('127.0.0.1', 9090))
sock.listen(5)
conn = sock.accept()[0]

client_public_key = conn.recv(4096)
cipher_rsa = PKCS1_OAEP.new(RSA.import_key(client_public_key))
enc_session_key = cipher_rsa.encrypt(block_key)
conn.send(enc_session_key)
conn.close()

z = 1
while (z != 0):
    conn = sock.accept()[0]
    login = conn.recv(1024)
    conn.close()
    conn = sock.accept()[0]
    password = conn.recv(1024)
    conn.close()

    hash_login = hashlib.md5(login).hexdigest()
    hash_password = hashlib.md5(password).hexdigest()

    c.execute('''SELECT * FROM account WHERE username LIKE ? AND password LIKE ?''',
              ('%' + hash_login + '%', '%' + hash_password + '%'))
    login_check = c.fetchall()
    conn = sock.accept()[0]
    if not login_check:
        conn.send(b'no')
        conn.close()
        conn = sock.accept()[0]
        new_login = hashlib.md5(conn.recv(1024)).hexdigest()
        conn.close()
        conn = sock.accept()[0]
        new_password = hashlib.md5(conn.recv(1024)).hexdigest()
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
        emails = ['tuleubay.safiullin@mail.ru']

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
        if conn.recv(200) == bytes(fa_key, 'utf-8'):
            conn.send(b'ok')
        else:
            conn.send(b'nope')
        conn.close()

sock.close()
