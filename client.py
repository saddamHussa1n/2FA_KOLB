import os
import sys
from Crypto.Cipher import PKCS1_OAEP
from PyQt5 import QtWidgets
from Crypto.PublicKey import RSA
import socket
import main_w
import window_sign_in
import window_create_acc
import fa

key = RSA.generate(2048)
client_private_key = key
client_public_key = key.publickey().exportKey()

s = socket.socket()
s.connect(('127.0.0.1', 9090))

s.sendall(client_public_key)
enc_block_key = s.recv(4096)
s.close()

cipher_rsa = PKCS1_OAEP.new(client_private_key)
block_key = cipher_rsa.decrypt(enc_block_key)


class FirstClass(QtWidgets.QMainWindow, window_sign_in.Ui_MainWindow):
    def __init__(self, parent=None):
        super(FirstClass, self).__init__(parent)
        self.setupUi(self)
        self.window_create_acc = None
        self.fa_window = None
        self.main_window = None
        self.setFixedSize(self.size())

        self.pushButton.clicked.connect(self.sign_in)

    def sign_in(self):
        login = self.lineEdit.text()
        password = self.lineEdit_2.text()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(bytes(login, 'utf-8'))
        s.close()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(bytes(password, 'utf-8'))
        s.close()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        ans = s.recv(20)
        s.close()
        if ans == b'no':
            self.show_window_create_acc()
        else:
            self.show_fa_window()
            self.close()

    def show_window_create_acc(self):
        self.window_create_acc = SecondClass()
        self.window_create_acc.show()

    def show_fa_window(self):
        self.fa_window = FourthClass()
        self.fa_window.show()


class SecondClass(QtWidgets.QMainWindow, window_create_acc.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setFixedSize(self.size())

        self.pushButton.clicked.connect(self.add_note)

    def add_note(self):
        new_login = self.lineEdit.text()
        new_password = self.lineEdit_2.text()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(bytes(new_login, 'utf-8'))
        s.close()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(bytes(new_password, 'utf-8'))
        s.close()
        self.close()


class ThirdClass(QtWidgets.QMainWindow, main_w.Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setFixedSize(self.size())


class FourthClass(QtWidgets.QMainWindow, fa.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.setFixedSize(self.size())
        self.main_window = None
        self.pushButton.clicked.connect(self.verify)

    def verify(self):
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(bytes(self.lineEdit.text(), 'utf-8'))
        if s.recv(100) == b'ok':
            self.close()
            self.main_window = ThirdClass()
            self.main_window.show()
        else:
            self.close()
        s.close()


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = FirstClass()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
