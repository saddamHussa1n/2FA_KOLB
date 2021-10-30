import os
import sys
from Crypto.Cipher import PKCS1_OAEP
from PyQt5 import QtWidgets
from Crypto.PublicKey import RSA
import socket
from rc5 import RC5
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

RSA = PKCS1_OAEP.new(client_private_key)
block_key = RSA.decrypt(enc_block_key)
rc5 = RC5(32, 12, block_key)


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
        s.send(rc5.encrypt(login))
        s.close()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(rc5.encrypt(password))
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
        s.send(rc5.encrypt(new_login))
        s.close()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(rc5.encrypt(new_password))
        s.close()
        self.close()


class ThirdClass(QtWidgets.QMainWindow, main_w.Ui_MainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.setFixedSize(self.size())
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        data = rc5.decrypt(s.recv(4048)).decode('utf-8')
        s.close()
        self.textBrowser.setText(data)
        self.plainTextEdit.setPlainText(data)
        self.pushButton_3.clicked.connect(self.edit_note)

    def edit_note(self):
        edited_note = self.plainTextEdit.toPlainText()
        s = socket.socket()
        s.connect(('127.0.0.1', 9090))
        s.send(rc5.encrypt(edited_note))
        s.close()
        self.textBrowser.setText(edited_note)


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
        s.send(rc5.encrypt(self.lineEdit.text()))
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
