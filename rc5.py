from random import randint
import sys

class RC5:

    def __init__(self, w, r, key):
        with open('sync.bin', 'rb') as sync:
            self.syncro = sync.read()
        self.cipher_mode = 'CFB'
        self.complement_mode = 'ANSI X.923'
        
        self.w = w
        if len(self.syncro) > self.w // 4 or len(self.syncro) == 0:
            print(len(self.syncro))
            print('IV must be the of same size as block')
            # sys.exit()
        self.w_bytes = self.w // 8
        self.r = r
        self.key = key
        self.b = len(self.key)
        if not 0 <= self.b <= 255:
            print('Key size must be from 0 to 255 bytes')
            sys.exit()
        self.text = None
        self.S = None
        self.L = []
        self.c = None
        self.expand_key()
        self.fill_S()
        self.mix()

    def print_hex(self, some_bytes):
        return [item.to_bytes(1, byteorder='little').hex() for item in some_bytes]

    def expand_key(self):
        if self.b == 0:
            self.c = 1
            self.key += b'\x00' * self.w_bytes
        else:
            self.c = self.b // self.w_bytes
            delta = self.b % self.w_bytes
            if delta != 0:
                self.key += b'\x00' * (self.w_bytes - delta)
                self.b = len(self.key)
                self.c = self.b // self.w_bytes
        for i in range(0, self.b, self.w_bytes):
            self.L.append(int.from_bytes(self.key[i: i + self.w_bytes], byteorder='little'))

    def get_const(self):
        constants = {
            16: (0xB7E1, 0x9E37),
            32: (0xB7E15163, 0x9E3779B9),
            64: (0xB7E151628AED2A6B, 0x9E3779B97F4A7C15)
        }
        return constants[self.w]

    def fill_S(self):
        p, q = self.get_const()
        self.S = [(p + i * q) % 2 ** self.w for i in range(2 * (self.r + 1))]

    def rol(self, value, n):
        n %= self.w
        return ((value << n) & (2 ** self.w - 1)) | ((value & (2 ** self.w - 1)) >> (self.w - n))

    def ror(self, value, n):
        n %= self.w
        return ((value & (2 ** self.w - 1)) >> n) | (value << (self.w - n) & (2 ** self.w - 1))

    def mix(self):
        G, H, i, j = 0, 0, 0, 0
        for k in range(3 * max(self.c, 2 * (self.r + 1))):
            G = self.S[i] = self.rol(self.S[i] + G + H, 3)
            H = self.L[j] = self.rol(self.L[j] + G + H, G + H)
            i = (i + 1) % (2 * (self.r + 1))
            j = (j + 1) % self.c

    def encrypt_block(self, data):
        A = int.from_bytes(data[:self.w_bytes], byteorder='little')
        B = int.from_bytes(data[self.w_bytes:], byteorder='little')
        A = (A + self.S[0]) % (2 ** self.w)
        B = (B + self.S[1]) % (2 ** self.w)
        for i in range(1, self.r + 1):
            A = (self.rol(A ^ B, B) + self.S[2 * i]) % (2 ** self.w)
            B = (self.rol(B ^ A, A) + self.S[2 * i + 1]) % (2 ** self.w)
        return (A.to_bytes(self.w_bytes, byteorder='little')
                + B.to_bytes(self.w_bytes, byteorder='little'))

    def decrypt_block(self, data):
        A = int.from_bytes(data[:self.w_bytes], byteorder='little')
        B = int.from_bytes(data[self.w_bytes:], byteorder='little')
        for i in range(self.r, 0, -1):
            B = self.ror(B - self.S[2 * i + 1], A) ^ A
            A = self.ror(A - self.S[2 * i], B) ^ B
        B = (B - self.S[1]) % (2 ** self.w)
        A = (A - self.S[0]) % (2 ** self.w)
        return (A.to_bytes(self.w_bytes, byteorder='little')
                + B.to_bytes(self.w_bytes, byteorder='little'))

    def encrypt_bytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w // 4]
            if len(temp) != self.w // 4:
                data = data.ljust(self.w // 4, b'\x00')
                run = False
            res += self.encrypt_block(temp)
            data = data[self.w // 4:]
            if not data:
                break
        return res

    def decrypt_bytes(self, data):
        res, run = b'', True
        while run:
            temp = data[:self.w // 4]
            if len(temp) != self.w // 4:
                run = False
            res += self.decrypt_block(temp)
            data = data[self.w // 4:]
            if not data:
                break
        return res

    def complete_block(self, data):
        delta = self.w // 4 - len(data)
        if delta == self.w // 4:
            delta = 0
        if self.complement_mode == 'ANSI X.923':
            if delta == 0:
                data = data.ljust(self.w // 4 - 1, b'\x00')
            else:
                data = data.ljust(self.w // 2 - 1, b'\x00')
        elif self.complement_mode == 'ISO 10126':
            for i in range(delta + self.w // 4 - 1):
                data += randint(0, 255).to_bytes(1, byteorder='little')
        elif self.complement_mode == 'PKCS7':
            if delta == 0:
                data = data.ljust(self.w // 4, (self.w // 4).to_bytes(1, byteorder='little'))
            else:
                data = data.ljust(self.w // 2, (delta + self.w // 4).to_bytes(1, byteorder='little'))
        elif self.complement_mode == 'ISO/IEC 7816-4':
            data += b'\x80'
            if delta == 0:
                data = data.ljust(self.w // 4, b'\x00')
            else:
                data = data.ljust(self.w // 2, b'\x00')
        if self.complement_mode in ('ANSI X.923', 'ISO 10126'):
            data += (self.w // 4 + delta).to_bytes(1, byteorder='little')
        return data

    def cfb_encrypt(self, text):
        buf = bytearray(text, 'utf-8')
        output = bytearray()
        last_encrypted = self.syncro
        while True:
            data = buf[:self.w // 4]
            buf = buf[self.w // 4:]
            if len(data) != self.w // 4:
                data = self.complete_block(data)
                if len(data) == self.w // 4:
                    blocks = (data,)
                else:
                    blocks = (data[:self.w // 4], data[self.w // 4:])
                for item in blocks:
                    last_encrypted = (int.from_bytes(self.encrypt_bytes(last_encrypted), byteorder='little')
                                        ^ int.from_bytes(item, byteorder='little')).to_bytes(self.w // 4,
                                                                                            byteorder='little')
                    output.extend(last_encrypted)
                break
            last_encrypted = (int.from_bytes(self.encrypt_bytes(last_encrypted), byteorder='little')
                                ^ int.from_bytes(data, byteorder='little')).to_bytes(self.w // 4, byteorder='little')
            output.extend(last_encrypted)
        return bytes(output)

    def cfb_decrypt(self, buf):
        output = bytearray()
        last_data = self.syncro
        while True:
            data = buf[:self.w // 4]
            buf = buf[self.w // 4:]
            if not data:
                break
            text = (int.from_bytes(self.encrypt_bytes(last_data), byteorder='little')
                    ^ int.from_bytes(data, byteorder='little')).to_bytes(self.w // 4, byteorder='little')
            last_data = data
            output.extend(text)
        number_of_bytes_to_remove = output[len(output) -1]
        return bytes(output[:-number_of_bytes_to_remove])

    def encrypt(self, text):
        return self.cfb_encrypt(text)

    def decrypt(self, ciphertext):
        return self.cfb_decrypt(ciphertext)

def print_hex(some_bytes):
    return ','.join(item.to_bytes(1, byteorder='little').hex() for item in some_bytes)



if __name__ == '__main__':
    rc5 = RC5(32, 12, b'jiojdoifjiodsjfj32j4i32j4')
    encr = rc5.encrypt('12345678')
    print(rc5.decrypt(encr))
