from minimal import minimal

import pathlib
import os
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import gnupg

from PySide6.QtGui import Qt
from PySide6.QtWidgets import QGridLayout, QPushButton, QFileDialog, QPlainTextEdit, QLabel, QDialog, QVBoxLayout, QDialogButtonBox

from text_catalog import txt_practica0 as cat
import rsaKeys

class SimpleDialog(QDialog):
    def __init__(self, title:str, msg:str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)

        # Create a layout
        layout = QVBoxLayout(self)

        # Create a QLabel for the message
        message = QLabel(msg)
        message.setAlignment(Qt.AlignCenter)  # Alineación del texto al centro

        # Create a button box with OK and Cancel buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        # Add the message and button box to the layout
        layout.addWidget(message)
        layout.addWidget(button_box)

        # Connect the accepted and rejected signals to the dialog's accept and reject slots
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

class practica0(minimal):
    title_dsp = None

    # layouts
    layout = None

    interactable = None
    moddable = None
    loggable = None

    # widgets
    buttons = dict()
    modes = dict()
    passw = None
    initv = None
    logs = None

    # internal repr / controller / internal ds
    ds_main_dir = os.getcwd()
    ds_deciph = False
    ds_opmode = ''
    ds_passw = ''
    ds_initv = ''
    ds_file = ''
    ds_filesv = ds_file

    ds_fiehash = None
    ds_signature = None
    ds_filedata = None

    whoami = sys.argv[1]

    def doLog(self, txt:str):
        self.logs.appendPlainText(f'{txt}')

    def load_filedata(self):
        with open(self.ds_file, 'rb') as fd:
            self.ds_filedata = fd.read(-1)
        self.doLog(f'{cat.log.file}{self.ds_file}')

    def save_filedata(self):
        if len(sys.argv) == 3:
            l = int(-len(self.ds_filedata)//3)
            ba = bytearray(self.ds_filedata)
            ba[l] = ord('A')
            self.ds_filedata = bytes(ba)

        with open(self.ds_file, 'wb') as fd:
            fd.write(self.ds_filedata)
        self.doLog(f'{cat.log.expf}{self.ds_file}')

    def init_aes(self):
        cpu_aes = True
        cipher = None
        match self.ds_opmode:
            case cat.mode.ecb:
                cipher = AES.new(self.Key, AES.MODE_ECB, use_aesni=cpu_aes)
                self.doLog(cat.log.initvign)
            case cat.mode.cbc:
                cipher = AES.new(self.Key, AES.MODE_CBC, self.Iv, use_aesni=cpu_aes)
            case cat.mode.cfb:
                cipher = AES.new(self.Key, AES.MODE_CFB, self.Iv, use_aesni=cpu_aes)
            case cat.mode.ofb:
                cipher = AES.new(self.Key, AES.MODE_OFB, self.Iv, use_aesni=cpu_aes)
        return cipher

    def doHash(self):
        hasher = hashes.Hash(hashes.SHA512(), backend=default_backend())
        hasher.update(self.ds_filedata)
        self.ds_fiehash = hasher.finalize()
        self.ds_fiehash = int.from_bytes(self.ds_fiehash, "little")
        self.doLog(f'hash is: {self.ds_fiehash} length is: {len(str(self.ds_fiehash))}')

    def doSign(self):
        if self.whoami == cat.Who.Alice:
            self.change_working_directory(0)
        elif self.whoami == cat.Who.Bob:
            self.change_working_directory(1)

        public_key = rsaKeys.load_public()
        private_key = rsaKeys.load_private(public_key)

        self.ds_signature = rsaKeys.encrypt_w_private(self.ds_fiehash, private_key)

        print('\033[31m')
        print(f'Signature is:\n{str(self.ds_signature)} len is: {len(str(self.ds_signature))}')
        print('\033[0m')

        # os.chdir(self.ds_main_dir)

    def doEncrypt(self):
        # AES
        self.doHash()
        self.doSign()

        self.ds_filedata = self.ds_signature.to_bytes(cat.rsa.maxbytes, cat.cfg.endian) + self.ds_filedata
        # self.ds_filedata = f'{len(str(self.ds_signature))}\n{str(self.ds_signature)}'.encode(cat.cfg.txt_encode) + self.ds_filedata

        cipher = self.init_aes()
        self.ds_filedata = cipher.encrypt(
            pad(self.ds_filedata, AES.block_size)
            )
        
    def doCheckSignature(self):
        if self.whoami == cat.Who.Alice:
            self.change_working_directory(1)
        elif self.whoami == cat.Who.Bob:
            self.change_working_directory(0)

        self.doHash()

        public_key = rsaKeys.load_public()
        alleged_hash = rsaKeys.decrypt_w_public(self.ds_signature, public_key)

        self.doLog(f'***Alleged hash: {alleged_hash} vs actual hash: {self.ds_fiehash}***')

        if alleged_hash == self.ds_fiehash:
            dialog = SimpleDialog('estatus', 'Voila! 🤩, el farchivo es genuino')
            dialog.exec_()
        else:
            dialog = SimpleDialog('estatus', 'Carambolas! 😭, el archivo no es genuino / se corrompió')
            dialog.exec_()

        return
    
    def doDecrypt(self):
        # AES
        cipher = self.init_aes()
        try:
            self.ds_filedata = unpad(
                cipher.decrypt(self.ds_filedata),
                AES.block_size
            )
        except:
            self.ds_filedata = cipher.decrypt(self.ds_filedata)

        try:
            self.ds_signature = int.from_bytes(self.ds_filedata[:cat.rsa.maxbytes], cat.cfg.endian)
            self.ds_filedata = self.ds_filedata[cat.rsa.maxbytes:]

            print('\033[33m')
            print(f'signature size: {len(str(self.ds_signature))}\nsignature is: {self.ds_signature}')
            print('\033[0m')

            self.doCheckSignature()
        except:
            self.ds_file = ''
            self.doLog('error con el archivo, intente otro...')
            dialog = SimpleDialog('estatus', f'Archivo invalido, se necesitan al menos {cat.rsa.maxbytes} de firma digital')
            dialog.exec_()

        # print(self.ds_filedata)

    def dispatchAction(self):
        self.check_begin_requirements()
        try:
            self.load_filedata()
        except:
            self.doLog(f'{cat.log.fileerr} "{self.ds_file}"')
            self.ds_filesv = ''
            self.ds_file = ''
            self.check_begin_requirements()
            return
        mode = None
        if self.ds_deciph == False:
            self.doEncrypt()
            mode = '_c'
        elif self.ds_deciph == True:
            self.doDecrypt()
            mode = '_d'

        if self.check_begin_requirements():
            return

        try:
            self.ds_filesv = f'{self.ds_file}{mode}{self.ds_opmode}{pathlib.Path(self.ds_file).suffix}'
            self.ds_file = self.ds_filesv
            self.save_filedata()
            self.doLog(f'{cat.log.route} {self.ds_file}')
        except:
            self.doLog(f'{cat.log.filewerr} "{self.ds_file}"')
            self.ds_filesv = ''
            self.ds_file = ''
            self.ds_filedata = None
            self.check_begin_requirements()
        
        self.doLog('='*50)

    def set_mode(self, deciph:bool):
        print(deciph)
        if deciph == False:
            QPushButton().setText('')
            self.buttons[cat.btns.meta_mode].setText(cat.btns.as_cipher)
        elif deciph == True:
            self.buttons[cat.btns.meta_mode].setText(cat.btns.as_decipher)

        self.ds_deciph = deciph

    def check_begin_requirements(self):
        self.ds_passw = bytes(self.passw.toPlainText(), cat.cfg.txt_encode)
        self.ds_initv = bytes(self.initv.toPlainText(), cat.cfg.txt_encode)
        print([self.ds_file, self.ds_opmode, self.ds_passw, self.ds_initv])
        if self.ds_file == '' or self.ds_opmode == '' or self.ds_passw == '' or self.ds_initv == '':
            self.buttons[cat.btns.action].setEnabled(False)
            return True
        else:
            self.buttons[cat.btns.action].setEnabled(True)
            return False

    def create_directories(self):
        # Create the directories if they don't exist
        if not os.path.exists(cat.Who.Alice):
            print(f"{cat.Who.Alice} Created")
            os.mkdir(cat.Who.Alice)

        if not os.path.exists(cat.Who.Bob):
            print(f"{cat.Who.Bob} Created")
            os.mkdir(cat.Who.Bob)

    G = None
    P = None
    Key_num = None
    Key = None
    Iv_num = None
    Iv = None

    def generate_and_save_dh_params(self):

        if os.path.isfile(cat.dh.dh_params):
            print(f"The file '{cat.dh.dh_params}' already exists.")
            with open(cat.dh.dh_params, 'r') as f:
                self.P = int(f.readline())
                self.G = int(f.readline())
                # print(f'G = {self.G}\nP = {self.P}')
            return
        
        # Generate Diffie-Hellman parameters
        if len(sys.argv) > 2 and sys.argv[2] == '--keys':
            parameters = dh.generate_parameters(generator=cat.dh.gen, key_size=cat.dh.keysiz)
            numbers = parameters.parameter_numbers()

        # Write the parameters to a file
        try:
            with open(cat.dh.dh_params, 'w') as f:
                f.write(f'{numbers.p}\n')
                f.write(f'{numbers.g}')
        except:
            os.remove(cat.dh.dh_params)
            sys.exit(f'Faltan los parametros DH "{cat.dh.dh_params}", dile a tu amigo que no sea envidioso...')

        print("DH parameters successfully created!")

    def change_working_directory(self, argument:int):
        if argument == 0:
            os.chdir(os.path.join(self.ds_main_dir, cat.Who.Alice))
            print(f"Changed working directory to {cat.Who.Alice}")
        elif argument == 1:
            os.chdir(os.path.join(self.ds_main_dir, cat.Who.Bob))
            print(f"Changed working directory to {cat.Who.Bob}")

    def generate_and_save_public_keys(self, param_file, keyname):
        # Load parameters g,p
        g = None 
        p = None
        if self.G == None or self.P == None:
            with open(param_file, 'rb') as f:
                p = int(f.readline())
                g = int(f.readline())
        else:        
            g = self.G
            p = self.P

        param_numbers = dh.DHParameterNumbers(p=p, g=g)
        parameters = param_numbers.parameters(backend=default_backend())

    # Generate private keys for Alice and Bob

        # ALICE PRIVATE
        if sys.argv[1] == cat.Who.Alice:
            alice_file_name = f'private_{keyname}_{cat.Who.Alice}.pem'

            self.change_working_directory(0)
            if os.path.isfile(alice_file_name):
                print(f"The file '{alice_file_name}' already exists.")
                return
            
            private_key_alice = parameters.generate_private_key()
            with open(alice_file_name, 'w') as f:
                f.write(f'{private_key_alice.private_numbers().x}')
                print(f"Private {alice_file_name} saved to current directory.")

            os.chdir(self.ds_main_dir)
            public_key_alice = private_key_alice.public_key()

            alice_file_name = f'public_{keyname}_{cat.Who.Alice}.pem'
            if os.path.isfile(alice_file_name):
                print(f"The file '{alice_file_name}' already exists.")
                return

            with open(alice_file_name, 'w') as f:
                f.write(f'{public_key_alice.public_numbers().y}')
                print(f"Public {alice_file_name} saved to current directory.")


        # BOB PRIVATE
        if sys.argv[1] == cat.Who.Bob:
            bob_file_name = f'private_{keyname}_{cat.Who.Bob}.pem'
            self.change_working_directory(1)
            if os.path.isfile(bob_file_name):
                print(f"The file '{bob_file_name}' already exists.")
                return
            
            private_key_bob = parameters.generate_private_key()
            with open(bob_file_name, 'w') as f:
                f.write(f'{private_key_bob.private_numbers().x}')
                print(f"Private {bob_file_name} saved to current directory.")

            os.chdir(self.ds_main_dir)
            public_key_bob = private_key_bob.public_key()

            bob_file_name = f'public_{keyname}_{cat.Who.Bob}.pem'
            if os.path.isfile(bob_file_name):
                print(f"The file '{bob_file_name}' already exists.")
                return

            with open(bob_file_name, 'w') as f:
                f.write(f'{public_key_bob.public_numbers().y}')
                print(f"Public {bob_file_name} saved to current directory.")

    def load_all_keys(self, priv, pub, keyname):
        p = self.P
        g = self.G
        param_numbers = dh.DHParameterNumbers(p=p, g=g)
        # parameters = param_numbers.parameters(backend=default_backend())

        # load private and public numbers of alice/bob, generate shared secrets
        where = 0 if priv == cat.Who.Alice else 1
        self.change_working_directory(where)
        a = f'private_{keyname}_{priv}.pem'
        try:
            with open(a, 'r') as f:
                a_priv_num = int(f.readline())
        except:
            sys.exit(f'Falta tu llave privada {priv}, la perdiste?...')
        
        os.chdir(self.ds_main_dir)
        b = f'public_{keyname}_{pub}.pem'
        try:
            with open(b, 'r') as f:
                b_public_num = int(f.readline())
        except:
            sys.exit(f'Falta la llave publica de {pub}, dile a tu amigo que no sea envidioso...')

        private_numbers = dh.DHPrivateNumbers(
            a_priv_num, dh.DHPublicNumbers(
                y=b_public_num, parameter_numbers=param_numbers
            )
            )
        
        public_numbers = dh.DHPublicNumbers(
            b_public_num, param_numbers
        )
        
        a_private_key = private_numbers.private_key(backend=default_backend())
        b_public_key = public_numbers.public_key()
        secret = a_private_key.exchange(b_public_key)

        # secret is the one derived directly from Diffie Hellman

        hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=cat.cfg.key_len,
                salt=cat.cfg.salt,
                info=cat.cfg.pepper,
                backend=default_backend()
            )

        if keyname == cat.dh.K_param:
            self.Key = hkdf.derive(secret)
            self.Key_num = int.from_bytes(self.Key, "little")
            print(f"Key is:{int.from_bytes(self.Key, cat.cfg.endian)}")
        elif keyname == cat.dh.IV_param:
            self.Iv = hkdf.derive(secret)
            self.Iv_num = int.from_bytes(self.Iv, "little")
            print(f"IV is:{int.from_bytes(self.Iv, cat.cfg.endian)}")

        # print(f'A priv is = {a_private_key.private_numbers().x}')
        # print(f'B pub is = {b_public_key.public_numbers().y}')
        # print(f'Secret is = {int.from_bytes(secret, "little")}')
        # print('='*50)

    def __init__(self):
        super(practica0, self).__init__(cat.title, cat.df_color)

        # create Alice and Bob dirs
        self.create_directories()
        # g,n
        self.generate_and_save_dh_params()

        # a,b aiv,biv
        # ka, kb, k_aiv, k_biv
        self.generate_and_save_public_keys(cat.dh.dh_params, cat.dh.K_param)
        os.chdir(self.ds_main_dir)
        self.generate_and_save_public_keys(cat.dh.dh_params, cat.dh.IV_param)
        os.chdir(self.ds_main_dir)

        if len(sys.argv) > 2 and sys.argv[2] == '--keys':
            sys.exit(f'Llaves de {sys.argv[1]} generadas')

        # compute secrets, K, and IV, using Alice's a param and aiv
        if sys.argv[1] == cat.Who.Alice:
            self.load_all_keys(cat.Who.Alice, cat.Who.Bob, cat.dh.K_param)
            os.chdir(self.ds_main_dir)
            self.load_all_keys(cat.Who.Alice, cat.Who.Bob, cat.dh.IV_param)
            os.chdir(self.ds_main_dir)                
        elif sys.argv[1] == cat.Who.Bob:
            self.load_all_keys(cat.Who.Bob, cat.Who.Alice, cat.dh.K_param)
            os.chdir(self.ds_main_dir)
            self.load_all_keys(cat.Who.Bob, cat.Who.Alice, cat.dh.IV_param)
            os.chdir(self.ds_main_dir)
        else:
            sys.exit('Ese usuario no existe')


        # main layout
        self.layout = QGridLayout()
        self.layout.setSpacing(cat.layout.grid_spacin)

        # interactable layout
        self.interactable = QGridLayout()
        self.interactable.setSpacing(cat.layout.ingrid_spacin)

            # buttons widgets
        self.buttons[cat.btns.meta_mode] = QPushButton()
        self.buttons[cat.btns.import_file] = QPushButton(text=cat.btns.import_file)
        self.buttons[cat.btns.action] = QPushButton(text=cat.btns.action)

        for m in cat.mode.opmode:
            self.modes[m] = QPushButton(m)

            # password and IV input boxes
        self.passw = QPlainTextEdit()
        self.initv = QPlainTextEdit()
        self.passw.setReadOnly(True)
        self.initv.setReadOnly(True)

            # mod some props and add to layout
        center = Qt.AlignmentFlag.AlignHCenter
        self.passw.setFixedSize(*cat.layout.passw_sz)
        self.initv.setFixedSize(*cat.layout.initv_sz)

        vpos = 0
        for v in self.buttons.values():
            v.setFixedSize(*cat.layout.btn_sz)
            self.interactable.addWidget(v, vpos, 0, center)
            vpos += 1

        passw = QLabel(f'Contraseña({cat.cfg.key_len})')
        initv = QLabel(f'IV({cat.cfg.key_len})')
        passw.setFixedHeight(12)
        initv.setFixedHeight(12)
        self.interactable.addWidget(passw, vpos+1,0, center)
        self.interactable.addWidget(self.passw, vpos+2,0, center)
        self.interactable.addWidget(initv, vpos+3,0, center)
        self.interactable.addWidget(self.initv, vpos+4,0, center)

        # modes layout
        self.moddable = QGridLayout()
        self.moddable.setSpacing(cat.layout.ingrid_spacin)

        hpos = 0
        for v in self.modes.values():
            v.setFixedSize(*cat.layout.mod_sz)
            self.moddable.addWidget(v, 0, hpos)
            hpos += 1

        # loggable layout
        self.loggable = QGridLayout()
        self.loggable.setSpacing(cat.layout.ingrid_spacin)

            # text area log widget
        self.logs = QPlainTextEdit()
        
            # mod the props
        self.logs.setFixedSize(*cat.layout.log_sz)
        self.logs.setReadOnly(True)

        # add to loggable
        self.loggable.addWidget(self.logs, 0,0, center)


        # events
        self.buttons[cat.btns.meta_mode].setCheckable(True)
        self.buttons[cat.btns.meta_mode].clicked.connect(self.set_mode)

        for m in self.modes.values():
            m.setCheckable(True)

        def toggle_opmode(v:bool, name:str):
            if v == True:
                self.ds_opmode = name
            else:
                self.ds_opmode = ''
            print([self.ds_opmode, v])
            for k,m in self.modes.items():
                if name != k:
                    m.setChecked(False)
            self.check_begin_requirements()

        self.modes[cat.mode.opmode[0]].clicked.connect(
            lambda v: toggle_opmode(v, cat.mode.opmode[0])
        )
        self.modes[cat.mode.opmode[1]].clicked.connect(
            lambda v: toggle_opmode(v, cat.mode.opmode[1])
        )
        self.modes[cat.mode.opmode[2]].clicked.connect(
            lambda v: toggle_opmode(v, cat.mode.opmode[2])
        )
        self.modes[cat.mode.opmode[3]].clicked.connect(
            lambda v: toggle_opmode(v, cat.mode.opmode[3])
        )

        def import_file():
            fileopener = QFileDialog()
            self.ds_file = fileopener.getOpenFileName(self)[0]
            fileopener.deleteLater()
            if self.ds_file != '':
                self.doLog(f'{cat.log.route} {self.ds_file}')
            else:
                self.doLog(f'{cat.log.routerr} {[self.ds_file]}')
            # print([self.ds_file])
            self.check_begin_requirements()

        self.buttons[cat.btns.import_file].clicked.connect(import_file)
        self.buttons[cat.btns.action].clicked.connect(self.dispatchAction)

        self.passw.setPlainText(f'{self.Key_num}')
        self.initv.setPlainText(f'{self.Iv_num}')

        self.passw.textChanged.connect(self.check_begin_requirements)
        self.initv.textChanged.connect(self.check_begin_requirements)

        # initially as CFB
        self.modes[cat.mode.cfb].setChecked(True)
        toggle_opmode(True, cat.mode.cfb)

        # init view
        self.set_mode(0)
        self.check_begin_requirements()
        self.layout.addLayout(self.interactable, 0,0)
        self.layout.addLayout(self.moddable, 1,0)
        self.layout.addLayout(self.loggable, 2,0)
        self.setLayout(self.layout)
