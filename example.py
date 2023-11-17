import atexit
import base64
from random import randint
import os
from uuid import uuid4

from minimal import minimal

from cryptography.fernet import Fernet

from PySide6.QtGui import QIcon, QPixmap, QImage
from PySide6.QtWidgets import QGridLayout, QPushButton, QFileDialog, QPlainTextEdit, QLabel

from text_catalog import txt_practica0

class practica0(minimal):
    title_dsp = None

    fileopener = None
    info_area = None
    file_area = None
    info_txt = None
    file_txt = None
    left_hs = None
    button_area = None
    buttons = None

    curr_data = None

    key_prompt = None

    cipher_suite = None
    complete_log : [str] = None
    layout = None

    key = None
    file = None
    sv_file = None

    def log(self, string):
        self.complete_log.append(string)
        self.info_txt.appendPlainText(string)
        # logstr = '\n'.join(self.complete_log)
        # self.info_txt.setPlainText(logstr)

    def refresh_txt_and_vis(self):
        if not self.is_bmp:
            try:
                self.visual.setPlainText(self.curr_data.decode('utf-8'))
            except:
                self.visual.setPlainText(str(base64.encodebytes(self.curr_data)))
        else:
            pix = QPixmap(QImage(self.file).scaled(txt_practica0.layout.lhs, txt_practica0.layout.vis_h))
            self.visual.setPixmap(pix)


        self.file_txt.setPlainText(str(base64.encodebytes(self.curr_data)))
        self.set_state(1)

    def __quick_read__(self, file_name):
        data = None
        if file_name != None and file_name != '':
            with open(file_name, 'rb') as fd:
                data = fd.read(-1)
        return data

    def __at_init__(self):
        self.__at_exit__()
        os.mkdir(txt_practica0.cfg.tmp_dir)

    def __at_exit__(self):
        os.system(txt_practica0.cfg.tmp_dir_rm)

    def __set_vis_mode__(self):
        self.visual.deleteLater()
        self.visual_area.removeWidget(self.visual)

        if self.file.lower().endswith(txt_practica0.cfg.accept_img):
            self.visual = QLabel()
            self.is_bmp = True
        else:
            self.visual = QPlainTextEdit()
            self.visual.setReadOnly(True)
            self.is_bmp = False

        self.visual.setFixedWidth(txt_practica0.layout.lhs)
        self.visual.setFixedHeight(txt_practica0.layout.vis_h)
        self.visual_area.addWidget(self.visual)

    def import_file(self):
        self.fileopener = QFileDialog()
        self.file = self.fileopener.getOpenFileName(self)[0]

        if self.file != '':
            self.sv_file = self.file
            self.__set_vis_mode__()
            self.curr_data = None
            self.key = None
            self.curr_data = self.__quick_read__(self.file)
            self.refresh_txt_and_vis()
            self.log(txt_practica0.log.file + self.file)

        self.set_state(4)
        self.set_state(5)

    def __update_file__(self):
        nxt_f = f'{txt_practica0.cfg.tmp_dir}/{str(uuid4())}{txt_practica0.cfg.bmp_ext}'
        self.file = nxt_f
        with open(nxt_f, 'wb') as fd:
            fd.write(self.curr_data)
        self.curr_data = self.__quick_read__(nxt_f)

    def set_state(self, n):
        # QPushButton().setDisabled()
        if n == 0:
            self.buttons[txt_practica0.btns.export_file].setDisabled(True)
            self.buttons[txt_practica0.btns.export_plain].setDisabled(True)
            self.buttons[txt_practica0.btns.action].setDisabled(True)
            self.buttons[txt_practica0.btns.decipher].setDisabled(True)
        elif n == 1:
            self.buttons[txt_practica0.btns.export_file].setDisabled(True)
            self.buttons[txt_practica0.btns.action].setDisabled(False)
            self.buttons[txt_practica0.btns.decipher].setDisabled(False)
        elif n == 2:
            self.buttons[txt_practica0.btns.action].setDisabled(True)
            self.buttons[txt_practica0.btns.export_plain].setDisabled(True)
            self.buttons[txt_practica0.btns.export_file].setDisabled(False)
            self.buttons[txt_practica0.btns.decipher].setDisabled(False)
        elif n == 3:
            self.buttons[txt_practica0.btns.action].setDisabled(False)
            self.buttons[txt_practica0.btns.export_plain].setDisabled(False)
            self.buttons[txt_practica0.btns.export_file].setDisabled(True)
            # self.buttons[txt_practica0.btns.decipher].setDisabled(True)
        elif n == 4:
            self.buttons[txt_practica0.btns.export_plain].setDisabled(True)
        elif n == 5:
            self.buttons[txt_practica0.btns.export_file].setDisabled(True)

    def cipher(self):
        if self.is_bmp:
            self.key = randint(txt_practica0.cfg.bmp_rd_key_min, txt_practica0.cfg.bmp_rd_key_max)
            print(self.key)
            self.curr_data = self.curr_data[:txt_practica0.cfg.bmp_head_size] + \
                             bytes(map(lambda a: (a+self.key)%txt_practica0.cfg.bmp_mod,
                                       self.curr_data[txt_practica0.cfg.bmp_head_size:]))
            self.__update_file__()
        # self.key_prompt = QInputDialog(self)
        # self.key = self.key_prompt.getText(self, '', txt_practica0.prompt.key)[0]
        else:
            self.key = Fernet.generate_key()
            self.cipher_suite = Fernet(self.key)
            self.curr_data = self.cipher_suite.encrypt(self.curr_data)

        self.refresh_txt_and_vis()
        self.log(txt_practica0.log.key + str(self.key))
        self.set_state(2)

    def decipher(self):

        if self.key == None:
            self.key_prompt = QFileDialog()
            key_file = self.key_prompt.getOpenFileName()[0]
            if key_file == '':
                self.log(txt_practica0.log.please_key)
                return
            self.key = self.__quick_read__(key_file)

        if not self.is_bmp:

            try:
                self.cipher_suite = Fernet(self.key)
            except:
                self.log(txt_practica0.log.please_key)
                self.key = None
                return

            try:
                self.curr_data = self.cipher_suite.decrypt(self.curr_data)
            except:
                self.log(txt_practica0.log.wrongk)
                self.key = None
        else:
            self.key = int(str(self.key).strip("b'").strip("'"))
            print(self.key)
            self.curr_data = self.curr_data[:txt_practica0.cfg.bmp_head_size] + \
                 bytes(map(lambda a: (a-self.key)%txt_practica0.cfg.bmp_mod,
                           self.curr_data[txt_practica0.cfg.bmp_head_size:]))
            self.key = None
            self.__update_file__()

        self.refresh_txt_and_vis()
        self.set_state(3)

    def export_file(self):
        ename = self.sv_file + (txt_practica0.cfg.extension if not self.is_bmp else txt_practica0.cfg.bmp_ext)
        kname = self.sv_file + txt_practica0.cfg.kextension

        with open(ename, 'wb') as fd:
            fd.write(self.curr_data)

        if not self.is_bmp:
            with open(kname, 'wb') as kfd:
                kfd.write(self.key)
        else:
            with open(kname, 'w') as kfd:
                kfd.write(str(self.key))

        self.log(txt_practica0.log.expf + ename)
        self.log(txt_practica0.log.expk + kname)
        self.set_state(5)

    def export_plain(self):
        pname = self.sv_file.strip(txt_practica0.cfg.extension) + (txt_practica0.cfg.extension if not self.is_bmp else txt_practica0.cfg.bmp_ext)
        with open(pname, 'wb') as fd:
            fd.write(self.curr_data)
        self.log(txt_practica0.log.expf + pname)
        self.set_state(4)

    def changeMode(self, data):
        if data == txt_practica0.mode.cipher:
            self.buttons[txt_practica0.btns.meta_mode].setText(txt_practica0.btns.as_cipher)
            self.buttons[txt_practica0.btns.export_file].show()
            self.buttons[txt_practica0.btns.action].show()
            self.buttons[txt_practica0.btns.export_plain].hide()
            self.buttons[txt_practica0.btns.decipher].hide()
        else:
            self.buttons[txt_practica0.btns.meta_mode].setText(txt_practica0.btns.as_decipher)
            self.buttons[txt_practica0.btns.export_file].hide()
            self.buttons[txt_practica0.btns.action].hide()
            self.buttons[txt_practica0.btns.export_plain].show()
            self.buttons[txt_practica0.btns.decipher].show()
        print(data)

    def __init__(self):
        super(practica0, self).__init__(txt_practica0.title, txt_practica0.df_color)

        self.__at_init__()
        atexit.register(self.__at_exit__)
        self.complete_log = []

        # main layout
        self.layout = QGridLayout()
        self.layout.setSpacing(txt_practica0.layout.grid_spacin)

        # buttons area // right side

        self.button_area = QGridLayout()
        self.button_area.setSpacing(txt_practica0.layout.btn_spacin)
        self.layout.addLayout(self.button_area, 0,1)

        opn = QIcon(txt_practica0.icn.fopen)
        exp = QIcon(txt_practica0.icn.fexp)
        cry = QIcon(txt_practica0.icn.fciph)
        dcry = QIcon(txt_practica0.icn.fdciph)

        self.buttons = {
            txt_practica0.btns.meta_mode : QPushButton(cry, txt_practica0.btns.as_cipher),
            txt_practica0.btns.import_file : QPushButton(opn, txt_practica0.btns.import_file),
            txt_practica0.btns.export_plain : QPushButton(exp, txt_practica0.btns.export_plain),
            txt_practica0.btns.export_file : QPushButton(exp, txt_practica0.btns.export_file),
            txt_practica0.btns.action : QPushButton(cry, txt_practica0.btns.action),
            txt_practica0.btns.decipher : QPushButton(dcry, txt_practica0.btns.decipher),
        }

        vpos = 0
        for k,v in self.buttons.items():
            v.setFixedHeight(txt_practica0.layout.btn_h)
            v.setFixedWidth(txt_practica0.layout.btn_w)
            self.button_area.addWidget(v, vpos,0)
            vpos += 1

        # left side of the layout // not the right side (where buttons)
        self.left_hs = QGridLayout()
        self.left_hs.setSpacing(txt_practica0.layout.grid_spacin)
        self.layout.addLayout(self.left_hs, 0,0)

        # visual area // left side top
        self.visual_area = QGridLayout()
        self.visual = QPlainTextEdit()
        self.visual.setReadOnly(True)
        self.visual.setFixedWidth(txt_practica0.layout.lhs)
        self.visual.setFixedHeight(txt_practica0.layout.vis_h)
        self.visual_area.addWidget(self.visual, 0,0)
        self.left_hs.addLayout(self.visual_area, 0,0)

        # file area // left side middle
        self.file_area = QGridLayout()
        self.file_txt = QPlainTextEdit()
        self.file_txt.setReadOnly(True)
        self.file_txt.setFixedWidth(txt_practica0.layout.lhs)
        self.file_txt.setFixedHeight(txt_practica0.layout.txt_h)
        self.file_area.addWidget(self.file_txt, 0,0)
        self.left_hs.addLayout(self.file_area, 1,0)

        # info area // left side bottom
        self.info_area = QGridLayout()
        self.info_txt = QPlainTextEdit()
        self.info_txt.setReadOnly(True)
        self.info_txt.setFixedWidth(txt_practica0.layout.lhs)
        self.info_txt.setFixedHeight(txt_practica0.layout.log_h)
        self.info_area.addWidget(self.info_txt, 0,0)
        self.left_hs.addLayout(self.info_area, 2,0)

        #events
        self.buttons[txt_practica0.btns.import_file].clicked.connect(self.import_file)
        self.buttons[txt_practica0.btns.action].clicked.connect(self.cipher)
                # main mode // cipher or decipher
        self.buttons[txt_practica0.btns.meta_mode].setCheckable(True)
        self.buttons[txt_practica0.btns.meta_mode].clicked.connect(self.changeMode)

        # initialize the view
        self.set_state(0)
        self.changeMode(txt_practica0.mode.cipher)
        self.setLayout(self.layout)
