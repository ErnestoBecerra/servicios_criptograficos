from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QMainWindow, QGridLayout, QWidget
from text_catalog import txt_window, txt_main_menu
from practica0 import practica0 as p0
import sys
from minimal import minimal

class Application:
    runtime = None
    window = None

    df_state = None
    curr_state = None

    apps = None

    def __init__(self):
        self.runtime = QApplication(sys.argv)
        self.window = QMainWindow()

        self.apps = dict()

        self.df_state = minimal(txt_window.title, txt_window.df_color)
        self.add_states( [self.df_state] )
        self.goto_default_state()

        self.runtime.setWindowIcon( QIcon(txt_window.app_icon) )
        self.runtime.setActiveWindow(self.window)
        self.runtime.setApplicationDisplayName(txt_window.app_name)

        self.window.setFixedWidth(txt_window.width)
        self.window.setFixedHeight(txt_window.height)

        # obtiene la geometria de la pantalla
        # print(self.runtime.primaryScreen().size())


    def deploy(self):
        self.window.show()
        self.runtime.exec()

    # with dependency injection
    def add_states(self, arr:[minimal]):
        for i in arr:
            self.apps[i.title_dsp] = i
        print(self.apps)

    def set_state(self, name:str):
        print(f'state {name}')
        v = self.apps[name]
        self.curr_state = v
        self.window.setCentralWidget(v)
        self.window.setWindowTitle(v.title_dsp)

    def goto_default_state(self):
        self.set_state(self.df_state.title_dsp)






def main():
    App = Application()

    pract_menu = minimal(txt_main_menu.title, txt_main_menu.df_color)
    pr0 = p0()
    
    practicas = [pract_menu, pr0]
    App.add_states(practicas)

    App.set_state(pr0.title_dsp)
    # App.set_state(pract_menu.title_dsp)

    App.deploy()


if __name__ == '__main__':
    main()
