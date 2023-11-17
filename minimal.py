from PySide6.QtGui import QPalette, QColor
from PySide6.QtWidgets import QWidget

class minimal(QWidget):
    title_dsp = None

    def __init__(self, title_dsp, color):
        super(minimal, self).__init__()
        self.title_dsp = title_dsp
        self.set_color(color)

    def set_color(self, color):
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(color))
        self.setPalette(palette)