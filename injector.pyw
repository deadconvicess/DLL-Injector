# Coded by @deadconvicess
# Github Repo  - https://github.com/deadconvicess/DLL-Injector

import sys
import os
import psutil
import ctypes
from ctypes import wintypes
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QListWidget, QFileDialog, QLabel, QLineEdit, QComboBox, QFrame
)
from PyQt5.QtGui import QIcon, QMovie, QPixmap
from PyQt5.QtCore import Qt, QTimer, QPoint
import win32gui
import win32process

if sys.executable.endswith("pythonw.exe"):
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")

ROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

def setup_api():
    global OpenProcess, VirtualAllocEx, WriteProcessMemory
    global GetModuleHandleA, GetProcAddress, CreateRemoteThread, NtCreateThreadEx

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    OpenProcess.restype = wintypes.HANDLE

    VirtualAllocEx = kernel32.VirtualAllocEx
    VirtualAllocEx.argtypes = (
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
        wintypes.DWORD, wintypes.DWORD
    )
    VirtualAllocEx.restype = wintypes.LPVOID

    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = (
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
    )
    WriteProcessMemory.restype = wintypes.BOOL

    GetModuleHandleA = kernel32.GetModuleHandleA
    GetModuleHandleA.argtypes = (wintypes.LPCSTR,)
    GetModuleHandleA.restype = wintypes.HANDLE

    GetProcAddress = kernel32.GetProcAddress
    GetProcAddress.argtypes = (wintypes.HANDLE, wintypes.LPCSTR)
    GetProcAddress.restype = wintypes.LPVOID

    CreateRemoteThread = kernel32.CreateRemoteThread
    CreateRemoteThread.argtypes = (
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
        wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)
    )
    CreateRemoteThread.restype = wintypes.HANDLE

    NtCreateThreadEx = ntdll.NtCreateThreadEx
    NtCreateThreadEx.argtypes = (
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
        wintypes.LPVOID, wintypes.HANDLE, wintypes.LPVOID,
        wintypes.LPVOID, wintypes.BOOL, wintypes.ULONG,
        wintypes.ULONG, wintypes.ULONG, wintypes.LPVOID
    )
    NtCreateThreadEx.restype = wintypes.LONG

setup_api()

class TitleBar(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.setFixedHeight(30)
        self.setStyleSheet("background-color: rgba(26,42,108,0.9);")
        self.mousePos = None
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5,0,5,0)
        layout.setSpacing(5)
        logo = QLabel(self)
        icon_pixmap = QPixmap('icons/injector_icon.png')
        if icon_pixmap.isNull():
            icon_pixmap = QPixmap(20, 20)
            icon_pixmap.fill(Qt.transparent)
        logo.setPixmap(icon_pixmap.scaled(20,20, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        layout.addWidget(logo)
        self.title = QLabel("simple injector v1.0.0", self)
        self.title.setStyleSheet("color: #fff; font-weight: bold;")
        layout.addWidget(self.title)
        layout.addStretch()
        btn_min = QPushButton("–", self)
        btn_min.setFixedSize(30,30)
        btn_min.setStyleSheet("background:transparent; color:#fff; font-size:18px;")
        btn_min.clicked.connect(self.parent.showMinimized)
        layout.addWidget(btn_min)
        btn_close = QPushButton("\u2715", self)
        btn_close.setFixedSize(30,30)
        btn_close.setStyleSheet("background:transparent; color:#fff; font-size:18px;")
        btn_close.clicked.connect(self.parent.close)
        layout.addWidget(btn_close)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.mousePos = event.globalPos()
            event.accept()

    def mouseMoveEvent(self, event):
        if self.mousePos:
            delta = event.globalPos() - self.mousePos
            self.parent.move(self.parent.pos() + delta)
            self.mousePos = event.globalPos()
            event.accept()

    def mouseReleaseEvent(self, event):
        self.mousePos = None
        event.accept()

class InjectorGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAcceptDrops(True)
        self.setFixedSize(660,400)
        self.setStyleSheet("""
            QWidget { background: qlineargradient(x1:0,y1:0,x2:1,y2:1,
                stop:0 #1a2a6c, stop:1 #b21f1f); color:#fff; }
            QPushButton { background:rgba(0,0,0,0.4); padding:8px; border-radius:4px; }
            QPushButton:hover { background:rgba(0,0,0,0.6); }
            QListWidget { background:rgba(0,0,0,0.3); border:1px solid #fff; }
            QLineEdit,QComboBox{background:rgba(0,0,0,0.3);
                border:1px solid #fff; border-radius:3px; padding:4px; }
            QLabel{font-weight:bold; }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0,0,0,0)
        self.titleBar = TitleBar(self)
        layout.addWidget(self.titleBar)

        body = QVBoxLayout()
        self.status = QLabel("Press 'Detect Game' to find Your Game Processes.")
        body.addWidget(self.status)

        self.procList = QListWidget()
        body.addWidget(self.procList)

        btn_detect = QPushButton(" Detect Game")
        btn_detect.setIcon(QIcon('icons/detect_icon.png'))
        btn_detect.clicked.connect(self.detect_game)
        body.addWidget(btn_detect)

        self.spinner = QLabel(self)
        self.spinner.setAlignment(Qt.AlignCenter)
        self.spinner_movie = QMovie('icons/spinner.gif')
        if not self.spinner_movie.isValid():
            self.spinner_movie = QMovie()
        self.spinner.setMovie(self.spinner_movie)
        self.spinner.hide()
        body.addWidget(self.spinner)

        pathLayout = QHBoxLayout()
        self.dllPath = QLineEdit()
        self.dllPath.setPlaceholderText("Drop DLL here or click Browse...")
        pathLayout.addWidget(self.dllPath)
        btn_browse = QPushButton(" Browse")
        btn_browse.setIcon(QIcon('icons/browse_icon.png'))
        btn_browse.clicked.connect(self.browse_dll)
        pathLayout.addWidget(btn_browse)
        body.addLayout(pathLayout)

        self.methodCombo = QComboBox()
        self.methodCombo.addItems(["LoadLibraryA","NtCreateThreadEx"])
        body.addWidget(self.methodCombo)

        btn_inject = QPushButton(" Inject DLL")
        btn_inject.setIcon(QIcon('icons/inject_icon.png'))
        btn_inject.clicked.connect(self.inject)
        body.addWidget(btn_inject)

        container = QWidget()
        container.setLayout(body)
        layout.addWidget(container)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            path = urls[0].toLocalFile()
            if path.lower().endswith('.dll'):
                self.dllPath.setText(path)
    def detect_game(self):
        self.procList.clear()
        self.status.setText("Detecting...")
        self.spinner.show(); self.spinner_movie.start()
        QTimer.singleShot(1500, self.finish_detect)

    def finish_detect(self):
        self.spinner_movie.stop(); self.spinner.hide()
        common_games = {
            'robloxplayerbeta.exe', 'roblox.exe', 'javaw.exe', 'java.exe',
            'fortniteclient-win64-shipping.exe', 'cs2.exe', 'csgo.exe',
            'valorant.exe', 'hl2.exe', 'gta5.exe', 'eldenring.exe',
            'minecraft.exe', 'RDR2.exe', 'leagueclient.exe',
            'apex.exe', 'warzone.exe',
        }
        game_procs = []
        other_procs = []
        window_titles = {}
        def enum_cb(hwnd, _):
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            title = win32gui.GetWindowText(hwnd)
            if title:
                window_titles[pid] = title
        win32gui.EnumWindows(enum_cb, None)
        for p in psutil.process_iter(['pid', 'name']):
            try:
                name = p.info['name']
                pid = p.info['pid']
                label = f"{name} [{pid}]"
                if pid in window_titles:
                    label += f" - {window_titles[pid]}"
                if name.lower() in common_games:
                    game_procs.append(label)
                else:
                    other_procs.append(label)
            except:
                continue
        for item in sorted(game_procs): self.procList.addItem(item)
        for item in sorted(other_procs): self.procList.addItem(item)
        self.status.setText("\u2705 Select a process and click 'Inject DLL'" if self.procList.count() else "\u274C No processes found.")

    def browse_dll(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select DLL", os.getcwd(), "DLL Files (*.dll)")
        if path:
            self.dllPath.setText(path)

    def inject(self):
        sel = self.procList.currentItem()
        dll = self.dllPath.text().strip()
        if not sel or not dll or not os.path.isfile(dll):
            self.status.setText("\u274C Select a process and valid DLL.")
            self.status.setStyleSheet("color: red;")
            return
        pid = int(sel.text().split('[')[-1].split(']')[0])
        method = self.methodCombo.currentText()
        try:
            self.spinner.show(); self.spinner_movie.start()
            h = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            addr = VirtualAllocEx(h, None, len(dll)+1, MEM_COMMIT, PAGE_READWRITE)
            WriteProcessMemory(h, addr, dll.encode()+b'\0', len(dll)+1, ctypes.byref(ctypes.c_size_t()))
            fk = GetModuleHandleA(b"kernel32.dll")
            fn = GetProcAddress(fk, b"LoadLibraryA")
            if method == "LoadLibraryA":
                CreateRemoteThread(h, None, 0, fn, addr, 0, ctypes.byref(wintypes.DWORD()))
            else:
                if NtCreateThreadEx:
                    th = wintypes.HANDLE()
                    NtCreateThreadEx(ctypes.byref(th), PROCESS_ALL_ACCESS, None,
                                     h, fn, addr, False, 0, 0, 0, None)
                else:
                    raise RuntimeError("NtCreateThreadEx not available.")
            self.spinner_movie.stop(); self.spinner.hide()
            self.status.setText("\u2705 injected Your DLL")
            self.status.setStyleSheet("color: green;")
        except Exception as e:
            self.spinner_movie.stop(); self.spinner.hide()
            self.status.setText(f"\u274C Failed {e}")
            self.status.setStyleSheet("color: red;")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = InjectorGUI()
    gui.show()

    sys.exit(app.exec_())

