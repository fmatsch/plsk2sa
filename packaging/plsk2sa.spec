# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: one self-contained executable per platform.
#   pyinstaller packaging/plsk2sa.spec
# Data files are listed explicitly so that no build host needs the package installed.
from pathlib import Path

root = Path(SPECPATH).parent

a = Analysis(
    [str(root / "packaging" / "entry.py")],
    pathex=[str(root)],
    datas=[
        (str(root / "plsk2sa" / "ui" / "static"), "plsk2sa/ui/static"),
        (str(root / "plsk2sa" / "templates"), "plsk2sa/templates"),
    ],
    hiddenimports=["plsk2sa.ui.server", "yaml"],
    excludes=["tkinter", "unittest.mock"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="plsk2sa",
    debug=False,
    strip=False,
    upx=False,
    console=True,  # keep the console: it shows the local link and the log
)
