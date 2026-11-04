# -*- mode: python ; coding: utf-8 -*-
import glob
import sys

datas, binaries, hiddenimports = [], [], []
if sys.platform != "win32":
    sys.path.extend(glob.glob("/usr/lib/python*/site-packages"))
    sys.path.extend(glob.glob("/usr/lib/python*/dist-packages"))

datas.append(("static", "static"))
hiddenimports += [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.http.httptools_impl",
    "uvicorn.lifespan.on",
]
if sys.platform == "win32":
    hiddenimports.append("webview.platforms.winforms")
else:
    hiddenimports.append("webview.platforms.gtk")

a = Analysis(
    ["desktop.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={
        "gi": {
            "icons": ["Adwaita"],
            "themes": [],
            "languages": [],
        }
    },
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="LASS",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)
