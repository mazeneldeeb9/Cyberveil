from pathlib import Path
import sys

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

root = Path(SPECPATH).parent
datas = collect_data_files("cyberveil") + copy_metadata("cyberveil")
a = Analysis(
    [str(root / "packaging" / "launcher.py")],
    pathex=[str(root / "src")],
    datas=datas,
    hiddenimports=["sklearn.linear_model._logistic", "sklearn.preprocessing._data"],
    excludes=["pytest", "matplotlib", "IPython", "notebook", "tkinter", "PySide6.QtWebEngineCore"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="CYBERVEIL", console=True)
demo_scripts = [entry for entry in a.scripts if entry[0] != "launcher"]
demo_scripts.append(("demo_child", str(root / "packaging" / "demo_child.py"), "PYSOURCE"))
demo = EXE(pyz, demo_scripts, [], exclude_binaries=True, name="CYBERVEIL-demo", console=True)
coll = COLLECT(exe, demo, a.binaries, a.datas, name="CYBERVEIL")
if sys.platform == "darwin":
    app = BUNDLE(coll, name="CYBERVEIL.app", bundle_identifier="lab.cyberveil.desktop",
                 info_plist={"CFBundleShortVersionString": "0.3.0", "NSHighResolutionCapable": True})
