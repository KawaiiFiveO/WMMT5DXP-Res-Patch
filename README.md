# WMMT5DX+ Resolution Patch

This is a resolution patch for the WMMT5DX+ Japanese Update 5 Dump (2017). It will not work with the English (2016) version.

## Usage

Download the latest zip from [Releases](../../releases) and follow the instructions in `README.txt`.

## Script

Already have Python? Download `patch.py`, place it in your game directory, and run the script:

```
pip install pefile
python patch.py
```

## Building

Requires Python 3 on Windows:

```
pip install pyinstaller pefile
pyinstaller --onefile --name patch patch.py
```

The exe is written to `dist/patch.exe`.
