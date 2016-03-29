# evtkit
Fix acquired .evt - Windows Event Log files (Forensics)

## Requirements
- Python 2 (not tested on 3)
- no external dependencies

## Usage
Fix in-place 2 files (Make sure you got a copy!):
```
evtkit.py AppEvent.Evt SysEvent.Evt
```
Find all *.evt files in evt_dir/, copy them to fixed_copy/ and repair them:
```
evtkit.py --copy_to_dir=fixed_copy evt_dir
```

## Options
```
-h, --help                                 show this help message and exit
-c COPY_TO_DIR, --copy_to_dir COPY_TO_DIR
                                           Output directory for fixed .evt files.
-q, --quiet                                Turn off verbosity
```
