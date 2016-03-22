# evtkit
Fix acquired .evt - Windows Event Log files (Forensics)

positional arguments:
  sources               a.evt b.evt evt_dir/

optional arguments:
  -h, --help            show this help message and exit
  -i, --in-place        Change .evt in-place (Default)
  -c, --copy            Create copy of .evt with suffix [NAME]_fixed.evt
  -o OUT_DIR, --out-dir OUT_DIR
                        Output directory for fixed .evt files. Implies -c
  -q, --quiet           Turn off verbosity

Examples
1. Fix in-place 2 files (Make sure you got a copy!):
 evtkit.py AppEvent.Evt SysEvent.Evt

2. Find all *.evt files in logs_dir/, copy them to fixed_copy/ and repair them:
 evtkit.py --copy --out-dir=fixed_copy logs_dir
