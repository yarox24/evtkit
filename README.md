# evtkit
Fix acquired .evt - Windows Event Log files (Forensics)

## Help
evtkit v 0.2 (beta)     -== https://github.com/yarox24/evtkit ==-
*** Please provide at least one .evt file or directory containing .evt files

Examples:
1. Fix in-place 2 files (Make sure you got a copy!):
 evtkit.py AppEvent.Evt SysEvent.Evt

2. Find all *.evt files in evt_dir/, copy them to fixed_copy/ and repair them:
 evtkit.py --copy_to_dir=fixed_copy evt_dir
