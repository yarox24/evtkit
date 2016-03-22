#!/usr/bin/env python
import argparse, mmap, os, re, shutil, sys

VERSION = "0.1 (alpha)"
OPTION_SUFFIX = "_fixed"
PROJECT_SITE = "https://github.com/yarox24/evtkit"

# PARSER
parser = argparse.ArgumentParser(description='Fix acquired .evt - Windows Event Log files (Forensics)')
group = parser.add_mutually_exclusive_group(required=False)
group.add_argument('-i', '--in-place', action='store_true', help='Change .evt in-place (Default)')
group.add_argument('-c', '--copy', action='store_true', help='Create copy of .evt with suffix [NAME]' + OPTION_SUFFIX + '.evt')
parser.add_argument('-o', '--out-dir', nargs=1, help='Output directory for fixed .evt files. Implies -c')
parser.add_argument('-q', '--quiet', action='store_true', help='Turn off verbosity')
parser.add_argument('sources', nargs='*', action='append', help="a.evt b.evt evt_dir/")
args = parser.parse_args()


#FUNCTIONS
def qprint(text):
   if not args.quiet: print text

# -o implies -c
if args.out_dir:
   args.copy = True

# -i and -o
if args.in_place and args.out_dir:
   qprint("--out-dir implies --copy mode")

# Determine method
method = "i"
if args.copy:
   method = "c"

# Evt to work on
sources = args.sources[0]
items_number = len(sources)

# --------------------------------------------- MAIN ---------------------------------------------
qprint("evtkit v " + VERSION + "\t-== " + PROJECT_SITE + " ==-")
first_time = True
if items_number == 0:
   qprint("*** Please provide at least one .evt file or directory containing .evt files")
   qprint("")
   qprint("Examples:")
   qprint("1. Fix in-place 2 files (Make sure you got a copy!):")
   qprint(" " + sys.argv[0] + " AppEvent.Evt SysEvent.Evt")
   qprint("")
   qprint("2. Find all *.evt files in logs_dir/, copy them to fixed_copy/ and repair them:")
   qprint(" " + sys.argv[0] + " --copy --out-dir=fixed_copy logs_dir")
   sys.exit(-10)

out_dir = None
if args.out_dir:
   out_dir = args.out_dir[0].rstrip("/\\")
   if not os.path.isdir(out_dir):
      qprint("Error: " + out_dir + " is not a valid output directory")
      sys.exit(-4)

##### REBUILD STARTING FROM THIS
##### REBUILD STARTING FROM THIS
##### REBUILD STARTING FROM THIS

def check_mm_range(ptr, filesize, msg):
   if ptr > filesize:
      qprint(msg)
      return False
   return True


def fixevtfile(path):
   try:
      filesize = os.path.getsize(path)
      if filesize == 0:
         qprint("* Empty evt file - 0-byte size : %s" % (path))
         return

      f = open(path, "a+")
      mm = mmap.mmap(f.fileno(), 0)

      if not ord(mm[0]) == 0x30:
         qprint("* Invalid evt file - wrong HeaderSize (first byte), should be 0x30 is 0x%x : %s" % (ord(mm[0]), path))
         mm.close()
         f.close()
         return

      if not check_mm_range(0x24, filesize, "* Invalid evt file - too short Header: %s" % path):
         mm.close()
         f.close()
         return
      #FLAG_ELF_LOGFILE_ARCHIVE_SET = 0x8
      mm[0x24] = chr(0x8)

      # Search for floating footer
      res = re.search("\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44", mm)

      # Count events
      #t = re.findall("LfLe", mm)
      # print t
      #print len(t) - 1

      if not res:
         qprint(
            "* Invalid evt file - Cannot find floating footer (0x110x110x110x110x220x220x220x220x330x330x330x330x440x440x440x44) : %s" % path)
         mm.close()
         f.close()
         return

      ff_pointers_start = res.start() + 0x10

      mm[0x10:0x20] = mm[ff_pointers_start:ff_pointers_start + 0x10]

      mm.close()
      f.close()
   except Exception as e:
      qprint("* Error when fixing file: " + path)
      qprint("* " + e.message)


def add_suffix(path):
   filename = os.path.basename(path)
   spl = filename.split(".")
   filename = spl[0] + OPTION_SUFFIX
   if spl[1]:
      filename += "." + spl[1]
   return os.path.dirname(path) + os.path.sep + filename


def process_single_evt(path):
   global first_time
   if first_time == True:
      if not args.quiet:
         print "Choosen method: ",
      if method == "i":
         qprint("[In-place] (Default)")
      elif method == "c":
         qprint('[Copy]')
         if out_dir:
            qprint("Result will be copied to - " + out_dir)
         else:
            qprint("Result within the same directory with suffix: [NAME]" + OPTION_SUFFIX + ".evt")
      first_time = False

   qprint("-> Processing: " + path)

   if method == "i":
      fixevtfile(path)
   elif method == "c":
      if not out_dir:
         new_copy_path = add_suffix(path)
      else:
         #os.makedirs(out_dir, 0o777, True)
         new_copy_path = add_suffix(out_dir + os.path.sep + os.path.basename(path))
      print "Copying %s -> %s" % (path, new_copy_path)
      try:
         shutil.copy2(path, new_copy_path)
      except Exception as e:
         qprint("* Error when copying : %s -> %s" % (path, new_copy_path))
         qprint("* " + e.strerror)
         return
      fixevtfile(new_copy_path)

   qprint("")


for path in sources:
   if os.path.isdir(path):
      path = path.rstrip("/\\")
      files = os.listdir(path)
      for file in files:
         if file[-3:].lower() == "evt":
            full_path = path + os.path.sep + file
            process_single_evt(full_path)
   elif os.path.isfile(path):
      process_single_evt(path)
   else:
      qprint("File/directory doesn't exist: " + path)
