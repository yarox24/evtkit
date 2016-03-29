#!/usr/bin/env python
import argparse, mmap, os, re, shutil, sys

VERSION = "0.2 (beta)"
OPTION_SUFFIX = "_fixed"
PROJECT_SITE = "https://github.com/yarox24/evtkit"

# PARSER
parser = argparse.ArgumentParser(description='Fix acquired .evt - Windows Event Log files (Forensics)')
parser.add_argument('-c', '--copy_to_dir', nargs=1, help='Output directory for fixed .evt files.')
parser.add_argument('-q', '--quiet', action='store_true', help='Turn off verbosity')
parser.add_argument('sources', nargs='*', action='append', help="a.evt b.evt evt_dir/ [...]")
args = parser.parse_args()

#FUNCTIONS
def qprint(text):
   if not args.quiet: print text

#MODE
CURRENT_MODE = "i" # IN-PLACE
if args.copy_to_dir:
   CURRENT_MODE = "c" # COPY
   OUT_DIR = args.copy_to_dir[0].rstrip("/\\")
   if not os.path.isdir(OUT_DIR):
      os.makedirs(OUT_DIR)
      if not os.path.isdir(OUT_DIR):
         qprint("Error: " + OUT_DIR + " cannot create directory")
         sys.exit(-4)

# SOURCES
sources = args.sources[0]
items_number = len(sources)
COUNTER = 1

def check_mm_range(ptr, filesize):
   return not ptr > filesize

def fixevtfile(path):
   try:
      filesize = os.path.getsize(path)
      if filesize == 0:
         return "Empty evt file - 0-byte size"

      f = open(path, "a+")
      mm = mmap.mmap(f.fileno(), 0)

      if not ord(mm[0]) == 0x30:
         return "Invalid evt file - wrong HeaderSize (first byte), should be 0x30 is 0x%x" % (ord(mm[0]))

      if not check_mm_range(0x24, filesize):
         return "Invalid evt file - too short Header"

      mm[0x24] = chr(0x8)  #FLAG_ELF_LOGFILE_ARCHIVE_SET = 0x8

      # Search for floating footer
      res = re.search("\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33\x44\x44\x44\x44", mm)

      if not res:
         return "Invalid evt file - Cannot find floating footer (0x110x110x110x110x220x220x220x220x330x330x330x330x440x440x440x44)"

      if not check_mm_range(res.start() + 0x10, filesize):
         return "Invalid evt file - floating footer too short"
      ff_pointers_start = res.start() + 0x10

      mm[0x10:0x20] = mm[ff_pointers_start:ff_pointers_start + 0x10]

      # Count events
      count_lfle = len(re.findall("LfLe", mm)) - 1
      mm.close()
      f.close()

      return "Fixed, " + str(count_lfle) + " possible events"
   except Exception as e:
      return "Exception: " + e.message

def add_suffix(path):
   filename = os.path.basename(path)
   spl = filename.split(".")
   filename = spl[0] + OPTION_SUFFIX
   if len(spl) > 1 and spl[1]:
      filename += "." + spl[1]
   return os.path.dirname(path) + os.path.sep + filename


def process_single_evt(path):
   global COUNTER
   global CURRENT_MODE
   global OUT_DIR

   if CURRENT_MODE == "i":
      result = fixevtfile(path)
   elif CURRENT_MODE == "c":
      new_copy_path = add_suffix(OUT_DIR + os.path.sep + os.path.basename(path))
      try:
         shutil.copy2(path, new_copy_path)
         result = fixevtfile(new_copy_path)
      except Exception as e:
         result = "Error when copying to: " + new_copy_path + " " + e.strerror

   qprint('{0: <3}'.format(str(COUNTER)+'.') + " " + path + " [" + result + "]")
   COUNTER += 1


def main():
   qprint("evtkit v " + VERSION + "\t-== " + PROJECT_SITE + " ==-")

   if items_number == 0:
      qprint("*** Please provide at least one .evt file or directory containing .evt files")
      qprint("")
      qprint("Examples:")
      qprint("1. Fix in-place 2 files (Make sure you got a copy!):")
      qprint(" " + sys.argv[0] + " AppEvent.Evt SysEvent.Evt")
      qprint("")
      qprint("2. Find all *.evt files in evt_dir/, copy them to fixed_copy/ and repair them:")
      qprint(" " + sys.argv[0] + " --copy_to_dir=fixed_copy evt_dir")
      sys.exit(-10)

   if not args.quiet:
      print "Choosen method: ",
   if CURRENT_MODE == "i":
      qprint("[In-place] (Default)")
   elif CURRENT_MODE == "c":
      qprint('[Copy]')
      qprint("Result will be copied to - " + OUT_DIR)

   # ITERATE OVER SOURCES
   for path in sources:
      if os.path.isdir(path):
         path = path.rstrip("/\\")
         try:
            files = os.listdir(path)
         except Exception as e:
            qprint("Error when listing directory: %s" % (path) + " [" + e.strerror + "]")
            continue
         for file in files:
            if file[-3:].lower() == "evt":
               full_path = path + os.path.sep + file
               process_single_evt(full_path)
      elif os.path.isfile(path):
         process_single_evt(path)
      else:
         qprint("Error: File/directory doesn't exist: " + path)

      qprint("")

if __name__ == "__main__":
   main()