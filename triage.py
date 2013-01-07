####################################################################################
# triage.py
# 		Automation script for running the !exploitable (bang exploitable) WinDbg 
# command against a set of potential crash files.  Creates a directory structure 
# according to it's findings in order to sort the triaged files.  
#
# 		The files are grouped according to the hash assigned to each crash by 
# !exploitable.  Each crash is grouped by the hash that !exploitable assigns 
# to the crash.  Similar crashes are then placed into a directory named after
# the group hash.  From there, the groups are sorted into two categories;
# one group where the register states change between crashes, and another
# where they do now.  The follwoing registers are checked during this time:
#
# 		- EAX
# 		- EBX
#  		- ECX
# 		- EDX
# 		- EDI
# 		- ESI
# 		- EBP
# 		- ESP
#
# 		All crash groups with varying register states are placed in the 
# "RegistersChanged" directory, others are left in the main directory.  
# From here, all crash groups are evaluated for the highest crash rating
# assigned to any member of the group, the group is placed into a directory 
# associated with that rating.  Finally, any crash files that failed to 
# reproduce during this process are placed in a directory called: 
# "UnableToReproduce".
#
# Structure is as follows:
# - Crashes
#		- RegistersChanged 
#			- EXPLOITABLE
#				- [Crash_Hash]
#					- [Files]
#			- PROBABLY EXPLOITABLE
#				- [Crash_Hash]
#					- [Files]
#			- UNKNOWN
#				- [Crash_Hash]
#					- [Files]
#			- PROBABLY NOT EXPLOITABLE
#				- [Crash_Hash]
#					- [Files]
# 		- EXPLOITABLE
#			- [Crash_Hash]
#				- [Files]
# 		- PROBABLY EXPLOITABLE
#			- [Crash_Hash]
#				- [Files]
# 		- UNKNOWN
#			- [Crash_Hash]
#				- [Files]
#		- PROBABLY NOT EXPLOITABLE
#			- [Crash_Hash]
#				- [Files]
#		- UnableToReproduce
#			[Files]		
####################################################################################
# Dependencies:
#		- psutil python library (http://code.google.com/p/psutil/) 
# 		- WinDbg (http://msdn.microsoft.com/en-us/windows/hardware/gg463009.aspx)
# 		- GFlags (http://msdn.microsoft.com/en-us/windows/hardware/gg463009.aspx)
# 		- !exploitable WinDbg extension (http://msecdbg.codeplex.com/)
####################################################################################
# Additional Installation Notes:
# 		The following WinDbg Script needs to be placed in the same directory as
# the WinDbg executable.  It should be called "monitor.wds".
'''
* monitor.wds - run this script upon launching an executable, 
*      when a crash occurs a file named "crash_details.txt" 
*      is written to the local directory.  Uses !exploitable
*      to determine exploitability.

sxr
ad *

.block
{
	aS ${/v:break} ".echo ********************************************************************************;"
	aS ${/v:logfile} "crash_details.txt"

	.block
	{
		sxe -c "gN;" -c2 "!load msec.dll; .logopen ${logfile}; ${break}; !exploitable; ${break}; .lastevent; ${break}; r; ${break}; u; ${break}; k; q;" -h av
	}
}

sxi gp
sxi ii
sxi asrt
sxi aph
sxi bpe
sxi eh
sxi clr 
sxi clrn
sxi cce
sxi dm
sxi ip
sxi dz
sxi iov
sxi ch
sxi isc
sxi 3c
sxi svh
sxi sse
sxi sbo
sxi sov
sxi vs
sxi wkd
sxi wob
sxi wos

'''
####################################################################################
# Usage:
Usage = '''
python triage.py [options] [target application]
options:

-b [path to base directory]
	path to directory containing input files to be triaged
	Default: "Crashes"
-o [path to output directory]
	path to directory where trace files should be written to
	Default: "Crashes"
-w [path to WinDbg Installation]
	path to the installation of WinDbg
	Default: "WinDbg"
-t [path to test file directory]
	path where test files are stored.  Each iteration of the fuzzer
	will create two copies of the fuzzed file, one to store in the output
	directory and one to test.  This avoids any changes to the test file 
	during testing that may be caused by auto save and sanitize features 
	in the target program.  This file is always deleted after every test.
	Default: "Tests"
-a [arguments]
	string representing additional arguements to be passed to the target
	application during each test.
	Default: ""
-i [report interval]
	number of test cases to report progress, progress only reported if -v 
	is also specified
	Default: 1
-m [time in seconds]
	max amount of time to allow for each test
	Default: 10 seconds
-k 
	Enable an embedded window_killer to attempt to automatically deal with 
	dialog boxes spawned by the program.  This window_killer is spawned
	for each instance of the target application that is spawned and only 
	deals with windows belonging to the target's PID
-e
	Uses the window_killer to attempt to close the main window of the target
	application before killing the process.  This is used to trigger any 
	events that might occur upon closing the application normally for process
	cleanup
-g
	Do not use GFlags while triaging.
-c
	Run in continuous mode.  The base directory is constantly checked for 
	new files to triage.  This is usefull when running a fuzzer in 
	parallel, and will allow crash files to be triaged as they are found. 
-v 
	Verbose Mode, includes progress updates and error messages
-h 
	Print the usage message and exit
'''
####################################################################################
# Imports:
import subprocess, os, shutil, time, hashlib, sys, getopt
import psutil
####################################################################################
# Global Variables:
crashFiles = []
crashDir = outputDir = "Crashes"
WinDbgPath = "WinDbg"
TestDir = "Tests"
target = ""
target_args = ""
logoutput = "crash_details.txt"
max_time = 20
reportEvery = 1
useGflags = True
kill_windows = False
close_main = False
continuous = False
verbose = False
####################################################################################
# Functions:

# Enables GFlags for the given process, if no process is 
# given, then default is the global target process
def EnableGFlags(proc=None):
	global verbose
	global WinDbgPath
	global target

	if proc == None:
		proc = target[target.rfind("\\") + 1:]
	if verbose:
		print "Setting GFlags for " + proc
	subprocess.call(WinDbgPath + os.sep + "GFlags.exe /p /enable " + proc + " /full")

# Disables GFlags for the given process, if no process is
# given, then default is the global target process
def DisableGFlags(proc=None):
	global verbose
	global WinDbgPath
	global target

	if proc == None:
		proc = target[target.rfind("\\") + 1:]
	if verbose:
		print "Disabling GFlags for " + proc
	subprocess.call(WinDbgPath + os.sep + "GFlags.exe /p /disable " + proc)

# Generates the crash output for the target input file
# Returns the path to the output file
def GenerateCrashReport(file):
	global WinDbgPath
	global TestDir
	global target
	global max_time
	global logoutput
	global verbose

	if kill_windows or close_main:
		import window_killer

	if not os.path.exists(TestDir):
		os.mkdir(TestDir)
		
	windowKiller = None
	test = None

	testname = TestDir + os.sep + file[file.rfind(os.sep) + 1:]
	shutil.copy(file, testname)
	
	try:	
		if os.path.exists(logoutput):
			os.remove(logoutput)

		test = proc = subprocess.Popen(WinDbgPath + os.sep + "windbg.exe -Q -c \"$$<" + WinDbgPath + os.sep + "monitor.wds; g;\" -o \"" + target + "\" " + target_args + " \"" + testname + "\"")

		time.sleep(1)
		timeout = 0
		while timeout < 3:
			for p in psutil.process_iter():
				if p.name.lower() == target[target.rfind(os.sep) + 1:].lower():
					proc = p
					break
			if proc.name.lower() == target[target.rfind(os.sep) + 1:].lower():
				break
			time.sleep(1)
			timeout += 1

		if kill_windows:
			windowKiller = window_killer.MultithreadedWindowKiller(proc.pid)
			windowKiller.start()

		timeout = 0
		while test.poll() == None and timeout < max_time:
			time.sleep(1)
			timeout += 1
		if windowKiller != None:
			windowKiller.start_halt()
		if close_main: 
			window_killer.CloseMain(proc.pid)
		test.kill()
		time.sleep(1)
		if timeout == max_time and not os.path.exists(logoutput):
			return None
	except KeyboardInterrupt:
		if windowKiller != None:
			windowKiller.start_halt()
		try:
			test.kill()
		except:
			pass
		while os.path.exists(testname):
			try:
				os.remove(testname)
			except:
				pass
		raise KeyboardInterrupt()
	except:
		if windowKiller != None:
			windowKiller.start_halt()
		try:
			test.kill()
		except:
			pass
		while os.path.exists(testname):
			try:
				os.remove(testname)
			except:
				pass
		if not os.path.exists(logoutput):
			return None
	while os.path.exists(testname):
		try:
			os.remove(testname)
		except:
			pass
	return logoutput

# Initializes the crash files used for triaging	
def InitTestCases(dir=None):
	global crashFiles
	global crashDir
	global verbose

	if dir != None:
		crashDir = dir
	if verbose:
		print "Initializing Test File List..."
	crashFiles = []
	for file in os.listdir(crashDir):
		if not os.path.isdir(crashDir + os.sep + file):
			crashFiles += [crashDir + os.sep + file]
	if verbose:
		print "Crash Files Initialized: " + str(len(crashFiles)) + " total files"

# Returns the crash hash from the string representation of the crash report
def GetHash(data):
	hash = data[data.find("Hash=") + len("Hash="):]
	hash = hash[:hash.find(")")]
	return hash

# Recursively searches the baseDir for a directory labeled [hash]
# Returns the full path of that directory
def FindHashGroupPath(hash, baseDir=None):
	global outputDir

	if baseDir == None:
		baseDir = outputDir
	dirs = []

	for file in os.listdir(baseDir):
		if os.path.isdir(file):
			if file == hash:
				return baseDir + os.sep + hash
			else:
				dirs += [file]

	for dir in dirs:
		returnValue = FindHashGroupPath(hash, baseDir + os.sep + dir)
		if returnValue != None:
			return returnValue
	return None

# Creates a directory structure multiple directories deep, creates folders
# where necessary.
def BuildPath(path):
	if not os.path.exists(path):
		BuildPath(path[:path.rfind(os.sep)])
		os.mkdir(path)

# Processes all of the crash reports in a hash folder and returns the path of the 
# proper category to place the hash group in
def SortHashDir(hashDir):
	global outputDir

	registersChanged = False
	registerHash = []
	exploitability = []

	for file in os.listdir(hashDir):
		if not file.endswith(".txt") or os.path.isdir(file):
			continue

		data = open(hashDir + os.sep + file, "r").read()
		bang_rank = data[data.find("Exploitability Classification: ") + len("Exploitability Classification: "):]
		registers = bang_rank
		bang_rank = bang_rank[:bang_rank.find("\n")]
		exploitability += [bang_rank]

		registers = registers[registers.find("********************************************************************************") + len("********************************************************************************") + 1:]
		registers = registers[:registers.find("********************************************************************************")]

		esp = registers[registers.find("esp="):]
		esp = esp[:esp.find(" ")]

		ebp = registers[registers.find("ebp="):]
		ebp = ebp[:ebp.find(" ")]

		registers = registers[:registers.find("\n")]
		registers += " " + esp + " " + ebp
		registerHash += [hashlib.md5(registers).hexdigest()]

	regprev = registerHash[0]
	for register in registerHash:
		if register != regprev:
			registersChanged = True
			break

	best = exploitability[0]
	for exp in exploitability:
		if best == "EXPLOITABLE":
			break
		if exp == "EXPLOITABLE":
			best = exp
		elif exp == "PROBABLY EXPLOITABLE":
			best = exp
		elif exp == "UNKNOWN" and best != "PROBABLY EXPLOITABLE":
			best = exp
		elif exp == "PROBABLY NOT EXPLOITABLE" and best != "PROBABLY EXPLOITABLE" and best != "UNKNOWN":
			best = exp

	path = outputDir + os.sep
	if registersChanged:
		path += "RegistersChanged" + os.sep

	path += best + os.sep + hashDir[hashDir.rfind(os.sep) + 1:]
	return path

# Removes empty directories recursively
def CleanupFiles(path):
	dirs = []
	files = os.listdir(path)

	if len(files) == 0:
		os.rmdir(path)
		return

	for file in files:
		if os.path.isdir(path + os.sep + file):
			CleanupFiles(path + os.sep + file)

# Wraps shutil.move so that files are not overwritten
def MoveFile(source, destination):
	if os.path.isdir(source):
		if not os.path.exists(destination):
			os.mkdir(destination)
		for file in os.listdir(source):
			MoveFile(source + os.sep + file, destination + os.sep + file)
		return
	elif os.path.isdir(destination):
		destination += os.sep + source[source.rfind(os.sep) + 1:]
	if os.path.exists(destination):
		dup = 1
		while os.path.exists(destination[:destination.rfind(".")] + "_(" + str(dup) + ")" + destination[destination.rfind("."):]):
			dup += 1
		destination = destination[:destination.rfind(".")] + "_(" + str(dup) + ")" + destination[destination.rfind("."):]
	while os.path.exists(source):
		try:
			shutil.move(source, destination)
		except:
			time.sleep(3)

# Parses a crash details file and sorts it and the crash file into their
# corresponding hash folders 
def ProcessDetailsFile(report, crash_file):
	data = open(report, "r").read()

	hash = GetHash(data)
	group = FindHashGroupPath(hash)

	if group == None:
		if not os.path.exists(outputDir + os.sep + hash):
			os.mkdir(outputDir + os.sep + hash)
		group = outputDir + os.sep + hash

	MoveFile(report, group + os.sep + report[report.rfind(os.sep) + 1:])
	MoveFile(crash_file, group + os.sep + crash_file[crash_file.rfind(os.sep) + 1:])

	newPath = SortHashDir(group)

	BuildPath(newPath)

	for newFile in os.listdir(group):
		MoveFile(group + os.sep + newFile, newPath)
	
# Main loop for triaging.
# Takes all files, runs them through a debugger and sorts the output
# into an organized directory structure 
def RunTriage():
	global crashFiles
	global outputDir
	global reportEvery
	global logoutput
	global useGFlags
	global verbose

	count = 1

	try:
		if useGflags:
			EnableGFlags()

		if verbose:
			print "Starting Triage..."

		if not os.path.exists(outputDir):
			os.mkdir(outputDir)

		for file in crashFiles:
			if verbose and ((reportEvery > 1 and count % reportEvery == 1) or (reportEvery == 1 and count % reportEvery == 0)):
				print "Working on file " + str(count) + " of " + str(len(crashFiles)) + " (" + ("%0.2f" % (count * 100.0 / len(crashFiles))) + "%)"
			
			report = GenerateCrashReport(file)
			if report == None or not "Hash=" in open(report, "r").read():
				if verbose:
					print "Failed to reproduce file: " + file[file.rfind(os.sep) + 1:]
				if not os.path.exists(outputDir + os.sep + "UnableToReproduce"):
					os.mkdir(outputDir + os.sep + "UnableToReproduce")

				MoveFile(file, outputDir + os.sep + "UnableToReproduce" + os.sep + file[file.rfind(os.sep) + 1:])
			else:
				shutil.move(report, file + "-" + logoutput)
				report = file + "-" + logoutput
				
				ProcessDetailsFile(report, file)

			count += 1
	except KeyboardInterrupt:
		CleanupFiles(outputDir)
		if useGflags:
			DisableGFlags()
		raise KeyboardInterrupt()	

	CleanupFiles(outputDir)

# Prints the command line usage if run as stand alone application.
def PrintUsage():
	global Usage
	print Usage
####################################################################################
# Main:
def main(args):
	global crashDir 
	global outputDir
	global WinDbgPath
	global TestDir
	global target 
	global target_args
	global max_time
	global reportEvery
	global useGflags
	global kill_windows
	global close_main
	global continuous
	global verbose

	if len(args) < 2:
		PrintUsage()
		exit()

	optlist, argv = getopt.getopt(args[1:], 'b:o:w:t:a:i:m:kegcvh')
	for opt in optlist:
		if opt[0] == '-b':
			crashDir = opt[1]
		elif opt[0] == '-o':
			outputDir = opt[1]
		elif opt[0] == '-w':
			WinDbgDir = opt[1]
		elif opt[0] == '-t':
			TestDir = opt[1]
		elif opt[0] == '-a':
			target_args = opt[1]
		elif opt[0] == '-i':
			reportEvery = int(opt[1])
		elif opt[0] == '-m':
			max_time = int(opt[1])
		elif opt[0] == '-k':
			kill_windows = True
		elif opt[0] == '-e':
			close_main = True
		elif opt[0] == '-g':
			useGflags = False
		elif opt[0] == '-c':
			continuous = True
		elif opt[0] == '-v':
			verbose = True
		elif opt[0] == '-h':
			PrintUsage()
			exit()

	if len(argv) < 1:
		PrintUsage()
		exit()
	target = argv[0]


	try:
		while True: # haha, ghetto do-while loops make me laugh
			InitTestCases()

			if verbose:
				print "Starting Triage Session..."

			RunTriage()
			if not continuous:
				break
	except KeyboardInterrupt:
		print "Ctrl-C Detected - Ending Triage Session..."
####################################################################################
if __name__=="__main__":
	main(sys.argv)
####################################################################################