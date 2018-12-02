import string, sys , os, subprocess


def createOutput():
    incorrectly_verifies_hostnames = []
    incorrectly_verifies_cerficates = []
    uses_ssl_pinning = []
    implements_implict_intents = []
    uses_dangerous_permissions = []
    
    f= open("app_anaylsis.txt", "w")
    

def runAnalysis(apks):
    for a in apks:
        subprocess.call([ "FirstScript1.py", "-f", a, "-x"])

def parseDir():
    #get directory with all apk's to be analyzed
    directory = sys.argv[1]
    fp = os.open(directory, os.O_RDONLY)
    os.fchdir(fp)
    #makes list of the apks in the folder 
    apks = os.listdir(os.getcwd())

    runAnalysis(apks)


#main code
parsing = parseDir()
