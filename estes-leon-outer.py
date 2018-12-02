import string, sys , os, subprocess


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
