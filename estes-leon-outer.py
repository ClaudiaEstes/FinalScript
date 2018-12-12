import string, sys , os, subprocess

def runAnalysis(apks, numApps):
    for a in apks:
        if a.endswith(".apk"):
            numApps+=1
            subprocess.call(["python3", "FinalScript1.py", "-f", a, "-x"])
    return numApps

def parseDir():
    #get directory with all apk's to be analyzed
    directory = sys.argv[1]
    fp = os.open(directory, os.O_RDONLY)
    os.fchdir(fp)
    #makes list of the apks in the folder 
    apks = os.listdir(os.getcwd())
    f= open("FinalOutput.txt", "w")
    
    f.close()
    
    numApps = 0
    numApps = runAnalysis(apks, numApps)
    
    #collected stats on how many apps have the problem
    act = 0
    ser= 0
    rec = 0
    con = 0
    cal = 0
    aud = 0
    host = 0
    ssl = 0
    cert = 0
    both = 0
    
    f= open("FinalOutput.txt", "r")
    w = open("FinalStats.txt", "w")
    
    for line in f:
        if ("Exported activities: " in line):
            act+=1
        if("Exported services: " in line):
            ser +=1
        if("Exported receivers: " in line):
            rec +=1
        if("READ_CONTACTS" in line):
            con +=1
        if("READ_CALENDAR" in line):
            cal +=1
        if("RECORD_AUDIO" in line):
            aud +=1
        if("App implements custom HostnameVerifier" in line):
            host +=1
        if("App implements custom TrustManager" in line):
            cert +=1
        if("App instantiates AllowAllHostnameVerifier" in line or "App ignores ssl error" in line):
            ssl +=1
        if ("App implements custom HostnameVerifier and TrustManager that incorrectly verifies hostnames and certificate." in line):
            both +=1
    w.write("For apps examined: \n")
    w.write("Apps with exported activities: ")
    w.write(str(act))
    w.write("\n")
    w.write("Apps with exported services: ")
    w.write(str(ser))
    w.write("\n")    
    w.write("Apps with exported receivers: ")
    w.write(str(rec))
    w.write("\n")         
    w.write("Apps using RECORD_AUDIO permission: ")
    w.write(str(aud))
    w.write("\n")    
    w.write("Apps using READ_CONTACTS permission: ")
    w.write(str(con))
    w.write("\n")     
    w.write("Apps using READ_CALENDAR permission: ")
    w.write(str(cal))
    w.write("\n")    
    w.write("Apps with hostname verification issues ")
    w.write(str(host))
    w.write("\n")    
    w.write("Apps with SSL pining ( ignoring ssl erros)problems/allowallhostnameverifier: ")
    w.write(str(ssl))
    w.write("\n")    
    w.write("Apps with certificate verification issues: ")
    w.write(str(cert))
    w.write("\n")   
    w.write("Total number of apps reviewed: ")
    w.write(str(numApps))
    w.write("\n")
    
    w.close()
    f.close()
    
    

#main code
parsing = parseDir()
