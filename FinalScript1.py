#!/usr/bin/env python
# encoding: utf-8

from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.bytecodes.apk import APK
#from androguard.core.analysis.analysis import uVMAnalysis
from androguard.core.analysis.analysis import Analysis
#from androguard.core.analysis.ganalysis import GVMAnalysis

import sys
import os
import pprint
import datetime
import argparse

def _get_method_instructions(_method):
	_code = _method.get_code()
	_instructions = []
	if _code:
		_bc = _code.get_bc()
		for _instr in _bc.get_instructions():
			_instructions.append(_instr)
	return _instructions

def _ensure_dir(_d):
	d = os.path.dirname(_d)
	if not os.path.exists(d):
		os.makedirs(d)

def _parseargs():
	parser = argparse.ArgumentParser(description="Analyse Android Apps for broken SSL certificate validation.")
	parser.add_argument("-f", "--file", help="APK File to check", type=str, required=True)
	parser.add_argument("-j", "--java", help="Show Java code for results for non-XML output", action="store_true", required=False)
	parser.add_argument("-x", "--xml", help="print(XML output", action="store_true", required=False)
	parser.add_argument("-d", "--dir", help="Store decompiled App's Java code for further analysis in dir", type=str, required=False)
	args = parser.parse_args()

	return args

def printResults(AllowAllHostnameVerifier,IgnoresSSLError,TrustManager, SocketFactory,HostnameVerifier,f,w):
	
	if len(AllowAllHostnameVerifier) > 0:
		f.write("App instantiates AllowAllHostnameVerifier: \n" )
		w.write("App instantiates AllowAllHostnameVerifier: \n" )
		for each in AllowAllHostnameVerifier:
			f.write("\tAllowAllHostnameVerifier is instantiated in" )
			f.write(str(each['methodName']) )
			f.write(str(each['class']))
			f.write(str(each['method'] ))
			f.write("\n" )		
	if len(IgnoresSSLError)>0:
		f.write("App ignores ssl error: \n")
		w.write("App ignores ssl error: \n")
		for each in IgnoresSSLError:
			f.write("\tCustom ssl error handler in" )
			f.write(str(each['methodName']) )
			f.write(str(each['method']))
			f.write(str(each['class'] ))
			f.write("\n" )
		
			
	if len(TrustManager) > 0:
		f.write("App implements custom TrustManager: \n")
		w.write("App implements custom TrustManager: \n")
		for each in TrustManager:
			_class_name = each['class'].get_name()
			f.write("\tCustom TrustManager is implemented in class that incorrectly verifies certificates")
			f.write(_class_name)
			f.write(str(each['methodName']) )
			f.write(str(each['method']))
			f.write(str(each['class'] ))
			f.write("\n" )
			
	if len(SocketFactory) > 0:
		f.write("App instantiates insecure SSLSocketFactory: \n")
		w.write("App instantiates insecure SSLSocketFactory: \n")
		for each in _insecure_socket_factory:
			_class_name = _translate_class_name(eac['class'].get_name())
			f.write("\tInsecure SSLSocketFactory is instantiated in" )
			f.write(_class_name)
			f.write(each['methodName']) 
			f.write(str(each['method']))
			f.write(str(each['class'] ))	
			f.write("\n" )
			
	if len(HostnameVerifier) > 0:
		f.write("App implements custom HostnameVerifier: \n")
		w.write("App implements custom HostnameVerifier: \n")
		for each in HostnameVerifier:
			_class_name = each['class'].get_name()
			f.write("\tCustom HostnameVerifiers is implemented in class that incorrectly verifies hostnames" )
			f.write(_class_name)
			f.write(str(each['methodName']) )
			f.write(str(each['method']))
			f.write(str(each['class'] ))	
			f.write("\n" )
	if len(HostnameVerifier) > 0 and len(TrustManager) > 0:
		f.write("App implements custom HostnameVerifier and TrustManager that incorrectly verifies hostnames and cerficaites.\n" )
		w.write("App implements custom HostnameVerifier and TrustManager that incorrectly verifies hostnames and cerficaites. \n" )
		

				
def findHostnameVerifiers(_vmx, name, _class, _method, interfaces,superclass, HostnameVerifier):
	verifier_interfaces = ['Ljavax/net/ssl/HostnameVerifier;', 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;']
	verifier_classes = ['L/org/apache/http/conn/ssl/AbstractVerifier;', 'L/org/apache/http/conn/ssl/AllowAllHostnameVerifier;', \
                             'L/org/apache/http/conn/ssl/NaiveHostnameVerifier;', 'L/org/apache/http/conn/ssl/AcceptAllHostnameVerifier;'\
                             'L/org/apache/http/conn/ssl/FakeHostnameVerifier;'
                                'L/org/apache/http/conn/ssl/BrowserCompatHostnameVerifier;', 'L/org/apache/http/conn/ssl/StrictHostnameVerifier;']	
	if name == 'verify':
		if 'void' or 'boolean' in info:
			code = get_code(_class,_vmx)
			for i in interfaces:
				if i == verifier_interfaces[0] or i == verifier_interfaces[1]:
					#print(name)
					#print(_method)
					#print(_class)
					#print(code)
					HostnameVerifier.append({'methodName': name, 'method':_method, 'class': _class} )
			for i in verifier_classes:
				if i == superclass:
					#print("verifier classes")
					#print(name)
					#print(_method)
					#print(_class)
					#print(code)
					HostnameVerifier.append({'methodName': name, 'method':_method, 'class': _class} )
				
def findAllAllow(_method,instructions, name, info,_class,_allow_all_hostname_verifier):
	for i in instructions:
		if  i.get_name() == "new-instance" and i.get_output().endswith('Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;'):
	
			_allow_all_hostname_verifier.append ({'class': _class, 'methodName':name ,'method': _method, 'info': info } )
		elif (i.get_name() == "sget-object"): 
			if ('Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER' in i.get_output() ):
				_allow_all_hostname_verifier.append({'class': _class, 'methodName':name ,'method': _method, 'info': info } )
				
def findsslError(method,name, _vmx,_class,IgnoresSSLError):
	sslError = ['onReceivedSslError', 'Landroid/webkit/WebViewClient;','Landroid/webkit/WebView;', 'Landroid/webkit/SslErrorHandler' , 'Landroid/net/http/SslError ', 'android.net.http.SslError']
	if name == sslError[0]:
		if 'void' or 'true' in info:
			code = get_code(_class,_vmx)
			if 'super.onReceivedSslError' not in code:
				#print( get_code(_class,_vmx) )
				IgnoresSSLError.append({'methodName': name, 'method':method, 'class': _class} )	
				
def findCertsTrustManager_SocketFactory(_vmx, name,_class,_method,instructions, interfaces,TrustManager,SocketFactory ):		
		cert_check_trusted = ['checkServerTrusted','java.security.cert.X509Certificate[]', 'java.lang.String', 'Ljavax/net/ssl/TrustManager;', 'Ljavax/net/ssl/X509TrustManager;']
		if name == cert_check_trusted[0]:
			if 'void' or 'true' in info: #checks that method only returns true or is void ( so does nothing to handle err)
				code = get_code(_class,_vmx)
				for i in interfaces:
					if i == cert_check_trusted[3] or i  == cert_check_trusted[4]:
						##could potentially check to see if only public and not public final in the code
						##print(code)
						TrustManager.append({'methodName': name, 'method': _method, 'class': _class} )	
		for i in instructions:
			if i.get_name() == "invoke-static" and i.get_output().endswith('Landroid/net/SSLCertificateSocketFactory;->getInsecure(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;'):
				code = get_code(_class,_vmx)
				##print(code)
				SocketFactory.append({'methodName': name, 'method': _method, 'class': _class})

def _findPerm(perms,f, w):
	#print((perms)
	f.write("Suspicious Permission Use: \n")
	w.write("Suspicious Permission Use: \n")
	
	contacts = 0
	calendar = 0
	audio = 0
	
	none = True
	if (len(perms)>0):
		for x in perms:
			if (x.find('READ_CONTACTS') != -1):
				f.write("READ_CONTACTS permission used \n")
				contacts+=1
				none = False
			if (x.find('READ_CALENDAR') != -1):
				f.write("READ_CALENDAR permission used \n")
				calendar+=1
				none = False
			if (x.find('RECORD_AUDIO') != -1):
				f.write("RECORD_AUDIO permission used \n")
				audio +=1
				none = False
	if (none):
		f.write("No suspicious permissions in use \n")
		w.write("No suspicious permissions in use \n")
	else:
		if (contacts != 0):
			w.write("READ_CONTACTS permission use: ")
			w.write( str(contacts))
			w.write("\n")
		elif (calendar != 0):
			w.write("READ_CALENDAR permission use: ")
			w.write( str(calendar))
			w.write("\n")
		elif (audio != 0):
			w.write("RECORD_AUDIO permission use: ")
			w.write( str(audio))
			w.write("\n")	
		else:
			w.write("No suspicious permissions in use \n")
def _intentFilters(_a,f,w):
#should add which component is exported eventually
	act = 0
	ser = 0
	rec = 0
	activities = _a.get_activities()
	if (len(activities) >0):
		for x in activities:
			intent = _a.get_intent_filters("activity", x)

			if (len(intent) > 0 and 'category' in intent.keys()):
				for i in intent['category']:
					if(i.find('DEFAULT') or i.find('EXPORTED')):
						if not(i.find('LAUNCHER')):
							f.write(i + " Exported activity intent filter \n")
							act +=1
	services = _a.get_services()
	if (len(services) >0):
		for x in services:
			intent = _a.get_intent_filters("service", x)

			if (len(intent) > 0 and 'category' in intent.keys()):
				for i in intent['category']:
					if(i.find('DEFAULT') or i.find('EXPORTED')):
						f.write(i + " Exported service intent filter \n")
						ser +=1
	recs = _a.get_receivers()
	if (len(recs) >0):
		for x in recs:
			intent = _a.get_intent_filters("receiver", x)
			#print(intent)
			if (len(intent) > 0 and 'category' in intent.keys()):
				for i in intent['category']:
					if(i.find('DEFAULT') or i.find('EXPORTED')):
						f.write(i + " Exported receiver intent filter \n")
						rec +=1
	if (act <1):
		w.write("No exported activities\n")
	else:
		w.write("Exported activities: ")
		w.write(str(act))
		w.write("\n")
	if (ser <1):
		w.write("No exported services\n")
	else:
		w.write("Exported services: ")
		w.write(str(ser))
		w.write("\n")	

	if (rec <1):
		w.write("No exported receivers\n")
	else:
		w.write("Exported receivers: ")
		w.write(str(rec))
		w.write("\n")
def get_code(_class,_vmx):
	ms = decompile.DvClass(_class, _vmx)
	ms.process()	
	return ms.get_source()
	
def main():

	_args = _parseargs()

	_a = apk.APK(_args.file)
	name = _a.get_app_name()
	w = open("FinalOutput.txt", "a")
	f = open(name+".txt", "w")
	f.write("-------------------RESULTS-------------- \n")
	w.write("-------------------RESULTS-------------- \n")	
	f.write("Analyze file: {:s}".format(_args.file) + "\n")
	f.write("Package name: {:s}".format(_a.get_package())+ "\n \n")
	w.write("Analyze file: {:s}".format(_args.file) + "\n")
	w.write("Package name: {:s}".format(_a.get_package())+ "\n \n")


	#for research question 3
	_findPerm(_a.get_permissions(), f, w)

	#for research question 8
	_intentFilters(_a, f, w)


	_vm = dvm.DalvikVMFormat(_a.get_dex())
	#_vmx = uVMAnalysis(_vm)
	_vmx = Analysis(_vm)
	
	
	AllowAllHostnameVerifier = []		
	IgnoresSSLError = []
	TrustManager = []
	SocketFactory = []
	HostnameVerifier = []
	
	for _method in _vm.get_methods():
		name = _method.get_name()
		info = _method.get_information()
		##returns something like this {'registers': (0, 1), 'params': [(2, 'boolean')], 'return': 'void'} 
		_class = _vm.get_class(_method.get_class_name()) 
		##returns something like Ljava/lang/Object;->Lorg/jacoco/agent/rt/internal_773e439/output/TcpServerOutput;
		superclass = _class.get_superclassname()
		interfaces = _class.get_interfaces()	
		instructions = _get_method_instructions(_method)
		
		
		findAllAllow(_method,instructions, name, info, _class, AllowAllHostnameVerifier)
		findsslError(_method,name, _vmx,_class,IgnoresSSLError)
		findCertsTrustManager_SocketFactory(_vmx, name,_class,_method,instructions,interfaces,TrustManager, SocketFactory)
		findHostnameVerifiers(_vmx, name, _class, _method, interfaces,superclass, HostnameVerifier)
	
				
	printResults(AllowAllHostnameVerifier,IgnoresSSLError,TrustManager, SocketFactory,HostnameVerifier,f,w)
	
	f.close()
	w.close()


if __name__ == "__main__":
	main()
