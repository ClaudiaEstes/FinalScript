#!/usr/bin/env python
# encoding: utf-8

from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import Analysis
#from androguard.core.analysis.ganalysis import GVMAnalysis

import sys
import os
import base64
import pprint
import datetime
import argparse

def _get_java_code(_class, _vmx):
	try:
		_ms = decompile.DvClass(_class, _vmx)
		print ( _ms.get_source(), "\n")
		_ms.process()
		return _ms.get_source()
	except :
		print("Error getting Java source code for: {:s}".format(_class.get_name()) )
	return None

def _has_signature(_method, _signatures):
	_name = _method.get_name()
	_return = _method.get_information().get('return', None)
	_params = [_p[1] for _p in _method.get_information().get('params', [])]
	_access_flags = _method.get_access_flags_string()

	for _signature in _signatures:
		if (_access_flags == _signature['access_flags']) \
				and (_name == _signature['name']) \
				and (_return == _signature['return']) \
				and (_params == _signature['params']):
			return True
	return False

def _class_implements_interface(_class, _interfaces):
	return (_class.get_interfaces() and any([True for i in _interfaces if i in _class.get_interfaces()]))

def _class_extends_class(_class, _classes):
	return any([True for i in _classes if i == _class.get_superclassname()])

def _get_method_instructions(_method):
	_code = _method.get_code()
	_instructions = []
	if _code:
		_bc = _code.get_bc()
		for _instr in _bc.get_instructions():
			_instructions.append(_instr)
	return _instructions

def _returns_true(_method):
	_instructions = _get_method_instructions(_method)
	if len(_instructions) == 2:
		_i = "->".join([_instructions[0].get_output(), _instructions[1].get_name() + "," + _instructions[1].get_output()])
		_i = _i.replace(" ", "")
		_v = _instructions[0].get_output().split(",")[0]
		_x = "{:s},1->return,{:s}".format(_v, _v)
		return _i == _x
	return False

def _returns_void(_method):
	_instructions = _get_method_instructions(_method)
	if len(_instructions) == 1:
		return _instructions[0].get_name() == "return-void"
	return False

def _instantiates_allow_all_hostname_verifier(_method):
	if not _method.get_class_name() == "Lorg/apache/http/conn/ssl/SSLSocketFactory;":
		_instructions = _get_method_instructions(_method)
		for _i in _instructions:
			if _i.get_name() == "new-instance" and _i.get_output().endswith('Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier;'):
				return True
			elif _i.get_name() == "sget-object" and 'Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER' in _i.get_output():
				return True
	return False

def _instantiates_get_insecure_socket_factory(_method):
	_instructions = _get_method_instructions(_method)
	for _i in _instructions:
		if _i.get_name() == "invoke-static" and _i.get_output().endswith('Landroid/net/SSLCertificateSocketFactory;->getInsecure(I Landroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;'):
			return True
	return False

def _get_javab64_xref(_class, _vmx):
	#_java_b64 = base64.b64encode(_get_java_code(_class, _vmx).encode("utf-8"))
	_java_b64 = _get_java_code(_class, _vmx)
	_xref = None
	try:
		_xref = _class.XREFfrom
		if _xref:
			_xref = [_m[0] for _m in _xref.items]
	except AttributeError:
		pass
	return _java_b64, _xref

def _check_trust_manager(_method, _vm, _vmx):
	_check_server_trusted = {'access_flags' : 'public', 'return' : 'void', 'name' : 'checkServerTrusted', 'params' : ['java.security.cert.X509Certificate[]', 'java.lang.String']}
	_trustmanager_interfaces = ['Ljavax/net/ssl/TrustManager;', 'Ljavax/net/ssl/X509TrustManager;']
	_custom_trust_manager = []
	_insecure_socket_factory = []

	if _has_signature(_method, [_check_server_trusted]):
		_class = _vm.get_class(_method.get_class_name())
		if _class_implements_interface(_class, _trustmanager_interfaces):
			_java_b64, _xref = _get_javab64_xref(_class, _vmx)
			_empty = _returns_true(_method) or _returns_void(_method)
			_custom_trust_manager.append({'class' : _class, 'xref' : _xref, 'java_b64' : _java_b64, 'empty' : _empty})
	if _instantiates_get_insecure_socket_factory(_method):
		_class = _vm.get_class(_method.get_class_name())
		_java_b64, _xref = _get_javab64_xref(_class, _vmx)
		_insecure_socket_factory.append({'class' : _class, 'method' : _method, 'java_b64' : _java_b64})

	return _custom_trust_manager, _insecure_socket_factory

def _check_hostname_verifier(_method, _vm, _vmx):
	_verify_string_sslsession = {'access_flags' : 'public', 'return' : 'boolean', 'name' : 'verify', 'params' : ['java.lang.String', 'javax.net.ssl.SSLSession']}
	_verify_string_x509cert = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'java.security.cert.X509Certificate']}
	_verify_string_sslsocket = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'javax.net.ssl.SSLSocket']}
	_verify_string_subj_alt = {'access_flags' : 'public', 'return' : 'void', 'name' : 'verify', 'params' : ['java.lang.String', 'java.lang.String[]', 'java.lang.String[]']}
	_verifier_interfaces = ['Ljavax/net/ssl/HostnameVerifier;', 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;']
	_verifier_classes = ['L/org/apache/http/conn/ssl/AbstractVerifier;', 'L/org/apache/http/conn/ssl/AllowAllHostnameVerifier;', \
	                     'L/org/apache/http/conn/ssl/NaiveHostnameVerifier;', 'L/org/apache/http/conn/ssl/AcceptAllHostnameVerifier'\
	                     'L/org/apache/http/conn/ssl/FakeHostnameVerifier'
				'L/org/apache/http/conn/ssl/BrowserCompatHostnameVerifier;', 'L/org/apache/http/conn/ssl/StrictHostnameVerifier;']
	_custom_hostname_verifier = []
	_allow_all_hostname_verifier = []

	if _has_signature(_method, [_verify_string_sslsession, _verify_string_x509cert, _verify_string_sslsocket, _verify_string_subj_alt]):
		_class = _vm.get_class(_method.get_class_name())
		if _class_implements_interface(_class, _verifier_interfaces) or _class_extends_class(_class, _verifier_classes):
			_java_b64, _xref = _get_javab64_xref(_class, _vmx)
			_empty = _returns_true(_method) or _returns_void(_method)
			_custom_hostname_verifier.append({'class' : _class, 'xref' : _xref, 'java_b64' : _java_b64, 'empty' : _empty})
	if _instantiates_allow_all_hostname_verifier(_method):
		_class = _vm.get_class(_method.get_class_name())
		_java_b64, _xref = _get_javab64_xref(_class, _vmx)
		_allow_all_hostname_verifier.append({'class' : _class, 'method' : _method, 'java_b64' : _java_b64})

	return _custom_hostname_verifier, _allow_all_hostname_verifier

def _check_ssl_error(_method, _vm, _vmx):
	_on_received_ssl_error = {'access_flags' : 'public', 'return' : 'void', 'name' : 'onReceivedSslError', 'params' : ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError']}
	_webviewclient_classes = ['Landroid/webkit/WebViewClient;']
	_custom_on_received_ssl_error = []

	if _has_signature(_method, [_on_received_ssl_error]):
		_class = _vm.get_class(_method.get_class_name())
		if _class_extends_class(_class, _webviewclient_classes) or True:
			_java_b64, _xref = _get_javab64_xref(_class, _vmx)
			print( _java_b64, "\n")
			_empty = _returns_true(_method) or _returns_void(_method)
			_custom_on_received_ssl_error.append({'class' : _class, 'xref' : _xref, 'java_b64' : _java_b64, 'empty' : _empty})
			#_custom_on_received_ssl_error.append({'class' : _class, 'empty' : _empty})

	return _custom_on_received_ssl_error

def _check_all(_vm, _vmx, _gx):

	_custom_trust_manager = []
	_insecure_socket_factory = []

	_custom_hostname_verifier = []
	_allow_all_hostname_verifier = []

	_custom_on_received_ssl_error = []

	for _method in _vm.get_methods():
		hv, _a = _check_hostname_verifier(_method, _vm, _vmx)
		if len(_hv) > 0:
			custom_hostname_verifier += _hv
		if len(_a) > 0:
			allow_all_hostname_verifier += _a
		_tm, _i = _check_trust_manager(_method, _vm, _vmx)
		if len(_tm) > 0:
			_custom_trust_manager += _tm
		if len(_i) > 0:
			insecure_socket_factory += _i
		_ssl = _check_ssl_error(_method, _vm, _vmx)
		if len(_ssl) > 0:
			_custom_on_received_ssl_error += _ssl

	return { 'trustmanager' : _custom_trust_manager, 'insecuresocketfactory' : _insecure_socket_factory, 'customhostnameverifier' : _custom_hostname_verifier, 'allowallhostnameverifier' : _allow_all_hostname_verifier, 'onreceivedsslerror' : _custom_on_received_ssl_error}

def _print_result(_result, _java=True):
	print("Analysis result:")

	if len(_result['trustmanager']) > 0:
		if len(_result['trustmanager']) == 1:
			print("App implements custom TrustManager:")
		elif len(_result['trustmanager']) > 1:
			print("App implements {:d} custom TrustManagers".format(len(_result['trustmanager'])) )

		for _tm in _result['trustmanager']:
			_class_name = _tm['class'].get_name()
			print("\tCustom TrustManager is implemented in class {:s}".format(_translate_class_name(_class_name)))
			if _tm['empty']:
				print("\tImplements naive certificate check. This TrustManager breaks certificate validation!")
			for _ref in _tm['xref']:
				print("\t\tReferenced in method {:s}->{:s}".format(_translate_class_name(_ref.get_class_name()), _ref.get_name()))
			if _java:
				print("\t\tJavaSource code:")
				print("{:s}".format(base64.b64decode(_tm['java_b64'])) )
				      
	if len(_result['insecuresocketfactory']) > 0:
		if len(_result['insecuresocketfactory']) == 1:
			print("App instantiates insecure SSLSocketFactory:")
		elif len(_result['insecuresocketfactory']) > 1:
			print("App instantiates {:d} insecure SSLSocketFactorys".format(len(_result['insecuresocketfactory'])) )

		for _is in _result['insecuresocketfactory']:
			_class_name = _translate_class_name(_is['class'].get_name())
			print("\tInsecure SSLSocketFactory is instantiated in {:s}->{:s}".format(_class_name, _is['method'].get_name()) )
			if _java:
				print("\t\tJavaSource code:")
				print("{:s}".format(base64.b64decode(_is['java_b64'])) )

	if len(_result['customhostnameverifier']) > 0:
		if len(_result['customhostnameverifier']) == 1:
			print("App implements custom HostnameVerifier:")
		elif len(_result['customhostnameverifier']) > 1:
			print("App implements {:d} custom HostnameVerifiers".format(len(_result['customhostnameverifier'])) )

		for _hv in _result['customhostnameverifier']:
			_class_name = _hv['class'].get_name()
			print("\tCustom HostnameVerifiers is implemented in class {:s}".format(_translate_class_name(_class_name)) )
			if _hv['empty']:
				print("\tImplements naive hostname verification. This HostnameVerifier breaks certificate validation!")
			for _ref in _tm['xref']:
				print("\t\tReferenced in method {:s}->{:s}".format(_translate_class_name(_ref.get_class_name()), _ref.get_name()) )
			if _java:
				print("\t\tJavaSource code:" )
				print("{:s}".format(base64.b64decode(_hv['java_b64'])) )

	if len(_result['allowallhostnameverifier']) > 0:
		if len(_result['allowallhostnameverifier']) == 1:
			print("App instantiates AllowAllHostnameVerifier:" )
		elif len(_result['allowallhostnameverifier']) > 1:
			print("App instantiates {:d} AllowAllHostnameVerifiers".format(len(_result['allowallhostnameverifier']))  )

		for _aa in _result['allowallhostnameverifier']:
			_class_name = _translate_class_name(_aa['class'].get_name())
			print("\tAllowAllHostnameVerifier is instantiated in {:s}->{:s}".format(_class_name, _aa['method'].get_name()) )
		if _java: 
			print("\t\tJavaSource code:" )
			print("{:s}".format(base64.b64decode(_aa['java_b64'])))

def _xml_result(_a, _result):
	from xml.etree.ElementTree import Element, SubElement, tostring, dump
	import xml.dom.minidom

	_result_xml = Element('result')
	_result_xml.set('package', _a.get_package())
	_tms = SubElement(_result_xml, 'trustmanagers')
	_hvs = SubElement(_result_xml, 'hostnameverifiers')
	_orse = SubElement(_result_xml, 'onreceivedsslerrors')

	print("\nXML output:\n")

	for _tm in _result['trustmanager']:
		_class_name = _translate_class_name(_tm['class'].get_name())
		_t = SubElement(_tms, 'trustmanager')
		_t.set('class', _class_name)
		if _tm['empty']:
			_t.set('broken', 'True')
		else:
			_t.set('broken', 'Maybe')

		for _r in _tm['xref']:
			_rs = SubElement(_t, 'xref')
			_rs.set('class', _translate_class_name(_r.get_class_name()))
			_rs.set('method', _r.get_name())

	if len(_result['insecuresocketfactory']):
		for _is in _result['insecuresocketfactory']:
			_class_name = _translate_class_name(_is['class'].get_name())
			_i = SubElement(_tms, 'insecuresslsocket')
			_i.set('class', _class_name)
			_i.set('method', _is['method'].get_name())
	else:
		_i = SubElement(_tms, 'insecuresslsocket')


	for _hv in _result['customhostnameverifier']:
		_class_name = _translate_class_name(_hv['class'].get_name())
		_h = SubElement(_hvs, 'hostnameverifier')
		_h.set('class', _class_name)
		if _hv['empty']:
			_h.set('broken', 'True')
		else:
			_h.set('broken', 'Maybe')

		for _ref in _hv['xref']:
			_hs = SubElement(_h, 'xref')
			_hs.set('class', _translate_class_name(_ref.get_class_name()))
			_hs.set('method', _ref.get_name())

	if len(_result['allowallhostnameverifier']):
		for _aa in _result['allowallhostnameverifier']:
			_class_name = _translate_class_name(_aa['class'].get_name())
			_a = SubElement(_hvs, 'allowhostnames')
			_a.set('class', _class_name)
			_a.set('method', _aa['method'].get_name())
	else:
		_a = SubElement(_hvs, 'allowhostnames')

	for _se in _result['onreceivedsslerror']:
		_class_name = _translate_class_name(_se['class'].get_name())
		_s = SubElement(_orse, 'sslerror')
		_s.set('class', _class_name)
		if _se['empty']:
			_s.set('broken', 'True')
		else:
			_s.set('broken', 'Maybe')

		for _ref in _se['xref']:
			_ss = SubElement(_s, 'xref')
			_ss.set('class', _translate_class_name(_ref.get_class_name()))
			_ss.set('method', _ref.get_name())


	_xml = xml.dom.minidom.parseString(tostring(_result_xml, method="xml"))
	print(_xml.toprettyxml() )

def _translate_class_name(_class_name):
	_class_name = _class_name[1:-1]
	_class_name = _class_name.replace("/", ".")
	return _class_name

def _file_name(_class_name, _base_dir):
	_class_name = _class_name[1:-1]
	_f = os.path.join(_base_dir, _class_name + ".java")
	return _f

def _ensure_dir(_d):
	d = os.path.dirname(_d)
	if not os.path.exists(d):
		os.makedirs(d)

def _store_java(_vm, _args):
	_vm.create_python_export()
	_vmx = uVMAnalysis(_vm)
	_gx = GVMAnalysis(_vmx, None)
	_vm.set_vmanalysis(_vmx)
	_vm.set_gvmanalysis(_gx)
	_vm.create_dref(_vmx)
	_vm.create_xref(_vmx)

	for _class in _vm.get_classes():
		try:
			_ms = decompile.DvClass(_class, _vmx)
			_ms.process()
			_f = _file_name(_class.get_name(), _args.storejava)
			_ensure_dir(_f)
			with open(_f, "w") as f:
				_java = str(_ms.get_source())
				f.write(_java)
		except:
			print("Could not process {:s}: {:s}".format(_class.get_name(), str(e)))


def _parseargs():
	parser = argparse.ArgumentParser(description="Analyse Android Apps for broken SSL certificate validation.")
	parser.add_argument("-f", "--file", help="APK File to check", type=str, required=True)
	parser.add_argument("-j", "--java", help="Show Java code for results for non-XML output", action="store_true", required=False)
	parser.add_argument("-x", "--xml", help="print(XML output", action="store_true", required=False)
	parser.add_argument("-d", "--dir", help="Store decompiled App's Java code for further analysis in dir", type=str, required=False)
	args = parser.parse_args()

	return args

def _findPerm(perms):
	#print((perms)
	print("Suspicious Permission Use:")
	none = True
	for x in perms:
		if (x.find('READ_CONTACTS') != -1):
			print("READ_CONTACTS permission used")
			none = False
		if (x.find('READ_CALENDAR') != -1):
			print("READ_CALENDAR permission used")
			none = False
		if (x.find('RECORD_AUDIO') != -1):
			print("RECORD_AUDIO permission used")
			none = False
	if (none):
		print("No suspicious permissions in use")
def _intentFilters(_a):
#should add which component is exported eventually
	activities = _a.get_activities()
	for x in activities:
		intent = _a.get_intent_filters("activity", x)
		
		if (len(intent) > 0):
			for i in intent['category']:				
				if(i.find('DEFAULT') or i.find('EXPORTED')):
					print(" Exported activity intent filter")
	activities = _a.get_services()
	for x in activities:
		intent = _a.get_intent_filters("service", x)
		
		if (len(intent) > 0):
			for i in intent['category']:				
				if(i.find('DEFAULT') or i.find('EXPORTED')):
					print(" Exported service intent filter")
	activities = _a.get_receivers()
	for x in activities:
		intent = _a.get_intent_filters("receiver", x)
		
		if (len(intent) > 0):
			for i in intent['category']:				
				if(i.find('DEFAULT') or i.find('EXPORTED')):
					print(" Exported receiver intent filter")	
#print(_a.get_services())
	#print(_a.get_receivers())

def main():

	_args = _parseargs()

	_a = apk.APK(_args.file)
	print("Analyse file: {:s}".format(_args.file))
	print("Package name: {:s}".format(_a.get_package()))
	print(_a.get_app_name())

	#for research question 3
	_findPerm(_a.get_permissions())
	
	#for research question 8
	#_intentFilters(_a)
	
	_vm = dvm.DalvikVMFormat(_a.get_dex())
	_vmx = Analysis(_vm)
	
	_custom_trust_manager = []
	_insecure_socket_factory = []

	_custom_hostname_verifier = []
	_allow_all_hostname_verifier = []

	_custom_on_received_ssl_error = []
	
	_java=True

	for _method in _vm.get_methods():
		_hv, _a = _check_hostname_verifier(_method, _vm, _vmx)
		if len(_hv) > 0:
			_custom_hostname_verifier += _hv
		if len(_a) > 0:
			_allow_all_hostname_verifier += _a
		_tm, _i = _check_trust_manager(_method, _vm, _vmx)
		if len(_tm) > 0:
			_custom_trust_manager += _tm
		if len(_i) > 0:
			_insecure_socket_factory += _i
		_ssl = _check_ssl_error(_method, _vm, _vmx)
		if len(_ssl) > 0:
			_custom_on_received_ssl_error += _ssl
	if len(_custom_trust_manager) > 0:
		if len(_custom_trust_manager) == 1:
			print("App implements custom TrustManager:")
		elif len(_custom_trust_manager) > 1:
			print("App implements {:d} custom TrustManagers".format(len(_custom_trust_manager)) )	
	for _tm in _custom_trust_manager:
			_class_name = _tm['class'].get_name()
			print("\tCustom TrustManager is implemented in class {:s}".format(_translate_class_name(_class_name)))
			if _tm['empty']:
				print("\tImplements naive certificate check. This TrustManager breaks certificate validation!")
			if ( _tm['xref'] != None):
				for _ref in _tm['xref']:
					print("\t\tReferenced in method {:s}->{:s}".format(_translate_class_name(_ref.get_class_name()), _ref.get_name()))
			if _java:
				print("\t\tJavaSource code:")
				print("{:s}".format(_tm['java_b64']) )	
	if len(_insecure_socket_factory) > 0:
		if len(_insecure_socket_factory) == 1:
			print("App instantiates insecure SSLSocketFactory:")
		elif len(_insecure_socket_factory) > 1:
			print("App instantiates {:d} insecure SSLSocketFactorys".format(len(_insecure_socket_factory)) )

		for _is in _insecure_socket_factory:
			_class_name = _translate_class_name(_is['class'].get_name())
			print("\tInsecure SSLSocketFactory is instantiated in {:s}->{:s}".format(_class_name, _is['method'].get_name()) )
			if _java:
				print("\t\tJavaSource code:")
				print("{:s}".format(_is['java_b64']) )

	if len(_custom_hostname_verifier) > 0:
		if len(_custom_hostname_verifier) == 1:
			print("App implements custom HostnameVerifier:")
		elif len(_custom_hostname_verifier) > 1:
			print("App implements {:d} custom HostnameVerifiers".format(len(_result['customhostnameverifier'])) )

		for _hv in _custom_hostname_verifier:
			_class_name = _hv['class'].get_name()
			print("\tCustom HostnameVerifiers is implemented in class {:s}".format(_translate_class_name(_class_name)) )
			if _hv['empty']:
				print("\tImplements naive hostname verification. This HostnameVerifier breaks certificate validation!")
			for _ref in _tm['xref']:
				print("\t\tReferenced in method {:s}->{:s}".format(_translate_class_name(_ref.get_class_name()), _ref.get_name()) )
			if _java:
				print("\t\tJavaSource code:" )
				print("{:s}".format(_hv['java_b64']) )

	if len(_allow_all_hostname_verifier) > 0:
		if len(_allow_all_hostname_verifier) == 1:
			print("App instantiates AllowAllHostnameVerifier:" )
		elif len(_allow_all_hostname_verifier) > 1:
			print("App instantiates {:d} AllowAllHostnameVerifiers".format(len(_allow_all_hostname_verifier))  )

		for _aa in _allow_all_hostname_verifier:
			_class_name = _translate_class_name(_aa['class'].get_name())
			print("\tAllowAllHostnameVerifier is instantiated in {:s}->{:s}".format(_class_name, _aa['method'].get_name()) )
		if _java: 
			print("\t\tJavaSource code:" )
			print("{:s}".format(_aa['java_b64']))


if __name__ == "__main__":
	main()
