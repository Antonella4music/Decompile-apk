#!/usr/bin/env python

import os, sys, argparse
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.decompiler.dad import decompile

def getClassPath(className):
    # va returna calea unde va trebui salvata o anumita clasa
    # get_name() pentru un obiect ClassDefItem va returna un nume de clasa care 
    # va incepe cu "L" si se termina cu ";" ex: Ljava/lang/Object;
	return '%s.java' % className[1:-1]

def getClassName(className):
    # va returna numele unei clase
    # ex. pentru Ljava/lang/Object; va returna: java.lang.Object
	return className[1:-1].replace('/', '.')
	
def makeDirs(directory):
    # va crea un director cu toate subdirectoarele care inca nu exista
    if not os.path.isdir(directory):
        os.makedirs(directory)
                
def decompileMethod(methodObj, analysis):
    # <methodObj> e un obiect de tipul EncodedMethod
    # <analysis> e un obiect de tipul VMAnalysis
    if method.get_code() == None:
        return None
    methodAnalysis = analysis.get_method(method)    # returns MethodAnalysis object
    decompMethod = decompile.DvMethod(methodAnalysis)
    try:
        decompMethod.process()
        methodSource = decompMethod.get_source()
    except:
        print 'Failed to decompile [%s]' % methodObj.get_name()
        return '''   method %s() {
        // failed to decompile
    }'''
    return methodSource
    
parser = argparse.ArgumentParser(description='Decompiler for APKs')

parser.add_argument('apkpath', help='path to apk')
parser.add_argument('-manifest', action='store_true', help='save AndroidManifest.xml')
parser.add_argument('-perms', action='store_true', help='list permissions')
parser.add_argument('-activities', action='store_true', help='list activities')
parser.add_argument('-decomp', action='store_true', help='decompile apk')

args = parser.parse_args()

apkpath = args.apkpath
apkobj = apk.APK(apkpath)

if args.manifest:
    # save manifest
	
	manifestPath = "/home/santoku/share/manifestSample3.xml"
	
	apkobj = dvm.APK(apkpath)
	if args.apkpath:
		if apkobj.xml["AndroidManifest.xml"].toxml(): 		
			fIn  = open (manifestPath, 'wb').write(apkobj.xml["AndroidManifest.xml"].toxml())
			print "AndroidManifest is saved to %s" % manifestPath
		else:
			print "Can't save AndroidManifest"
	
pass
    
if args.perms:
    # list permissions
	
	if args.perms:
		if apkobj.get_permissions():
			print "Permissions list:"
			for permiss in apkobj.get_permissions():
				print permiss
		else:
			print "Can't find permissions"
pass
    
if args.activities:
    # list activities
	
	if args.activities:
		if apkobj.get_activities():
			print "APK activities:"
			for actv in apkobj.get_activities():
				print actv
		else:
			print "Can't find activities"
pass 
    
if args.decomp:
    rawdex = apkobj.get_dex()
    dex = dvm.DalvikVMFormat(rawdex, decompiler='dad')
    analysis = analysis.VMAnalysis(dex)
	
if args.apkpath:	
	# enumerate classes
	apkClasses = dex.get_classes()
	if apkClasses:
		print "Classes List:"
		for eachClass in apkClasses:
			print getClassName(eachClass.get_name())
				
		# for each class enumerate interfaces
		apkInterfaces = eachClass.get_interfaces()
		if apkInterfaces:
			print "Interfaces List:"
			for eachInterface in apkInterfaces:
				print getClassName(eachInterface)
		else:
			print "Can't find interfaces"
			
		# for each class enumerate fields	
		apkFields = eachClass.get_fields()
		if apkFields:
			print "Fields List:"
			for eachField in apkFields:
				print getClassName(eachField.get_name())
		else:
			print "Can't find fields"

		# for each class enumerate query super class	
		apkSuperClass = eachClass.get_superclassname()
		if apkSuperClass:
			print "Superclasse:", getClassName(eachClass.get_superclassname())
		else:
			print "Can't find superclasses"
		
		# for each class enumerate and decompile methods
		apkMethods = eachClass.get_methods()
		if apkMethods:
			print "Methods list:"
			for eachMethod in apkMethods:
				print eachMethod.get_name()
				try:
					eachMethod = False
				except methodUndefined:
					print "Decompile methods:", decompileMethod(eachMethod, analysis)
		else:
			print "Can't find methods"
		
	else:
		print "Can't find classes"