# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------
# Code scanning for CWE
# Author:	MGE
# Log:
# 27/9/2016 SCS - Framework Upgrade 1.5.11

import cast_upgrade_1_5_11 # @UnusedImport
from cast.application import open_source_file
from cast.application import ApplicationLevelExtension, ReferenceFinder, Bookmark, Object
from collections import defaultdict
import logging
import re

import local_library

#Counting register
MGECountList = list()
MGECountResults = dict()

# CWE_685
aFunctionDefinitionName = []
aFunctionDefinitionNPar = []
aFunctionCallName = []
aFunctionCallNPar = []
aFunctionCallBookmark = []
# RLB-9
aFloatVariableName = []
# RLB-12
aFloatClassName = []

# ..............................................................................
# ..............................................................................

def update_counts(t):
#   Author :                 SCS
#   Last modification date : 5/5/2017
#   Description:             Log the tuple t on an extra internal counter register    
    global MGECountList
    
    try:
        if not(t[1] == 0 and t[2] == 0):        
            MGECountList.append(t)  
    except Exception as err:
        logging.error("local_library : Error: %s", str(err))
                
def count_results():
#   Author :                 SCS
#   Last modification date : 5/5/2017
#   Description:             Produces a string with counting results
#   RETURNS:                 a dictionary with the list of counts
    global MGECountList  

    regNV = dict()
    regNNAV = dict()
        
    try:
        for e in MGECountList:        
            if not e[0] in regNV.keys():
                regNV[e[0]] = int(e[1])
                regNNAV[e[0]] = int(e[2])
            else:
                regNV[e[0]] = regNV[e[0]] + int(e[1])
                regNNAV[e[0]] = regNNAV[e[0]] + int(e[2])
                        
        for k in sorted(regNV):                
            MGECountResults[k] = "Violations: " + str(regNV[k]) + ", Not Allowed Objects Violations: " + str(regNNAV[k])   
        
    except Exception as err:
        logging.error("SCS Global : Error: %s", str(err))

# ..............................................................................
# ..............................................................................

def scan_file_OMG_RLB_18(application, pfile, fileType):
#   Author :                          MGE
#   last modification date:           24/3/2017
#   Description: OMG-ASCCRM-RLB-18:   Storable and Member Data Element Initialization with Hard-Coded Network Resource Configuration Data 
#   Languages :                       C/C++/C#
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.OMGRLB18violationCPP     - CatID=2002000 PropID=2002024 SubID=2002274 QRID=2002598
#                                     CWEforFDA_CustomMetrics_CSharp.OMGRLB18violationCSharp - CatID=2003000 PropID=2003024 SubID=2003274 QRID=2003598
#   NOTE
#   
#   
#    
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("OMG-RLB-18 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("OMG-RLB-18 : Starting scan_file_OMG_RLB_18 > " + str(pfile.name))
    
    patNetResource1 = "([12]?[0-5]?[0-9]\.[12]?[0-5]?[0-9]\.[12]?[0-5]?[0-9]\.[12]?[0-5]?[0-9])"
    patNetResource2 = "(http[s]?://)|(ftp://)|(mailto://)|(file://)|(data://)|(irc://)"
    patNetResource3 = "(www\.)|(ftp\.)"
    patNetResource4 = "([\?\&][ \t]*[a-z0-9\-\_]+[ \t]*\=[ \t]*[a-z0-9\-\_]+)"
    # All pattern included in double quotes (strings)
    patNetResource  = "[^=]=[ \t]*\".*("+patNetResource1+"|"+patNetResource2+"|"+patNetResource3+"|"+patNetResource4+").*\""

    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    
    try:
        with open_source_file(pfile.get_path()) as f:
            #current line number
            current_line = 0
            
            for line in f:
                # Line of code
                current_line += 1
                
                # Comment Exclusion - Start
                resultCom = re.finditer(patComment, line)
                if not resultCom is None:
                    for c in resultCom:
                        if c.group(1):
                            isInSingleLineComment = True
                        if c.group(2):
                            isInMultiLineComment = True
                        if c.group(3):
                            isInMultiLineComment = False
                if isInMultiLineComment:
                    continue
                if isInSingleLineComment:
                    isInSingleLineComment = False
                    continue
                # Comment Exclusion - End
                
                nBytes = nBytes + len(line)
                
                # Get the most specific object containing the line
                obj = pfile.find_most_specific_object(current_line, 1)

                result = re.finditer(patNetResource, line)
                isFirstViolation = True     
                if not result is None:
                    for p in result:
                        # Set a bookmark for violation
                        bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                        #logging.debug("scan_file_OMG_RLB_18 : Found violation > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        
                        if fileType == "CCPP":
                            #logging.debug("saving violation for CCPP > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                            if isFirstViolation:
                                try:
                                    obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.OMGRLB18violationCPP',bk)
                                except Exception as e:
                                    local_library.cwefdaLoggerWarning("OMG-RLB-18: Violation not allowed on this kind of object, next version")
                                    nbNAViolation = nbNAViolation + 1
                                else:
                                    nbViolation += 1
                                    isFirstViolation = False
                                    #local_library.cwefdaLoggerInfo("SAVED CCPP")
                        
                        if fileType == "CSHARP":
                            #logging.debug("saving violation forCSHARP > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                            if isFirstViolation:
                                try:
                                    obj.save_violation('CWEforFDA_CustomMetrics_CSharp.OMGRLB18violationCSharp',bk)
                                except Exception as e:
                                    local_library.cwefdaLoggerWarning("OMG-RLB-18: Violation not allowed on this kind of object, next version")
                                    nbNAViolation = nbNAViolation + 1
                                else:
                                    nbViolation += 1
                                    isFirstViolation = False
                                    #local_library.cwefdaLoggerInfo("CSHARP")                            
    except FileNotFoundError:
        logging.error("OMG-RLB-18 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("OMG-RLB-18 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("OMG-RLB-18 : END scan_file_OMG_RLB_18 %s - Found %s violation ", str(pfile.name), str(nbViolation))                 
    
    tc = "OMG-RLB-18",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "OMG-RLB-18",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)
    
def scan_file_CWE_685_Step1(application, pfile, fileType):
#   Author :                          MGE
#   last modification date:           24/3/2017
#   Description: CWE-685:             Function Call With Incorrect Number of Arguments 
#   Languages :                       C
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.CWE685violationCPP     - CatID=2002000 PropID=2002016 SubID=2002266 QRID=2003582
#                                     
#   NOTE
#   scan_file_CWE_685_Step1: find all function definition and store it with number of parameters defined 
#   scan_file_CWE_685_Step2: find all function call by means of function name found in step1, and compare it with parameters stored
#  
    global aFunctionDefinitionName 
    global aFunctionDefinitionNPar 
    global aFunctionCallName 
    global aFunctionCallNPar 
    global aFunctionCallBookmark 
    global aFloatVariableName 
    global aFloatClassName 

    myIdx=0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-685-Step1 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-685-Step1 : Starting scan_file_CWE_685_Step1 > " + str(pfile.name))
    
    #pattern:                  return_type                    function_name                      ( parameter_list )                        { body of the function }
    patFunctionDefinition = "([A-Za-z][A-Za-z0-9_\-]*[ \t]+)([A-Za-z][A-Za-z0-9_\-]*)([ \t\r\n]*)(\([A-Za-z0-9_\- \t\r\n.,\.\*]*\))([ \t\r\n]*){"
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
     
    #rfCall= ReferenceFinder()
    #rfCall.add_pattern('patFunctionDefinition', before='', element = patFunctionDefinition, after='')
    #rfCall.add_pattern('patComment',            before='', element = patComment,            after='')
    try:
        with open_source_file(pfile.get_path()) as f:        
            #current line number
            current_line = 0

            for line in f:
                # Line of code
                current_line += 1
                
                resultCom = re.finditer(patComment, line)
                # Comment Exclusion - Start
                if not resultCom is None:
                    for c in resultCom:
                        if c.group(1):
                            isInSingleLineComment = True
                        if c.group(2):
                            isInMultiLineComment = True
                        if c.group(3):
                            isInMultiLineComment = False
                if isInMultiLineComment:
                    continue
                if isInSingleLineComment:
                    isInSingleLineComment = False
                    continue
                # Comment Exclusion - End
                
                nBytes = nBytes + len(line)

                resultFuncDef = re.finditer(patFunctionDefinition, line)
                if not resultFuncDef is None:
                    for p in resultFuncDef:
                        if not (local_library.is_a_keyword(p.group(2)) == 1):
                            nFun = p.group(2)
                            nPar = len(p.group(4).split(','))
                            functionIsPresent = False
                            for f in aFunctionDefinitionName:
                                if (f == nFun):
                                    functionIsPresent = True
                            if not functionIsPresent:
                                aFunctionDefinitionName.append(1)
                                aFunctionDefinitionNPar.append(1)
                                myIdx = len(aFunctionDefinitionName)-1
                                #local_library.cwefdaLoggerInfo("----------------------------CWE-685: adding FunctionDefinition > %s %s", nFun, nPar)
                                aFunctionDefinitionName[myIdx] = nFun
                                aFunctionDefinitionNPar[myIdx] = nPar
    except FileNotFoundError:
        logging.error("CWE-685-Step1 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-685-Step1 : Error: %s", str(e)) 
                        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-685-Step1 : END CWE-685 %s - Found %s definitions ", str(myIdx))
    
    #Extra log
    t = "CWE-685-STEP1",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)
  
def scan_file_CWE_685_Step2(application, pfile, fileType):
#   Author :                          MGE
#   last modification date:           24/3/2017
#   Description: CWE-685:             Function Call With Incorrect Number of Arguments 
#   Languages :                       C
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.CWE685violationCPP     - CatID=2002000 PropID=2002016 SubID=2002266 QRID=2003582
#                                     
#   NOTE
#   scan_file_CWE_685_Step1: find all function definition and store it with number of parameters defined 
#   scan_file_CWE_685_Step2: find all function call by means of function name found in step1, and compare it with parameters stored
# 
    global aFunctionDefinitionName 
    global aFunctionDefinitionNPar 
    global aFunctionCallName 
    global aFunctionCallNPar 
    global aFunctionCallBookmark 
    global aFloatVariableName 
    global aFloatClassName 
   
    myIdx = 0
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-685-Step2 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-685-Step2 : Starting scan_file_CWE_685_Step2 > " + str(pfile.name))
    
    patFuncName = "[A-Za-z][A-Za-z0-9_\-]*"
    patFunctionCall = "("+ patFuncName +")"+"([ \t\r\n]*)(\([A-Za-z0-9_\- \t\r\n.,\.\*]*\))"
    
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    
    try:
        with open_source_file(pfile.get_path()) as f:        
            #current line number
            current_line = 0

            for line in f:
                # Line of code
                current_line += 1
                
                resultCom = re.finditer(patComment, line)
                # Comment Exclusion - Start
                if not resultCom is None:
                    for c in resultCom:
                        if c.group(1):
                            isInSingleLineComment = True
                        if c.group(2):
                            isInMultiLineComment = True
                        if c.group(3):
                            isInMultiLineComment = False
                if isInMultiLineComment:
                    continue
                if isInSingleLineComment:
                    isInSingleLineComment = False
                    continue
                # Comment Exclusion - End
                
                nBytes = nBytes + len(line)

                obj = pfile.find_most_specific_object(current_line, 1)
                
                try:
                    resultFuncCall = re.finditer(patFunctionCall, line)
                except:
                    resultFuncCall = None
                    #local_library.cwefdaLoggerWarning("CWE-685-Step2: Cannot apply pattern %s to line %s", patFunctionCall, current_line)
                
                if not resultFuncCall is None:
                    for p in resultFuncCall:   
                        for f in aFunctionDefinitionName:   
                            myIdx = aFunctionDefinitionName.index(f)  
                            nFun = p.group(1)
                            nPar = len(p.group(3).split(','))
                            if (nFun == aFunctionDefinitionName[myIdx] and nPar != aFunctionDefinitionNPar[myIdx]):
                                #local_library.cwefdaLoggerInfo("------------------------------------> Found different parameter!!! %s %s <<-->> %s %s", nFun, str(nPar), self.aFunctionDefinitionName[myIdx], str(self.aFunctionDefinitionNPar[myIdx]))
                                #logging.debug("CWE_685_Step2 : C!!!! Found statement %s ==> %s ", str(reference.value), str(reference.bookmark))
                                try:
                                    bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                    obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE685violationCPP',bk)
                                    #reference.object.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE685violationCPP', reference.bookmark)
                                except Exception as e:
                                    local_library.cwefdaLoggerWarning("CWE-685-Step2: Violation not allowed on this kind of object, next version")
                                    nbNAViolation = nbNAViolation + 1
                                else:
                                    nbViolation += 1

    except FileNotFoundError:
        logging.error("CWE-685-Step2 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-685-Step2 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-685-Step2 : END CWE-685 %s - Found %s violation ", str(pfile.name), str(nbViolation))
    
    tc = "CWE-685-STEP2",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-685-STEP2",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

def scan_file_CWE_483(application, pfile, fileType):
#   Author :                          MGE
#   last modification date:           24/3/2017
#   Description:                      CWE-483: Incorrect Block Delimitation 
#   Languages :                       C/C++/C#
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.CWE483violationCPP       - CatID=2002000 PropID=2002013 SubID=2002263 QRID=2002598
#                                     CWEforFDA_CustomMetrics_CSharp.CWE483violationCSharp   - CatID=2003000 PropID=2003013 SubID=2003263 QRID=2003576
#   NOTE
#    

    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    msecs = local_library.millis()
    nBytes = 0
 
    local_library.cwefdaLoggerInfo("CWE-483 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-483 : Starting scan_file_CWE_483 > " + str(pfile.name))
    
    patIfNoBlk1 = "(if[ \t\n\r]*\(([A-Za-z0-9_\(\)\.\,:\?\=\/\+\-\* \t\n\r]+)(?!{)([A-Za-z0-9_\(\)\.\,:\?\=\/\+\-\* \t\n\r]+);)"
    patIfNoBlk2 = "(else[ \t\n\r]*([A-Za-z0-9_\(\)\.\,:\?\=\/\+\-\* \t\n\r]+)(?!{)([A-Za-z0-9_\(\)\.\,:\?\=\/\+\-\* \t\n\r]+);)"
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    patIfNoBlk = patIfNoBlk1 +"|" + patIfNoBlk2
    #rfCall= ReferenceFinder()
    #rfCall.add_pattern('patIfNoBlk', before='', element = patIfNoBlk, after='')
    #rfCall.add_pattern('patComment', before='', element = patComment, after='')
    try:
        with open_source_file(pfile.get_path()) as f:        
            #current line number
            current_line = 0

            for line in f:
                # Line of code
                current_line += 1
                
                resultCom = re.finditer(patComment, line)
                # Comment Exclusion - Start
                if not resultCom is None:
                    for c in resultCom:
                        if c.group(1):
                            isInSingleLineComment = True
                        if c.group(2):
                            isInMultiLineComment = True
                        if c.group(3):
                            isInMultiLineComment = False
                if isInMultiLineComment:
                    continue
                if isInSingleLineComment:
                    isInSingleLineComment = False
                    continue
                # Comment Exclusion - End
                
                nBytes = nBytes + len(line)
            
                obj = pfile.find_most_specific_object(current_line, 1)
                #logging.debug("Statement to analize >> %s", current_line)   
                
                resultIfNoBlk = re.finditer(patIfNoBlk, line)
                if not resultIfNoBlk is None:
                    for p in resultIfNoBlk:
                        if fileType == "CCPP":
                            #logging.debug("CWE_483 : C/C++! Found Test statement %s ==> %s", str(reference.value), str(reference.bookmark))
                            try:
                                bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE483violationCPP',bk)
                                #reference.object.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE483violationCPP', reference.bookmark)
                            except Exception as e:
                                local_library.cwefdaLoggerWarning("CWE-483: Violation not allowed on this kind of object, next version")
                                nbNAViolation = nbNAViolation + 1
                            else:
                                nbViolation += 1

                        if fileType == "CSHARP":
                            #logging.debug("CWE_483 : CSHARP! Found Test statement %s ==> %s", str(reference.value), str(reference.bookmark))
                            try:
                                bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                obj.save_violation('CWEforFDA_CustomMetrics_CSharp.CWE483violationCSharp',bk)
                                #reference.object.save_violation('CWEforFDA_CustomMetrics_CSharp.CWE483violationCSharp', reference.bookmark)
                            except Exception as e:
                                local_library.cwefdaLoggerWarning("CWE-483: Violation not allowed on this kind of object, next version")
                                nbNAViolation = nbNAViolation + 1
                            else:
                                nbViolation += 1
                        
    except FileNotFoundError:
        logging.error("CWE-483 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-483 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE_483 : END CWE-483 %s - Found %s violation ", str(pfile.name), str(nbViolation))  
    
    tc = "CWE-483",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-483",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)              
    
def scan_file_OMG_RLB_9_Step1(application, pfile, fileType):
#   Author :                          MGE
#   last modification date:           24/3/2017
#   Description: OMG RLB-9:           OMG RLB-9: Float Type Storable and Member Data Element Comparison with Equality Operator 
#   Languages :                       C/C++/C#
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.OMGRLB9violationCPP       - CatID=2002000 PropID=2002022 SubID=2002272 QRID=2002594
#                                     CWEforFDA_CustomMetrics_CSharp.OMGRLB9violationCSharp   - CatID=2003000 PropID=2003022 SubID=2003272 QRID=2003594
#   NOTE
#   scan_file_OMG_RLB_9_Step1: find all float objects definition and store it
#   scan_file_OMG_RLB_9_Step2: find all = comparison with float objects involved
#   The scope is internal to file+function or Global. Lower scopes are not considerered
# 
    global aFunctionDefinitionName 
    global aFunctionDefinitionNPar 
    global aFunctionCallName 
    global aFunctionCallNPar 
    global aFunctionCallBookmark 
    global aFloatVariableName 
    global aFloatClassName 
       
    myIdx=0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    msecs = local_library.millis()
    nBytes = 0
 
    local_library.cwefdaLoggerInfo("OMG-RLB-9-Step1 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("OMG-RLB-9-Step1 : Starting scan_file_OMG_RLB_9_Step1 > " + str(pfile.name))
    
    patFloatDefinition = "((float)|(double)|(long double))([ \t\r\n]+)([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
     
    #rfCall= ReferenceFinder()
    #rfCall.add_pattern('patFloatDefinition', before='', element = patFloatDefinition, after='')
    #rfCall.add_pattern('patComment',            before='', element = patComment,            after='')
    try:
        with open_source_file(pfile.get_path()) as f:        
            #current line number
            current_line = 0

            for line in f:
                # Line of code
                current_line += 1
                
                resultCom = re.finditer(patComment, line)
                # Comment Exclusion - Start
                if not resultCom is None:
                    for c in resultCom:
                        if c.group(1):
                            isInSingleLineComment = True
                        if c.group(2):
                            isInMultiLineComment = True
                        if c.group(3):
                            isInMultiLineComment = False
                if isInMultiLineComment:
                    continue
                if isInSingleLineComment:
                    isInSingleLineComment = False
                    continue
                # Comment Exclusion - End
                
                nBytes = nBytes + len(line)
                  
                resultPatFloatDef = re.finditer(patFloatDefinition, line)
            
                if not resultPatFloatDef is None:
                #if reference.pattern_name=='patFloatDefinition':
                    ps = re.compile('([A-Za-z][A-Za-z0-9_\-]*)([ \t\r\n]*)(\([A-Za-z0-9_\- \t\r\n.,\.\*]*\))')
                    codeWithoutFunctions = ps.sub('|NullF|',line)
                    ps = re.compile('([ \t\r\n]*)=([ \t\r\n]*)([0-9\.]+)')
                    codeWithoutAssign = ps.sub('',codeWithoutFunctions)
                    
                    #logging.debug("----------------------------%s-----------------------",codeWithoutFunctions)
                    result = re.finditer(patFloatDefinition, codeWithoutAssign)

                    for p in result:
                        # Bookmark(File(TestCase.cs, CAST_DotNet_CSharpFile), 28, 19, 28, 33) 
                        #local_library.cwefdaLoggerInfo("%s",reference.bookmark)
                        bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                        current_line = int(str(bk).split(",")[2])
                        #current_line = int(str(reference.bookmark).split(",")[2])
                        #local_library.cwefdaLoggerInfo("%s %s",str(current_line), nScp)
                        tScp = pfile.find_most_specific_object(current_line, 1).get_name()
                        tVar = p.group(6)
                        #logging.debug("=================== Global: %s %s", tScp, tVar)
                        if (tScp == tVar):
                            nVar = "[Global]." + tVar
                        else:
                            nVar = "[" + pfile.get_path()+"]." + tScp + "." + tVar    
                        #logging.debug("=================== Var: %s ", nVar)
                        variableIsPresent = False
                        # Check deleted for performance reason, a little amout of duplication is better 
                        if not variableIsPresent:
                            aFloatVariableName.append(1)
                            myIdx = len(aFloatVariableName)-1
                            aFloatVariableName[myIdx] = nVar
                            #logging.debug("----------------------------OMG_RLB_9_Step1: adding aFloatVariableName > %s ", self.aFloatVariableName[myIdx])

    except FileNotFoundError:
        logging.error("OMG-RLB-9-Step1 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("OMG-RLB-9-Step1 : Error: %s", str(e)) 
                        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("OMG-RLB-9-Step1 : END OMG-RLB-9-Step1 %s - Found %s definitions ", str(myIdx))
    
    #Extra log
    t = "OMG-RLB-9-STEP1",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

def scan_file_OMG_RLB_9_Step2(application, pfile, fileType):
#   Author :                          MGE
#   last modification date:           24/3/2017
#   Description: OMG RLB-9:           OMG RLB-9: Float Type Storable and Member Data Element Comparison with Equality Operator 
#   Languages :                       C/C++/C#
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.OMGRLB9violationCPP       - CatID=2002000 PropID=2002022 SubID=2002272 QRID=2002594
#                                     CWEforFDA_CustomMetrics_CSharp.OMGRLB9violationCSharp   - CatID=2003000 PropID=2003022 SubID=2003272 QRID=2003594
#   NOTE
#   scan_file_OMG_RLB_9_Step1: find all float objects definition and store it
#   scan_file_OMG_RLB_9_Step2: find all = comparison with float objects involved
#   The scope is internal to file+function or Global. Lower scopes are not considerered
#
    global aFunctionDefinitionName 
    global aFunctionDefinitionNPar 
    global aFunctionCallName 
    global aFunctionCallNPar 
    global aFunctionCallBookmark 
    global aFloatVariableName 
    global aFloatClassName 
        
    myIdx = 0
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("OMG-RLB-9-Step2 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("OMG-RLB-9-Step2 : Starting scan_file_OMG_RLB_9_Step2 > " + str(pfile.name))
    
    patFloatName = "[A-Za-z0-9_\-\.]*"
    patFloatCompLeft  = "("+ patFloatName +")" + "([A-Za-z0-9_ \(\)\t\r\n\*\+\-\/]*[\=][\=])"
    patFloatCompRight = "(==[A-Za-z0-9_ \(\)\t\r\n\*\+\-\/]*)" + "("+ patFloatName +")"
       
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
     
    try:
        with open_source_file(pfile.get_path()) as f:        
            #current line number
            current_line = 0

            for line in f:
                # Line of code
                current_line += 1
                
                resultCom = re.finditer(patComment, line)
                # Comment Exclusion - Start
                if not resultCom is None:
                    for c in resultCom:
                        if c.group(1):
                            isInSingleLineComment = True
                        if c.group(2):
                            isInMultiLineComment = True
                        if c.group(3):
                            isInMultiLineComment = False
                if isInMultiLineComment:
                    continue
                if isInSingleLineComment:
                    isInSingleLineComment = False
                    continue
                # Comment Exclusion - End
                
                nBytes = nBytes + len(line)
            
                obj = pfile.find_most_specific_object(current_line, 1)
                #logging.debug("Statement to analize >> %s", current_line)   
                
                try:
                    resultpatFloatRigh = re.finditer(patFloatCompRight, line)
                except:
                    resultpatFloatRigh = None
                    #local_library.cwefdaLoggerWarning("OMG-RLB-9-Step2: Cannot apply pattern %s to line %s", patFloatCompRight, current_line)
                
                # --- Scan for pattern on the right
                # ------------------------------------------------------------------------------------     
                if not resultpatFloatRigh is None:
                    for p in resultpatFloatRigh:
                        for myIdx in range(len(aFloatVariableName)):                            
                            bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                            current_line = int(str(bk).split(",")[2])
                            tVar = p.group(2)
                            tScp = pfile.find_most_specific_object(current_line, 1).get_name()
                            if (tScp == tVar):
                                nVar = "[Global]." + tVar
                            else:
                                nVar = "[" + pfile.get_path()+"]." + tScp + "." + tVar 
                            
                            if (nVar == aFloatVariableName[myIdx]):
                                if fileType == "CCPP":
                                    #logging.debug("RLB-9: C/C++! Found Test statement %s ==> %s", str(reference.value), str(reference.bookmark))
                                    try:
                                        #bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                        obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.OMGRLB9violationCPP',bk)
                                        #reference.object.save_violation('CWEforFDA_CustomMetrics_C_CPP.OMGRLB9violationCPP', reference.bookmark)
                                    except Exception as e:
                                        local_library.cwefdaLoggerWarning("OMG-RLB-9-Step2: Violation not allowed on this kind of object, next version")
                                        nbNAViolation = nbNAViolation + 1
                                    else:
                                        nbViolation += 1
                                if fileType == "CSHARP":
                                    #logging.debug("RLB-9 : CSHARP! Found Test statement %s ==> %s", str(reference.value), str(reference.bookmark))
                                    try:
                                        #bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                        obj.save_violation('CWEforFDA_CustomMetrics_CSharp.OMGRLB9violationCSharp',bk)
                                        #reference.object.save_violation('CWEforFDA_CustomMetrics_CSharp.OMGRLB9violationCSharp', reference.bookmark)
                                    except Exception as e:
                                        local_library.cwefdaLoggerWarning("OMG-RLB-9-Step2: Violation not allowed on this kind of object, next version")
                                        nbNAViolation = nbNAViolation + 1
                                    else:
                                        nbViolation += 1
                                     
                try:
                    resultpatFloatLeft = re.finditer(patFloatCompLeft, line)
                except:
                    resultpatFloatLeft = None
                    #local_library.cwefdaLoggerWarning("OMG-RLB-9-Step2: Cannot apply pattern %s to line %s", patFloatCompLeft, current_line)
                
                # --- Scan for pattern on the left
                # ------------------------------------------------------------------------------------    
                if not resultpatFloatLeft is None:
                    for p in resultpatFloatLeft:   
                        for myIdx in range(len(aFloatVariableName)):
                            bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                            current_line = int(str(bk).split(",")[2])
                            tVar = p.group(1)
                            tScp = pfile.find_most_specific_object(current_line, 1).get_name()
                            if (tScp == tVar):
                                nVar = "[Global]." + tVar
                            else:
                                nVar = "[" + pfile.get_path()+"]." + tScp + "." + tVar
                                
                            if (nVar == aFloatVariableName[myIdx]):
                                if fileType == "CCPP":
                                    #logging.debug("RLB-9: C/C++! Found Test statement %s ==> %s", str(reference.value), str(reference.bookmark))
                                    try:
                                        #bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                        obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.OMGRLB9violationCPP',bk)
                                        #reference.object.save_violation('CWEforFDA_CustomMetrics_C_CPP.OMGRLB9violationCPP', reference.bookmark)
                                    except Exception as e:
                                        local_library.cwefdaLoggerWarning("OMG-RLB-9-Step2: Violation not allowed on this kind of object, next version")
                                        nbNAViolation = nbNAViolation + 1
                                    else:
                                        nbViolation += 1
                                if fileType == "CSHARP":
                                    #logging.debug("RLB-9 : CSHARP! Found Test statement %s ==> %s", str(reference.value), str(reference.bookmark))
                                    try:
                                        #bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                        obj.save_violation('CWEforFDA_CustomMetrics_CSharp.OMGRLB9violationCSharp',bk)
                                        #reference.object.save_violation('CWEforFDA_CustomMetrics_CSharp.OMGRLB9violationCSharp', reference.bookmark)
                                    except Exception as e:
                                        local_library.cwefdaLoggerWarning("OMG-RLB-9-Step2: Violation not allowed on this kind of object, next version")
                                        nbNAViolation = nbNAViolation + 1
                                    else:
                                        nbViolation += 1
  
    except FileNotFoundError:
        logging.error("OMG-RLB-9-Step2 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("OMG-RLB-9-Step2 : Error: %s", str(e)) 
                
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("OMG-RLB-9-Step2 : END RLB-9-Step2 %s - Found %s violation ", str(pfile.name), str(nbViolation))
    
    tc = "OMG-RLB-9-STEP2",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "OMG-RLB-9-STEP2",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

def scan_file_OMG_RLB_12(application, pfile, fileType):
#   Author :                          MGE
#   last modification date:           29/3/2017
#   Description: OMG RLB-12:          OMG RLB-12: Singleton Class Instance Creation without Proper Lock Element Management 
#   Languages :                       C++/C#
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.OMGRLB12violationCPP       - CatID=2002000 PropID=2002023 SubID=2002273 QRID=2002596
#                                     CWEforFDA_CustomMetrics_CSharp.OMGRLB12ViolationCSharp   - CatID=2003000 PropID=2003023 SubID=2003273 QRID=2003596
#   NOTE
#   1) find all classes implementing singleton (with ""new className"" inside)
#   2) find all singleton classes without any lock primitive inside the method containing new
# 
    nbViolation = 0
    nbNAViolation = 0
    myIdx = -1
    isInMultiLineComment = False
    isInSingleLineComment = False
    aClass = []
    aClassIsSingleton = []
    aBookmark = []
    aIsViolation = []
    aCastSingletonObj = []
    
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("OMG-RLB-12 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("OMG-RLB-12 : Starting scan_file_OMG_RLB_12 > " + str(pfile.name))
    
    patClassDefinition = "(class[ \t]+)([A-Za-z0-9_\-]+)"
    patLockUsage = "([Ll][Oo][Cc][Kk])"
    #patBodyStart = "\{" 
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    
    try:
        with open_source_file(pfile.get_path()) as f:
            #current line number
            current_line = 0
            #classDefinition = False
            for line in f:
                # Line of code
                current_line += 1
                
                # Comment Exclusion - Start
                resultCom = re.finditer(patComment, line)
                if not resultCom is None:
                    for c in resultCom:
                        if c.group(1):
                            isInSingleLineComment = True
                        if c.group(2):
                            isInMultiLineComment = True
                        if c.group(3):
                            isInMultiLineComment = False
                if isInMultiLineComment:
                    continue
                if isInSingleLineComment:
                    isInSingleLineComment = False
                    continue
                # Comment Exclusion - End
                
                nBytes = nBytes + len(line)
                
                # Get the most specific object containing the line
                #if myIdx != 0:
                #obj = pfile.find_most_specific_object(current_line, 1)
                #local_library.cwefdaLoggerInfo("=====================================================")
                #local_library.cwefdaLoggerInfo("= Line: %s",str(current_line) )
                #local_library.cwefdaLoggerInfo("= Cast Object: %s",obj )
                #local_library.cwefdaLoggerInfo("= Cast Object Type: %s",obj.get_type())
                #local_library.cwefdaLoggerInfo("=====================================================")
 
                r1 = re.finditer(patClassDefinition, line)
                if not r1 is None:
                    for p1 in r1:
                        #bk = Bookmark(pfile,current_line,p1.start()+1,current_line,p1.end())
                        aClass.append(1)
                        aBookmark.append(1)
                        aIsViolation.append(1)
                        aCastSingletonObj.append(1)
                        aClassIsSingleton.append(1)
                        myIdx = len(aClass)-1
                        aClass[myIdx] = p1.group(2)
                        aIsViolation[myIdx] = True
                        aClassIsSingleton[myIdx] = False
                        patSingletonDefinition = "(new[ \t]+" + p1.group(2) +")"
                        #local_library.cwefdaLoggerInfo("=====================================================")
                        #local_library.cwefdaLoggerInfo("= myIdx:       %d",myIdx)
                        #local_library.cwefdaLoggerInfo("= Class:   %s",aClass[myIdx])
                        #local_library.cwefdaLoggerInfo("= Violation:   %s",aIsViolation[myIdx])
                        #local_library.cwefdaLoggerInfo("= patSingletonDefinition: %s",patSingletonDefinition)
                        #local_library.cwefdaLoggerInfo("=====================================================")
                if myIdx != -1:
                    r2 = re.finditer(patSingletonDefinition, line)
                    if not r2 is None:
                        for p2 in r2:
                            #local_library.cwefdaLoggerInfo(" in patSingletonDefinition FOUND")
                            aCastSingletonObj[myIdx] = pfile.find_most_specific_object(current_line, p2.start()-3)
                            aBookmark[myIdx] = Bookmark(pfile,current_line,p2.start()+1,current_line,p2.end())
                            aClassIsSingleton[myIdx] = True
                            #local_library.cwefdaLoggerInfo("Tipo Obj: %s ", type(aCastSingletonObj[myIdx]))
                            #local_library.cwefdaLoggerInfo("Is Singleton??? %d ",current_line)
                            #local_library.cwefdaLoggerInfo("Obj: %s ", aCastSingletonObj[myIdx].get_name())

                    r3 = re.finditer(patLockUsage, line)
                    if not r3 is None:
                        aIsViolation[myIdx] = False
                        #for p3 in r3:
                            #local_library.cwefdaLoggerInfo(" in patLockUsage FOUND")
                            #curObj = pfile.find_most_specific_object(current_line, 1)
                            #local_library.cwefdaLoggerInfo(" curObj = %s", curObj.get_name())
                            #aIsViolation[myIdx] = False

            for vIdx in range(len(aClass)):
                #local_library.cwefdaLoggerInfo("=====================================================")
                #local_library.cwefdaLoggerInfo("= Class : %s",aClass[vIdx])
                #local_library.cwefdaLoggerInfo("= Is Singleton: %s",aClassIsSingleton[vIdx])
                #local_library.cwefdaLoggerInfo("= Bookmark: %s", aBookmark[vIdx])
                #local_library.cwefdaLoggerInfo("= Violation: %s",aIsViolation[vIdx])
                #local_library.cwefdaLoggerInfo("= Cast Sinlgeton Obj : %s",aCastSingletonObj[vIdx].get_name())
                #local_library.cwefdaLoggerInfo("=====================================================")
                if aClassIsSingleton[vIdx] and aIsViolation[vIdx]:
                    if fileType == "CCPP":
                        try:
                            aCastSingletonObj[vIdx].save_violation('CWEforFDA_CustomMetrics_C_CPP.OMGRLB12violationCPP', aBookmark[vIdx])
                        except Exception as e:
                            local_library.cwefdaLoggerWarning("OMG-RLB-12: Violation not allowed on this kind of object, next version")
                            nbNAViolation = nbNAViolation + 1
                        else:
                            nbViolation += 1
                            #local_library.cwefdaLoggerInfo("SAVED CCPP")
                    if fileType == "CSHARP":
                        try:
                            aCastSingletonObj[vIdx].save_violation('CWEforFDA_CustomMetrics_CSharp.OMGRLB12violationCSharp',aBookmark[vIdx])
                        except Exception as e:
                            local_library.cwefdaLoggerWarning("OMG-RLB-12: Violation not allowed on class object, next version")
                            nbNAViolation = nbNAViolation + 1
                        else:
                            nbViolation += 1
                            #local_library.cwefdaLoggerInfo("SAVED CSHARP")
                            
    except FileNotFoundError:
        logging.error("OMG-RLB-12 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("OMG-RLB-12 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("OMG-RLB-12 : END scan_file_OMG_RLB_12 %s - Found %s violation ", str(pfile.name), str(nbViolation))                 
    
    tc = "OMG-RLB-12",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "OMG-RLB-12",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)
    