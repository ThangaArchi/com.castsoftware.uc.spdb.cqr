# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
# Code scanning for CWE
# Author:	PMB
# Log:
# 27/9/2016 SCS - Framework Upgrade 1.5.11

import cast_upgrade_1_5_11 # @UnusedImport
from cast.application import open_source_file
from cast.application import ApplicationLevelExtension, ReferenceFinder, Bookmark, Object
import logging
import re

import local_library

#Counting register
PMBCountList = list()
PMBCountResults = dict()

# ..............................................................................
# ..............................................................................

def update_counts(t):
#   Author :                 SCS
#   Last modification date : 5/5/2017
#   Description:             Log the tuple t on an extra internal counter register    
    global PMBCountList
    
    try:
        if not(t[1] == 0 and t[2] == 0):        
            PMBCountList.append(t)  
    except Exception as err:
        logging.error("local_library : Error: %s", str(err))
               
def count_results():
#   Author :                 SCS
#   Last modification date : 5/5/2017
#   Description:             Produces a string with counting results
#   RETURNS:                 a dictionary with the list of counts
    global PMBCountList  

    regNV = dict()
    regNNAV = dict()
        
    try:
        for e in PMBCountList:        
            if not e[0] in regNV.keys():
                regNV[e[0]] = int(e[1])
                regNNAV[e[0]] = int(e[2])
            else:
                regNV[e[0]] = regNV[e[0]] + int(e[1])
                regNNAV[e[0]] = regNNAV[e[0]] + int(e[2])
                        
        for k in sorted(regNV):                
            PMBCountResults[k] = "Violations: " + str(regNV[k]) + ", Not Allowed Objects Violations: " + str(regNNAV[k])   
        
    except Exception as err:
        logging.error("SCS Global : Error: %s", str(err))

# ..............................................................................
# ..............................................................................

def scan_file_CWE_120_122(application, pfile, fileType):
    #   Author :                     PMB
    #   last modification date:      28/3/2017
    #   Description: CWE_120_122:    Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') 
    #   Languages :                  C/C++
    #   Property :                   CWEforFDA_CustomMetrics_C_CPP.CWE120violationCPP - CatID=2002000 PropID=2002001 SubID=2002251 QRID=2002552
    #                                CWEforFDA_CustomMetrics_C_CPP.CWE122violationCPP - CatID=2002000 PropID=2002002 SubID=2002252 QRID=2002554
    #                                CWEforFDA_CustomMetrics_CSharp.CWE120violationCSharp - CatID=2003000 PropID=2003001 SubID=2003251 QRID=2003552
    #                                CWEforFDA_CustomMetrics_CSharp.CWE122violationCSharp - CatID=2003000 PropID=2003002 SubID=2003252 QRID=2003554
    #   NOTE:                        The program copies an input buffer to an output buffer without verifying that the size of the input buffer
    #                                is less than the size of the output buffer, leading to a buffer overflow.
    #    
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-120-122 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-120-122 : Starting scan_file_CWE_120_122        > " + str(pfile.name))

    #  search memcpy and strcpy
    pathMem = "(^[ \t]+memcpy[ \([a-zA-Z0-9_\s\[\]\-\(\)]+)([ \,]+)([a-zA-Z0-9_]*)([ a-zA-Z0-9\[\]\)\;]+)"
    pathStr = "(^[ \t]+strcpy[ \([a-zA-Z0-9_\s\[\]\-\(\)]+)([ \,]+)([a-zA-Z0-9_]*)([ a-zA-Z0-9\[\]\)\;]+)"
    pathIf = "(if[ ]*)([\(]+)([a-zA-Z0-9_]+)([\s\=\>\<\!\s]+)"

    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    
    try:
        with open_source_file(pfile.get_path()) as f:
            #current line number
            current_line = 0
            VarIf = None
            
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
                
                #SCS
                nBytes = nBytes + len(line)

                # Get the most specific object containing the line
                obj = pfile.find_most_specific_object(current_line, 1)

                # check variable on if
                result = re.finditer(pathIf, line)
                if not result is None:
                    for p in result:
                        #logging.debug("Found If Stmt > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        VarIf = p.group(3)

                # check memcpy variable
                result = re.finditer(pathMem, line)
                if not result is None:
                    for p in result:
                        #logging.debug("Found memcpy Stmt > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        VarMem = p.group(3)
                        if VarMem != VarIf:
                            #logging.debug("CWE_120_122: saving violation  > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                            bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                            if fileType == "CCPP":
                                try:
                                    obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE120violationCPP',bk)
                                    obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE122violationCPP',bk)
                                except:
                                    local_library.cwefdaLoggerWarning("CWE-120-122 : Violation not allowed on this object, next version")
                                    nbNAViolation = nbNAViolation + 1
                                else:
                                    nbViolation += 1  




                # check strcpy variable
                result = re.finditer(pathStr, line)
                if not result is None:
                    for p in result:
                        #logging.debug("Found strcpy Stmt > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        VarStr = p.group(3)
                        if VarStr != VarIf:
                            #logging.debug("CWE_120_122: saving violation  > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                            bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                            if fileType == "CCPP":
                                try:
                                    obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE120violationCPP',bk)
                                    obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE122violationCPP',bk) 
                                except:
                                    local_library.cwefdaLoggerWarning("CWE-120-122 : Violation not allowed on this object, next version")
                                    nbNAViolation = nbNAViolation + 1
                                else:
                                    nbViolation += 1  
                                      
                            if fileType == "CSHARP":
                                try:
                                    obj.save_violation('CWEforFDA_CustomMetrics_CSharp.CWE120violationCSharp',bk)
                                    obj.save_violation('CWEforFDA_CustomMetrics_CSharp.CWE122violationCSharp',bk)
                                except:
                                    local_library.cwefdaLoggerWarning("CWE-120-122 : Violation not allowed on this object, next version")
                                    nbNAViolation = nbNAViolation + 1
                                else:
                                    nbViolation += 1
                                    

    except FileNotFoundError:
        logging.error("CWE-120-122 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-120-122 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-120-122 : END scan_file_CWE_120_122 %s - Found %s violation ", str(pfile.name), str(nbViolation))                 
    
    tc = "CWE-120-122",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-120-122",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def scan_file_CWE_362(application, pfile, fileType):
#   Author :                 PMB
#   last modification date:  23/3/2017
#   Description: CWE_362:    Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') 
#   Languages :              C/C++
#   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE362violationCPP - CatID=2002000 PropID=2002005 SubID=2002255 QRID=2002588
#   NOTE:                    The program uses an expression in which operator precedence causes incorrect logic to be used.
#    
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-362 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-362 : Starting scan_file_CWE_362        > " + str(pfile.name))

    #  search "pthread_mutex_lock"
    pathSrc="^[ \t]+pthread_mutex_lock"

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
                
                #SCS
                nBytes = nBytes + len(line)
                
                # Get the most specific object containing the line
                obj = pfile.find_most_specific_object(current_line, 1)
                result = re.finditer(pathSrc, line)
                
                if not result is None:
                    for p in result:
                        #logging.debug("Found Stmt > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        # Set a bookmark for violation and save violation
                        bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                        #logging.debug("CWE_362: saving violation for CCPP > %s at line %s, col. %s", p.group(), current_line, p.start()+1)                        
                        try:
                            obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE362violationCPP',bk)                                
                        except:
                            local_library.cwefdaLoggerWarning("CWE-362 : Violation not allowed on this object, next version")
                            nbNAViolation = nbNAViolation + 1
                        else:
                            nbViolation += 1
                            
    except FileNotFoundError:
        logging.error("CWE-362 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-362 : Error: %s", str(e)) 
           
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-362 : END scan_file_CWE_362 %s - Found %s violation ", str(pfile.name), str(nbViolation))                
    
    tc = "CWE-362",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-362",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def scan_file_CWE_480_481(application, pfile, fileType):
#   Author :                 PMB
#   Last modification date:  10/4/2017
#   Description: CWE-481:    Assigning instead of Comparing 
#   Languages:               C/C++ C#
#   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE480violationCPP - CatID=2002000 PropID=2002010 SubID=2002260 QRID=2002570
#                            CWEforFDA_CustomMetrics_C_CPP.CWE481violationCPP - CatID=2002000 PropID=2002011 SubID=2002261 QRID=2002571
#                            CWEforFDA_CustomMetrics_C_CPP.CWE480violationCSharp - CatID=2003000 PropID=2003010 SubID=2003260 QRID=2003570
#                            CWEforFDA_CustomMetrics_C_CPP.CWE480violationCSharp - CatID=2003000 PropID=2003011 SubID=2003261 QRID=2003571
#   NOTE:                    The programmer accidentally uses the wrong operator, which changes the application logic in security-relevant ways.
#  
    nbProgramCall = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    nbViolation=0
    nbNAViolation = 0
    allIntVars = set()
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-480-481 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-480-481 : Starting scan_file_CWE_480_481 > " +str(pfile.name))

    
    PathIntB = "([\(]+)int ([a-zA-Z0-9_\.]+)"
    PathIntF = "([ \t]+)int ([a-zA-Z0-9_\.]+)"
    PathIf = "[ \t]+if([ \(]+)([a-zA-Z0-9_]+)"
    PathBitWise = "[ \t]+if([ \(]+)([a-zA-Z0-9_\!\(\)]+)( & | \| )+([a-zA-Z0-9_\!\(\)]+)"
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
                
                #SCS
                nBytes = nBytes + len(line)
            
                obj = pfile.find_most_specific_object(current_line, 1)
                #logging.debug("Statement to analize >> %s >> %s", current_line, line)

                resultIntB = re.finditer(PathIntB, line)            
                if not resultIntB is None:
                    for c in resultIntB:
                        #logging.debug("CWE_480_481 : Group StmtIntB > %s ", c.group(2))
                        varIntB=c.group(2)
                        allIntVars.add(varIntB)
                    
                resultIntF = re.finditer(PathIntF, line)
                if not resultIntF is None:
                    for c in resultIntF:
                        #logging.debug("CWE_480_481 : Group StmtIntF > %s ", c.group(2))
                        varIntF=c.group(2)
                        allIntVars.add(varIntF)

                resultBitWise = re.finditer(PathBitWise, line)
                if not resultBitWise is None:
                    for c in resultBitWise:
                        if  fileType == "CCPP":
                            # Set a bookmark for violation and save violation
                            bk = Bookmark(pfile,current_line,c.start()+1,current_line,c.end())
                            #logging.debug("sono in test cpp >> %s", bk)
                            
                            try:
                                obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE480violationCPP',bk)                               
                            except:
                                local_library.cwefdaLoggerWarning("CWE-480-481 : Violation not allowed on this object, next version")
                                nbNAViolation = nbNAViolation + 1
                            else:
                                nbViolation +=1
                                nbProgramCall += 1
                           
                            continue

                        if fileType == "CSHARP":
                            # Set a bookmark for violation and save violation
                            bk = Bookmark(pfile,current_line,c.start()+1,current_line,c.end())
                            #logging.debug("sono in test csharp >> %s", bk)
                            
                            try:
                                obj.save_violation('CWEforFDA_CustomMetrics_CSharp.CWE480violationCSharp',bk)                            
                            except:
                                local_library.cwefdaLoggerWarning("CWE-480-481 : Violation not allowed on this object, next version")
                                nbNAViolation = nbNAViolation + 1
                            else:
                                nbViolation +=1
                                nbProgramCall += 1

                            continue
                        
                resultPathIf = re.finditer(PathIf, line)
                if not resultPathIf is None:
                    resultPathIf = re.finditer(PathIf, line)       
                    for p in resultPathIf:
                        varIf=p.group(2)
                        for v in allIntVars:
                            if v==varIf:
                                CheckNoEq=line[line.find("!"):line.find("=")+2]
                                CheckLtEq=line[line.find("<"):line.find("=")+2]
                                CheckGtEq=line[line.find(">"):line.find("=")+2]
                                if CheckNoEq or CheckLtEq or CheckGtEq:
                                    continue
                                CheckEqEq=line[line.find("="):line.find("=")+2]
                                if not CheckEqEq:
                                    continue
                                if CheckEqEq != "==":
                                    if  fileType == "CCPP":
                                        bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                        
                                        try:
                                            obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE481violationCPP',bk)                            
                                        except:
                                            local_library.cwefdaLoggerWarning("CWE-480-481 : Violation not allowed on this object, next version")
                                            nbNAViolation = nbNAViolation + 1
                                        else:
                                            nbViolation +=1
                                            nbProgramCall += 1

                                    if  fileType == "CSHARP":
                                        bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                        
                                        try:
                                            obj.save_violation('CWEforFDA_CustomMetrics_CSharp.CWE481violationCSharp',bk)                            
                                        except:
                                            local_library.cwefdaLoggerWarning("CWE-480-481 : Violation not allowed on this object, next version")
                                            nbNAViolation = nbNAViolation + 1
                                        else:
                                            nbViolation +=1
                                            nbProgramCall += 1


    except FileNotFoundError:
        logging.error("CWE-480-481 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-480-481 : Error: %s", str(e)) 

    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-480-481 : END scan_file_CWE_480_481 %s - Found %s violation ", str(pfile.name), str(nbViolation)) 
    
    tc = "CWE-480-481",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-480-481",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def scan_file_CWE_482(application, pfile, fileType):
    #   Author :                 PMB
    #   last modification date:  27/3/2017
    #   Description: CWE_482:    Comparing instead of Assigning 
    #   Languages :              C/C++
    #   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE482violationCPP - CatID=2002000 PropID=2002012 SubID=2002262 QRID=2002574
    #   NOTE:                    The code uses an operator for comparison when the intention was to perform an assignment.
    #                            In many languages, the compare statement is very close in appearance to the assignment statement; they are often confused.
    #    
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-482 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-482 : Starting scan_file_CWE_482        > " + str(pfile.name))

    #  search 
    #pathSrc="(^[ \ta-zA-Z0-9_\s\*]+)(==)([a-zA-Z0-9\s]+)"
    pathSrc="[^\s\t]*(\**[a-zA-Z0-9_]+(\s*\[\s*[a-zA-Z0-9_]*\s*\]\s*)?)\s*==\s*([a-zA-Z0-9\s]+)\s*(\,|\;|\.)"

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
                
                #SCS
                nBytes = nBytes + len(line)
                
                # Get the most specific object containing the line
                obj = pfile.find_most_specific_object(current_line, 1)
                result = re.finditer(pathSrc, line)
                
                if not result is None:
                    for p in result:
                        #logging.debug("Found Stmt > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        # Set a bookmark for violation and save violation
                        bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                        #logging.debug("CWE-482 : Detected violation > %s at line %s, col. %s", p.group(), current_line, p.start()+1)

                        try:
                            obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE482violationCPP',bk)                                
                        except:
                            local_library.cwefdaLoggerWarning("CWE-482 : Violation not allowed on this object, next version")
                            nbNAViolation = nbNAViolation + 1
                        else:
                            nbViolation +=1
                            
    except FileNotFoundError:
        logging.error("CWE-482 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-482 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-482 : END scan_file_CWE_482 %s - Found %s violation ", str(pfile.name), str(nbViolation))   
    
    tc = "CWE-482",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-482",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def scan_file_CWE_783(application, pfile, fileType):
#   Author :                 PMB
#   last modification date:  23/3/2017
#   Description: CWE_783:    Operator Precedence Logic Error 
#   Languages :              C/C++
#   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE783violationCPP - CatID=2002000 PropID=2002019 SubID=2002269 QRID=2002588
#   NOTE:                    The program uses an expression in which operator precedence causes incorrect logic to be used.
#    
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-783 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-783 : Starting scan_file_CWE_783        > " + str(pfile.name))

    #  search "AuthenticateUser"
    pathSrc="(if[ ]*)([\(]+)([a-zA-Z0-9_\s\=\s]+)(AuthenticateUser)"

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
                
                #SCS
                nBytes = nBytes + len(line)
                
                # Get the most specific object containing the line
                obj = pfile.find_most_specific_object(current_line, 1)
                result = re.finditer(pathSrc, line)
                
                if not result is None:
                    for p in result:
                        #logging.debug("Found Stmt > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        if p.group(2) == "(":
                            # Set a bookmark for violation and save violation
                            bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                            #logging.debug("CWE_783: saving violation for CCPP > %s at line %s, col. %s", p.group(), current_line, p.start()+1)

                            try:
                                obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE783violationCPP',bk)                                
                            except:
                                local_library.cwefdaLoggerWarning("CWE-783 : Violation not allowed on this object, next version")
                                nbNAViolation = nbNAViolation + 1
                            else:
                                nbViolation +=1
                            
    except FileNotFoundError:
        logging.error("CWE-783 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-783 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-783 : END scan_file_CWE_783 %s - Found %s violation ", str(pfile.name), str(nbViolation))   
    
    tc = "CWE-783",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-783",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def scan_file_CWE_910(application, pfile, fileType):
    #   Author :                 PMB
    #   last modification date:  27/3/2017
    #   Description: CWE_910:    Use of Expired File Descriptor 
    #   Languages :              C/C++
    #   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE910violationCPP - CatID=2002000 PropID=2002020 SubID=2002270 QRID=2002590
    #   NOTE:                    The software uses or accesses a file descriptor after it has been closed. After a file descriptor for a particular 
    #                            file or device has been released, it can be reused. The code might not write to the original file, since the reused
    #                            file descriptor might reference a different file or device.The code uses an operator for comparison when the intention
    #                            was to perform an assignment.
    #                            In many languages, the compare statement is very close in appearance to the assignment statement; they are often confused.
    #    
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    pathMsg= "Niente"
    allFree = set()
    flagFree = False
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("CWE-910 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("CWE-910 : Starting scan_file_CWE_910        > " + str(pfile.name))

    #  search string "free" 
    pathSrc="(^[ \t]+)(free)([(\ \(]+)([a-zA-Z0-9_]+)([(\ \)\;]+)"
    # All pattern included in double quotes (strings)
    patResource  = "(^(.)*)("+pathMsg+")(.*$)"

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
                
                #SCS
                nBytes = nBytes + len(line)
                
                # Get the most specific object containing the line
                obj = pfile.find_most_specific_object(current_line, 1)

                # Search variable if found free before
                if flagFree:
                    for f in allFree:
                        pathMsg = f
                        #pathMsg = "messageBody"
                        #patResource  = "(^(.)*)("+pathMsg+")(.*$)"
                        patResource  = "([\t\s\*]*)("+pathMsg+")([\s\t\)\,\;\-\+\*])"
                        #result = re.finditer("(^(.)*)("+pathMsg+")(.*$)", line)
                        result = re.finditer(patResource, line)
                        if not result is None:
                            for p in result:
                                #logging.debug("Found Stmt > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                                # Set a bookmark for violation and save violation
                                bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
                                #logging.debug("CWE_910: saving violation for CCPP > %s at line %s, col. %s", p.group(), current_line, p.start()+1)

                                try:
                                    obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.CWE910violationCPP',bk)                                
                                except:
                                    local_library.cwefdaLoggerWarning("CWE-910 : Violation not allowed on this object, next version")
                                    nbNAViolation = nbNAViolation + 1
                                else:
                                    nbViolation += 1


                #   Search free stmt
                result = re.finditer(pathSrc, line)
                if not result is None:
                    for p in result:
                        #logging.debug("Found Stmt Free > %s at line %s, col. %s", p.group(), current_line, p.start()+1)
                        allFree.add(p.group(4))
                        flagFree = True


    except FileNotFoundError:
        logging.error("CWE-910 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("CWE-910 : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("CWE-910 : END scan_file_CWE_910 %s - Found %s violation ", str(pfile.name), str(nbViolation))      
    
    tc = "CWE-910",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "CWE-910",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def scan_file_OMG_MNT_3(application, pfile, fileType):
#   Author :                          PMB
#   last modification date:           10/4/2017
#   Description: OMG MNT-3:           OMG MNT-3: Storable and Member Data Element Initialization with Hard-Coded Literals, Float Type Storable and Member Data Element Comparison with Equality Operator 
#   Languages :                       C/C++/C#
#   Property :                        CWEforFDA_CustomMetrics_C_CPP.OMGRLB9violationCPP       - CatID=2002000 PropID=2002021 SubID=2002271 QRID=2002592
#                                     CWEforFDA_CustomMetrics_CSharp.OMGRLB9violationCSharp   - CatID=2003000 PropID=2003021 SubID=2003271 QRID=2003592
#   NOTE
# 
    nbViolation=0
    nbNAViolation = 0
    nbProgramCall=0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0        

    local_library.cwefdaLoggerInfo("OMG-MNT-3 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("OMG-MNT-3 : Starting scan_file_OMG_MNT_3 > " + str(pfile.name))
    
    patFloatDefinition = "((const)|(char)|(float)|(double)|(long double))([ \t\r\n]+)([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"
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
                
                #SCS
                nBytes = nBytes + len(line)
            
                obj = pfile.find_most_specific_object(current_line, 1)
                #logging.debug("Statement to analyze >> %s", current_line)

                resultFloat = re.finditer(patFloatDefinition, line)
                if not resultFloat is None:
                    for p in resultFloat:
                        if p.group(1) != "const":        
                            #newPat=re.compile('([ \t\r\n]+)([A-Za-z0-9_\-\(\)\. \t\r\n]+)([\= ]+)([\d]+)([ \;]+)')                   #bpm 
                            if p.group(1) == "char":                                             
                                newPat=re.compile('([ \t\r\n]+)([A-Za-z0-9_\-\(\)\. \t\r\n]+)([\= ]+)([.\d]+)([ \;]+)') 
                                resultNewPat = re.finditer(newPat, line) 
                            else:                                                     
                                newPat=re.compile('([ \t\r\n]+)([A-Za-z0-9_\-\(\)\. \t\r\n]+)([\= ]+)([\d]+)([ \;]+)') 
                                resultNewPat = re.finditer(newPat, line) 
                            for pp in resultNewPat: 
                                if  fileType =="CCPP":
                                    bk = Bookmark(pfile,current_line,pp.start()+1,current_line,pp.end())
                                    
                                    try:
                                        obj.save_violation('CWEforFDA_CustomMetrics_C_CPP.OMGMNT3violationCPP',bk)
                                    except:
                                        local_library.cwefdaLoggerWarning("OMG-MNT-3 : Violation not allowed on this object, next version")
                                        nbNAViolation = nbNAViolation + 1
                                    else:
                                        nbViolation += 1
                                        nbProgramCall += 1

                                if  fileType =="CSHARP":
                                    bk = Bookmark(pfile,current_line,pp.start()+1,current_line,pp.end())
                                    
                                    try:
                                        obj.save_violation('CWEforFDA_CustomMetrics_CSharp.OMGMNT3violationCSharp',bk)
                                    except:
                                        local_library.cwefdaLoggerWarning("OMG-MNT-3 : Violation not allowed on this object, next version")
                                        nbNAViolation = nbNAViolation + 1
                                    else:
                                        nbViolation += 1
                                        nbProgramCall += 1

    except FileNotFoundError:
        logging.error("OMG-MNT-3 : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("OMG-MNT-3 : Error: %s", str(e)) 

    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    local_library.cwefdaLoggerInfo("OMG-MNT-3 : END scan_file_OMG_MNT_3 %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "OMG-MNT-3",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "OMG-MNT-3",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)
    