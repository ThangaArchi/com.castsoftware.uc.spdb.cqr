# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------
# Code scanning for CWE

import cast_upgrade_1_5_11  # @UnusedImport
from cast.application import open_source_file
from cast.application import ApplicationLevelExtension, ReferenceFinder, Bookmark, Object
import logging
import re
import linecache

import local_library

# Counting register
SCSCountList = list()
SCSCountResults = dict()

# ..............................................................................
# ..............................................................................


def update_counts(t):
#   Description:             Log the tuple t on an extra internal counter register    
    global SCSCountList
    
    try:
        if not(t[1] == 0 and t[2] == 0):        
            SCSCountList.append(t)  
    except Exception as err:
        logging.error("local_library : Error: %s", str(err))

               
def count_results():
#   Description:             Produces a string with counting results
#   RETURNS:                 a dictionary with the list of counts
    global SCSCountList  

    regNV = dict()
    regNNAV = dict()
        
    try:
        for e in SCSCountList:        
            if not e[0] in regNV.keys():
                regNV[e[0]] = int(e[1])
                regNNAV[e[0]] = int(e[2])
            else:
                regNV[e[0]] = regNV[e[0]] + int(e[1])
                regNNAV[e[0]] = regNNAV[e[0]] + int(e[2])
                        
        for k in sorted(regNV):                
            SCSCountResults[k] = "Violations: " + str(regNV[k]) + ", Not Allowed Objects Violations: " + str(regNNAV[k])   
        
    except Exception as err:
        logging.error("SCS Global : Error: %s", str(err))

# ..............................................................................
# ..............................................................................


def scan_file_SPDBviolation9_1_3(application, pfile, fileType):
#   Description: CWE-252 :   Unchecked Return Value 
#   Languages :              C/C++/C#
#   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE252violationCPP  - CatID=2002000 PropID=2002004 SubID=2002254 QRID=2002558
#                            CWEforFDA_CustomMetrics_CSharp.CWE252violationCPP - CatID=2003000 PropID=2003004 SubID=2003254 QRID=2003558
#   Scope & Property :       Scope by fn 100010 (n. of function calls)
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    
    msecs = local_library.millis()
    nBytes = 0
    logging.debug("pfile.name----" + str(pfile.name))
    local_library.cwefdaLoggerInfo("SPDBviolation9_1_3 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("SPDBviolation9_1_3 : Starting scan_file_SPDBviolation9_1_3 > " + str(pfile.name))
    
    patFunCall = "(float|int|char|bool)[ \t\r\n]+([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"
#    patFunCall = "((?:int\s*|float\s*|char\s*|bool\s*)+)(?:\s+\*?\*?\s*)(\s*[^,\s][^\,]*[^,\s]*)\s*[;,*=)]"
#    patFunCall = "((?:int\s*|float\s*|char\s*|bool\s*)+)(?:\s+\*?\*?\s*)(\s*[a-z]*[A-Z]*[0-9]*)\s*\s*[;,=)]"
#    patFunCall = "\b(?:(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)+)(?:\s+\*?\*?\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*[\[;,=)]"
    
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
                                     
    try:
        isInSingleLineComment = False
        isInMultiLineComment = False
        with open_source_file(pfile.get_path()) as f:
            # current line number
            current_line = 0
            
            for line in f:                  
                # Line of code
#                logging.error("Current line %s", line) 

                current_line += 1
                
                try:               
                    resultCom = re.finditer(patComment, line)
                    # logging.debug("resultCom value---" + str(line))
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
                                        
                    # Get function call patterns
                    result = re.finditer(patFunCall, line)
                    
#                    logging.info("Result is: >%s<", result) 
                    if (not result is None):                                          
                        for p in result:   
                            logging.debug("result value---" + str(p))
#                            logging.info("scan_file_SPDBviolation9_1_3::Result is: [%s]  [%s]  [%s]  [%s] ", pfile, line, p.group(2), p.group(7)) 
                            
                            checkMultipleVars = p.group(2).split(",")
                            for getVar in checkMultipleVars:
                                logging.debug("getVar value---" + str(getVar))
 #                               logging.info("\n@@@@ "+getVar)
                                
                                if getVar.__contains__('='):
                                    logging.info("SPDBviolation9_1_3 :: [PASSED] Value is initialized for " + getVar)
                                else:                              
                                    logging.debug("Violation saved for getVar value---" + str(getVar))  
                                    bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                    pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation9_1_3', bk)
                                    # Set a bookmark for violation
#                                   obj = pfile
#                                     obj = pfile.find_most_specific_object(current_line, 1)
#                                     bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
#                                     try:
#                                         logging.error("SPDBviolation9_1_3 :: [VIOLATION] Value is NOT initialized for " + getVar)
#                                         obj.save_violation('SPDB_CustomMetrics_C.SPDBviolation9_1_3', bk)
#                                     except Exception as e:
#                                         logging.error("SPDBviolation9_1_3: Violation not allowed on this object, next version %s", str(e.message()))
#                                         nbNAViolation = nbNAViolation + 1
#                                     else:
#                                         nbViolation += 1
#                                                                 
                except Exception as e:
                    logging.error("SPDBviolation9_1_3 : Error: %s, at line ", str(e), current_line)
                                                                    
    except FileNotFoundError:
        logging.error("SPDBviolation9_1_3 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("SPDBviolation9_1_3 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    local_library.cwefdaLoggerInfo("SPDBviolation9_1_3 : END scan_file_CWE_252 %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation9_1_3", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation9_1_3", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------


def scan_file_SPDBviolation14_1_3(application, pfile, fileType):
#   Description: CWE-252 :   Unchecked Return Value 
#   Languages :              C/C++/C#
#   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE252violationCPP  - CatID=2002000 PropID=2002004 SubID=2002254 QRID=2002558
#                            CWEforFDA_CustomMetrics_CSharp.CWE252violationCPP - CatID=2003000 PropID=2003004 SubID=2003254 QRID=2003558
#   Scope & Property :       Scope by fn 100010 (n. of function calls)
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("scan_file_SPDBviolation14_1_3 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("scan_file_SPDBviolation14_1_3 : Starting scan_file_CWE_14_1_3 > " + str(pfile.name))
    
    patFunCall = "(float|int|char|bool|float\*|int\*|char\*|bool\*)[ \t\r\n]+([a-zA-Z0-9_]*)(\[([^\[\]]+)\]|\[[]])"
#    patFunCall = "\b(?:(?:int\s*|float\s*|char\s*|bool)+)(?:\s+\*?\*?\s*)([a-zA-Z0-9_]*)\s*(\[.*?\])"
#    patFunCall = "((?:int\s*|float\s*|char\s*|bool\s*)+)(?:\s+\*?\*?\s*)(\s*[^,\s][^\,]*[^,\s]*)\s*[;,*=)]"
#    patFunCall = "((?:int\s*|float\s*|char\s*|bool\s*)+)(?:\s+\*?\*?\s*)(\s*[a-z]*[A-Z]*[0-9]*)\s*\s*[;,=)]"
#    patFunCall = "\b(?:(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)+)(?:\s+\*?\*?\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*[\[;,=)]"
    
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
                                     
    try:
        isInSingleLineComment = False
        isInMultiLineComment = False
        with open_source_file(pfile.get_path()) as f:
            # current line number
            current_line = 0
            
            for line in f:                  
                # Line of code
#                logging.error("Current line %s", line) 

                current_line += 1
                
                try:               
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
                                        
                    # Get function call patterns
                    result = re.finditer(patFunCall, line)
                    
                    if (not result is None):                                          
                        for p in result:   
                            logging.info("scan_file_SPDBviolation14_1_3::Result is: %s  %s  %s ", pfile, line, p.group(1))
                            # , p.group(7)) 
                            
                            getArraySize = 0;
                            if  p.group(3) != "[]":
                                getArraySize = p.group(4)
                                logging.info("Value of %s is = %s", p.group(0), getArraySize)
                            else:
                                logging.info("Value of %s is = %s", p.group(0), line)
                                if line.__contains__(','):
                                    getArrVales = re.finditer("{([^}]+)\}|\"([^}]+)\"", line)
                                    logging("$$$$$$$$$$$: %s", getArrVales)
                                    if (not getArrVales is None):
                                        for arrVal in getArrVales:  
                                            logging("############%s", arrVal)
                                            getArraySize = len(arrVal.split(","))
                                            logging("@@@@@@@@@@@@%s", arrVal)
                                    logging.info("Value of %s is = %s", p.group(0), getArraySize)
                                else:
                                    getArrVales = 0
                        #------------------------------------------------- else:
                            #--------------- logging.error("NO match for array")
                except Exception as e:
                    logging.error("scan_file_SPDBviolation14_1_3 : Error: %s, at line ", str(e), current_line)
                                                                    
    except FileNotFoundError:
        logging.error("scan_file_SPDBviolation14_1_3 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("scan_file_SPDBviolation14_1_3 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    local_library.cwefdaLoggerInfo("scan_file_SPDBviolation14_1_3 : END scan_file_CWE_252 %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "scan_file_SPDBviolation14_1_3", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "scan_file_SPDBviolation14_1_3", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------


def scan_file_SPDBviolation12_2_5(application, pfile, fileType):
# Avoid return Pointer, because memory exists and is destroyed automatically at the end of the function body
    
#   Description: CWE-252 :   Unchecked Return Value 
#   Languages :              C/C++/C#
#   Property :               CWEforFDA_CustomMetrics_C_CPP.CWE252violationCPP  - CatID=2002000 PropID=2002004 SubID=2002254 QRID=2002558
#                            CWEforFDA_CustomMetrics_CSharp.CWE252violationCPP - CatID=2003000 PropID=2003004 SubID=2003254 QRID=2003558
#   Scope & Property :       Scope by fn 100010 (n. of function calls)
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("scan_file_SPDBviolation12_2_5 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("scan_file_SPDBviolation12_2_5 : Starting > " + str(pfile.name))
    
    patFunCall = "(float|int|char|bool)\s*\*\s*([\w]*)(\(.*)(?=)"
#    patFunCall = "\b(?:(?:int\s*|float\s*|char\s*|bool)+)(?:\s+\*?\*?\s*)([a-zA-Z0-9_]*)\s*(\[.*?\])"
#    patFunCall = "((?:int\s*|float\s*|char\s*|bool\s*)+)(?:\s+\*?\*?\s*)(\s*[^,\s][^\,]*[^,\s]*)\s*[;,*=)]"
#    patFunCall = "((?:int\s*|float\s*|char\s*|bool\s*)+)(?:\s+\*?\*?\s*)(\s*[a-z]*[A-Z]*[0-9]*)\s*\s*[;,=)]"
#    patFunCall = "\b(?:(?:auto\s*|const\s*|unsigned\s*|signed\s*|register\s*|volatile\s*|static\s*|void\s*|short\s*|long\s*|char\s*|int\s*|float\s*|double\s*|_Bool\s*|complex\s*)+)(?:\s+\*?\*?\s*)([a-zA-Z_][a-zA-Z0-9_]*)\s*[\[;,=)]"
    
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
                                     
    try:
        isInSingleLineComment = False
        isInMultiLineComment = False
        with open_source_file(pfile.get_path()) as f:
            if (pfile.get_path().endswith('libtypeb.c') or 
            pfile.get_path().endswith('win.c') or
            pfile.get_path().endswith('win32s.c') or
            pfile.get_path().endswith('servdll.c')) :
                logging.error("Check this break point======>")
                
            # current line number
            current_line = 0
            
            for line in f:                  
                # Line of code
#                logging.error("Current line %s", line) 

                current_line += 1
                
                try:               
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
                                        
                    # Get function call patterns
                    result = re.finditer(patFunCall, line)
                    
                    if (not result is None):                                          
                        for p in result:   
                            logging.info("scan_file_SPDBviolation12_2_5::Result is: %s  %s", pfile, line)
                            try:
                                bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation12_2_5', bk)
                                logging.info("scan_file_SPDBviolation12_2_5 :: [VIOLATION] Avoid return Pointer, because memory exists and is destroyed automatically at the end of the function body <===> " + line)
                            except Exception as e:
                                logging.error("scan_file_SPDBviolation12_2_5 : Error: %s, at line (not allowed on this object) %s", str(e), e.message())
                                nbNAViolation = nbNAViolation + 1
                            
                except Exception as e:
                    logging.error("scan_file_SPDBviolation12_2_5 : Error: %s, at line ", str(e), current_line)
                                                                    
    except FileNotFoundError:
        logging.error("scan_file_SPDBviolation12_2_5 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("scan_file_SPDBviolation12_2_5 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    local_library.cwefdaLoggerInfo("scan_file_SPDBviolation12_2_5 : END scan_file_CWE_252 %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "scan_file_SPDBviolation12_2_5", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "scan_file_SPDBviolation12_2_5", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------


def scan_file_SPDBviolation14_1_1(application, pfile, fileType):
#   Description: SPDBviolation14_1_1: Memory allocation with malloc should be checked with NULL 

    skipFirstPattern = 0
    skipSecontPattern = 0
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    # SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("14_1_1 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("14_1_1 : Starting scan_file_SPDBviolation14_1_1        > " + str(pfile.name))

    #  search "pthread_mutex_lock"
    pathSrc = "([a-zA-Z0-9_\.]*)\s*=\s*(\(\s*[a-zA-Z0-9_\.]+\s*\**\s*\))?\s*malloc\s*\("

    patNullCheck = "if\s*\((.*)(?=\))"

    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    
    try:
        with open_source_file(pfile.get_path()) as f:
            # current line number
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
                
                # SCS
                nBytes = nBytes + len(line)
                
                if skipFirstPattern == 0:
                    # Get the most specific object containing the line
                    result = re.finditer(pathSrc, line)
                    
                    if not result is None:
                        for p in result:
                            logging.error("MALLOC %s, %s", p.group(1), line)
                            nxtLine = 0;
#                            nextLine = lines[0]+" "+lines[1]
#                            nullRes = re.finditer(patNullCheck, nextLine)
                                                  
                            module_line = linecache.getline(pfile.get_path(), current_line + 1)
                            logging.error("Attempt to process %s", module_line)
                            if module_line.__eq__("\n"):
                                module_line = linecache.getline(pfile.get_path(), current_line + 2)
                                logging.error("Attempt to process %s", module_line)
                                isValidatedWithIF(module_line, pfile, current_line, p)
                            else:
                                isValidatedWithIF(module_line, pfile, current_line, p)
                                       
    except FileNotFoundError:
        logging.error("SPDBviolation14_1_1 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("SPDBviolation14_1_1 : Error: %s", str(e)) 
           
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    logging.error("SPDBviolation14_1_1 : END scan_file_SPDBviolation14_1_1 %s - Found %s violation ", str(pfile.name), str(nbViolation))                
    
    tc = "SPDBviolation14_1_1", nbViolation, nbNAViolation
    update_counts(tc)
    
    # Extra log
    t = "SPDBviolation14_1_1", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def isValidatedWithIF(line, pfile, current_line, p):
    patNullCheck = "if\s*\((.*)(?=\))"
    logging.error("%s", line)
    nullRes2 = re.findall(patNullCheck, line)
    logging.error("IF condition present")
    
    if nullRes2:
        memCheck = re.findall( "(NULL)", line )
        logging.error("Search String %s", line)
        if memCheck :
#        if p.group(1).find("NULL") != -1:
            logging.error("2.1. NO-VIOLATION MALLOC is validated with NULL - lines[1] %s", line)
        else:
            bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
            pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_1', bk)
            logging.error("SPDBviolation14_1_1 :: VIOLATION: MALLOC is NOT validated with NULL - %s", line )
    else:
        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_1', bk)
        logging.error("SPDBviolation14_1_1 :: VIOLATION: MALLOC is NOT validated with NULL - %s", line )
        
# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def markFreed(pfile, current_line, p, module_line):
    open1 = "("
    close1 = ")"
    patNullify = "\s*=\s*NULL\s*;"
#    module_line = linecache.getline(pfile.get_path(), current_line + 2)
    patNullifyConstruct = open1 + p.group(1) + close1 + patNullify
    resNullify = re.findall(patNullifyConstruct, module_line)
    logging.error("Pattern %s, String %s", patNullifyConstruct, module_line)
    
    if resNullify:
        logging.error("MEMORY is freed - True %s", module_line)
    else:
        logging.error("MEMORY is NOT freed - VIOLATION %s", module_line)
        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_5', bk)
    
        
# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def scan_file_SPDBviolation14_1_5(application, pfile, fileType):
#   Description: SPDBviolation14_1_5: Memory allocation with malloc should be checked with NULL 

    skipFirstPattern = 0
    skipSecontPattern = 0
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    # SCS
    msecs = local_library.millis()
    nBytes = 0
    
    local_library.cwefdaLoggerInfo("14_1_5 : -------------------------------------------------------------------------")
    local_library.cwefdaLoggerInfo("14_1_5 : Starting scan_file_SPDBviolation14_1_5        > " + str(pfile.name))

    #  search "pthread_mutex_lock"
    pathSrc = "[\t*|\s*]free\s*\((.*)(?=\))"

    open1 = "("
    close1 = ")"
    patNullify = "\s*=\s*NULL\s*;"

    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    
    try:
        with open_source_file(pfile.get_path()) as f:
            # current line number
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
                
                # SCS
                nBytes = nBytes + len(line)
                
                if skipFirstPattern == 0:
                    # Get the most specific object containing the line
                    result = re.finditer(pathSrc, line)
                    
                    if not result is None:
#                        print( lines )
#                        logging.error( lines )
                        for p in result:
#                            lines=f.readlines(current_line)
                            logging.error("Currently processing %s", line)
                            logging.error("Freed memory %s" , p.group(1))
                                                      
                            module_line = linecache.getline(pfile.get_path(), current_line + 1)
                            logging.error("%s", module_line)
                            if module_line.__eq__("\n"):
                                module_line = linecache.getline(pfile.get_path(), current_line + 2)
                                markFreed(pfile, current_line, p, module_line)

#                                patNullifyConstruct = open1 + p.group(1) + close1 + patNullify
#                                resNullify = re.findall(patNullifyConstruct, module_line)
#                                logging.error("Pattern %s, String %s", patNullifyConstruct, module_line)
#                                
#                                if resNullify:
#                                    print("MEMORY is freed - True %s", module_line)
#                                else:
#                                    print("MEMORY is NOT freed - VIOLATION %s", module_line)
#                                    bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
#                                    pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_5', bk)
                            else:
                                markFreed(pfile, current_line, p, module_line)

#                                patNullifyConstruct = open1 + p.group(1) + close1 + patNullify
#                                resNullify = re.findall(patNullifyConstruct, module_line)
#                                logging.error("Pattern %s, String %s", patNullifyConstruct, module_line)
#                                
#                                if resNullify:
#                                    print("MEMORY is freed - True %s", module_line)
#                                else:
#                                    print("MEMORY is NOT freed - VIOLATION %s", module_line)
#                                    bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
#                                    pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_5', bk)
                                
                        else:
                            nbViolation += 1
                            
    except FileNotFoundError:
        logging.error("SPDBviolation14_1_5 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("SPDBviolation14_1_5 : Error: %s", str(e)) 
           
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    logging.error("SPDBviolation14_1_5 : END scan_file_SPDBviolation14_1_5 %s - Found %s violation ", str(pfile.name), str(nbViolation))                
    
    tc = "SPDBviolation14_1_5", nbViolation, nbNAViolation
    update_counts(tc)
    
    # Extra log
    t = "SPDBviolation14_1_5", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
    
