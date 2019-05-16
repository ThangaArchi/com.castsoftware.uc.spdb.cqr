##############################################################################################
#---------------------------------------------------------------------------------------------
# Created on 
#
# Aauthor: Thangadurai Kandhasamy<t.kandhasamy@castsoftware.com> - TKA
#
# Description: 
#---------------------------------------------------------------------------------------------
##############################################################################################


import local_library
import logging
import re
from cast.application import open_source_file
from cast.application import ApplicationLevelExtension, ReferenceFinder, Bookmark, Object
import linecache
import scan_Utilities

# Counting register
SCSCountList = list()
SCSCountResults = dict()




def scan_file_SPDBviolation12_2_5(application, pfile, fileType):
# Avoid return Pointer, because memory exists and is destroyed automatically at the end of the function body
    
#   Description:  :   scan_file_SPDBviolation12_2_5
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    
    msecs = local_library.millis()
    nBytes = 0
    
    logging.info("scan_file_SPDBviolation12_2_5 : -------------------------------------------------------------------------")
    logging.info("scan_file_SPDBviolation12_2_5 : Starting > " + str(pfile.name))
    
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
            #-------------------- if (pfile.get_path().endswith('libtypeb.c') or
            #----------------------------- pfile.get_path().endswith('win.c') or
            #-------------------------- pfile.get_path().endswith('win32s.c') or
            #------------------------- pfile.get_path().endswith('servdll.c')) :
                #---------------- logging.error("Check this break point======>")
                
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
    logging.info("scan_file_SPDBviolation12_2_5 : END scan_file_ %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation12_2_5", nbViolation, nbNAViolation
#    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation12_2_5", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------



def scan_file_SPDBviolation14_1_1(application, pfile, fileType):
# ----------------------------------------------------------------------------------------
#   Description: SPDBviolation14_1_1: Memory allocation with malloc should be checked with NULL 
# ----------------------------------------------------------------------------------------

    skipFirstPattern = 0
    skipSecontPattern = 0
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    # SCS
    msecs = local_library.millis()
    nBytes = 0
    
    logging.info("scan_file_SPDBviolation14_1_1 : -------------------------------------------------------------------------")
    logging.info("scan_file_SPDBviolation14_1_1 : Starting scan_file_SPDBviolation14_1_1        > " + str(pfile.name))

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
                            logging.info("scan_file_SPDBviolation14_1_1 :: MALLOC %s, %s", p.group(1), line)
                            nxtLine = 0;
#                            nextLine = lines[0]+" "+lines[1]
#                            nullRes = re.finditer(patNullCheck, nextLine)
                                                  
                            module_line = linecache.getline(pfile.get_path(), current_line + 1)
                            logging.info("scan_file_SPDBviolation14_1_1 :: Attempt to process %s", module_line)
                            if module_line.__eq__("\n"):
                                module_line = linecache.getline(pfile.get_path(), current_line + 2)
                                logging.info("scan_file_SPDBviolation14_1_1 :: Attempt to process %s", module_line)
                                scan_Utilities.isValidatedWithIF(module_line, pfile, current_line, p)
                            else:
                                scan_Utilities.isValidatedWithIF(module_line, pfile, current_line, p)
                                       
    except FileNotFoundError:
        logging.error("SPDBviolation14_1_1 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("SPDBviolation14_1_1 : Error: %s", str(e)) 
           
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    logging.error("SPDBviolation14_1_1 : END scan_file_SPDBviolation14_1_1 %s - Found %s violation ", str(pfile.name), str(nbViolation))                
    
    tc = "SPDBviolation14_1_1", nbViolation, nbNAViolation
#    update_counts(tc)
    
    # Extra log
    t = "SPDBviolation14_1_1", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

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
    
    logging.info("scan_file_SPDBviolation14_1_5 : -------------------------------------------------------------------------")
    logging.info("scan_file_SPDBviolation14_1_5 : Starting scan_file_SPDBviolation14_1_5        > " + str(pfile.name))

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
                            logging.info("scan_file_SPDBviolation14_1_5 :: Currently processing %s", line)
                            logging.info("scan_file_SPDBviolation14_1_5 :: Freed memory %s" , p.group(1))
                                                      
                            module_line = linecache.getline(pfile.get_path(), current_line + 1)
                            logging.info("scan_file_SPDBviolation14_1_5 :: Next line is %s", module_line)
                            if module_line.__eq__("\n"):
                                module_line = linecache.getline(pfile.get_path(), current_line + 2)
                                scan_Utilities.markFreed(pfile, current_line, p, module_line)

                            else:
                                scan_Utilities.markFreed(pfile, current_line, p, module_line)

                                
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
#    update_counts(tc)
    
    # Extra log
    t = "SPDBviolation14_1_5", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
    

def scan_file_SPDBviolation10_3_4(application, pfile, fileType):
#   Description:  :   scan_file_SPDBviolation10_3_4 
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    dtType = "pointer"
    
    msecs = local_library.millis()
    nBytes = 0
    logging.debug("pfile.name----" + str(pfile.name))
    logging.info("scan_file_SPDBviolation10_3_4 : -------------------------------------------------------------------------")
    logging.info("scan_file_SPDBviolation10_3_4 : Starting scan_file_scan_file_SPDBviolation10_3_4 > " + str(pfile.name))
    
    patFunCall = "((int|float|char|bool)\s*\*\s*)([a-z]*[A-Z]*[0-9]*)\s*[,|=|;]"
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
            
            boolVarsInFile = list()
            boolExist = 0
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
#                            logging.debug("result value---" + str(p))
                            logging.info("scan_file_scan_file_SPDBviolation10_3_4::Result is: [%s]  [%s]  [%s]", pfile, line, p.group(2)) 
                            
                            checkMultipleVars = p.group(2).split(",")
                            for getVar in checkMultipleVars:
                                logging.debug("scan_file_SPDBviolation10_3_4 :: getVar value---" + str(getVar))
 #                               logging.info("\n@@@@ "+getVar)
                                
                                if getVar.__contains__('='):
                                    varNames = getVar.split("=")
                                    if (not varNames is None):                                          
                                        varName = varNames[0]
                                        logging.info("scan_file_SPDBviolation10_3_4 :: [PASSED] Value is initialized for " + varName)
                                        boolExist = 1
                                        scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, varName, dtType)
                                else:                              
                                    logging.debug("scan_file_SPDBviolation10_3_4 :: Violation saved for getVar value---" + str(getVar))  
                                    boolExist = 1
                                    scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, getVar, dtType)
                                    bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                    
                except Exception as e:
                    logging.error("scan_file_SPDBviolation10_3_4 : Error: %s, at line ", str(e), current_line)
                    
            if boolExist :
                for line1 in f:                  
                    logging.info(line1)

    except FileNotFoundError:
        logging.error("scan_file_SPDBviolation10_3_4 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("scan_file_SPDBviolation10_3_4 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    logging.info("scan_file_SPDBviolation10_3_4 : END %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation10_3_4", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation10_3_4", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------


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

