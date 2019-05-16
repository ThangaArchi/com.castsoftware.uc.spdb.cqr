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
import scan_Utilities

# Counting register
SCSCountList = list()
SCSCountResults = dict()



boolVarsInFile = list()



# ..............................................................................
# ..............................................................................

def scan_file_SPDBviolation9_1_3(application, pfile, fileType):
#   Description: scan_file_SPDBviolation9_1_3
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    
    msecs = local_library.millis()
    nBytes = 0
    logging.debug("pfile.name----" + str(pfile.name))
    logging.info("SPDBviolation9_1_3 : -------------------------------------------------------------------------")
    logging.info("SPDBviolation9_1_3 : Starting scan_file_SPDBviolation9_1_3 > " + str(pfile.name))
    
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
#                                    bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                    bk = Bookmark(pfile, current_line, 1, current_line, -1)
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
    logging.info("SPDBviolation9_1_3 : END %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation9_1_3", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation9_1_3", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)


# ..............................................................................
# ..............................................................................




#--------------- def scan_file_SPDBviolation9_1_3(application, pfile, fileType):
   #---------------------------------- Description: scan_file_SPDBviolation9_1_3
   #----------------------------------------------------------------------- NOTE
   # As the rule is widely general and largely semantic, it is tailored only on specific patterns.
   #--------- It simply finds all function calls which are not assigned to vars.
#------------------------------------------------------------------------------ 
    #----------------------------------------------------------- nbViolation = 0
    #--------------------------------------------------------- nbNAViolation = 0
#------------------------------------------------------------------------------ 
    #-------------------------------------------- msecs = local_library.millis()
    #---------------------------------------------------------------- nBytes = 0
    #------------------------- logging.debug("pfile.name----" + str(pfile.name))
    # logging.info("SPDBviolation9_1_3 : -------------------------------------------------------------------------")
    # logging.info("SPDBviolation9_1_3 : Starting scan_file_SPDBviolation9_1_3 > " + str(pfile.name))
#------------------------------------------------------------------------------ 
    # patFunCall = "(float|int|char|bool)[ \t\r\n]+([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"
#------------------------------------------------------------------------------ 
#------------------------------------------------------------------------------ 
    #-------------------- patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
#------------------------------------------------------------------------------ 
    #---------------------------------------------------------------------- try:
        #----------------------------------------- isInSingleLineComment = False
        #------------------------------------------ isInMultiLineComment = False
        #------------------------- with open_source_file(pfile.get_path()) as f:
             #---------------------------------------------- current line number
            #-------------------------------------------------- current_line = 0
#------------------------------------------------------------------------------ 
            #---------------------------------------------------- for line in f:
                 #------------------------------------------------- Line of code
                #------------------------ logging.error("Current line %s", line)
#------------------------------------------------------------------------------ 
                #--------------------------------------------- current_line += 1
#------------------------------------------------------------------------------ 
                #---------------------------------------------------------- try:
                    #----------------- resultCom = re.finditer(patComment, line)
                     #---------- logging.debug("resultCom value---" + str(line))
                     #-------------------------------- Comment Exclusion - Start
                    #--------------------------------- if not resultCom is None:
                        #----------------------------------- for c in resultCom:
                            #------------------------------------ if c.group(1):
                                #------------------ isInSingleLineComment = True
                            #------------------------------------ if c.group(2):
                                #------------------- isInMultiLineComment = True
                            #------------------------------------ if c.group(3):
                                #------------------ isInMultiLineComment = False
                    #---------------------------------- if isInMultiLineComment:
                        #---------------------------------------------- continue
                    #--------------------------------- if isInSingleLineComment:
                        #------------------------- isInSingleLineComment = False
                        #---------------------------------------------- continue
                     #---------------------------------- Comment Exclusion - End
#------------------------------------------------------------------------------ 
                    #------------------------------- nBytes = nBytes + len(line)
#------------------------------------------------------------------------------ 
                     #------------------------------- Get function call patterns
                    #-------------------- result = re.finditer(patFunCall, line)
#------------------------------------------------------------------------------ 
                    #------------------- logging.info("Result is: >%s<", result)
                    #---------------------------------- if (not result is None):
                        #-------------------------------------- for p in result:
                            # logging.debug("scan_file_SPDBviolation9_1_3 :: result value---" + str(p))
                            # logging.info("scan_file_SPDBviolation9_1_3::Result is: [%s]  [%s]  [%s]  [%s] ", pfile, line, p.group(2), p.group(7))
#------------------------------------------------------------------------------ 
                            #--------- checkMultipleVars = p.group(2).split(",")
                            #------------------ for getVar in checkMultipleVars:
                                # logging.debug("scan_file_SPDBviolation9_1_3 :: getVar value---" + str(getVar))
                                #---------------- logging.info("\n@@@@ "+getVar)
#------------------------------------------------------------------------------ 
                                #------------------ if getVar.__contains__('='):
                                    # logging.info("SPDBviolation9_1_3 :: [PASSED] Value is initialized for " + getVar)
                                #----------------------------------------- else:
                                    # logging.debug("Violation saved for getVar value---" + str(getVar))
                                     #--------------------------- Set a bookmark
                                    # bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                    # bk = Bookmark(pfile, current_line, 1, current_line, -1)
                                    # pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation9_1_3', bk)
                #---------------------------------------- except Exception as e:
                    # logging.error("SPDBviolation9_1_3 : Error: %s, at line ", str(e), current_line)
#------------------------------------------------------------------------------ 
    #------------------------------------------------- except FileNotFoundError:
        # logging.error("SPDBviolation9_1_3 : File not found > " + str(pfile.get_path()))
    #---------------------------------------------------- except Exception as e:
        #--------------- logging.error("SPDBviolation9_1_3 : Error: %s", str(e))
#------------------------------------------------------------------------------ 
    #------------------------------------ msecs = local_library.millis() - msecs
    #------------------------------------------------------------ if msecs == 0:
        #------------------------------------------------------------- msecs = 1
    # logging.info("SPDBviolation9_1_3 : END %s - Found %s violation ", str(pfile.name), str(nbViolation))
#------------------------------------------------------------------------------ 
    #--------------------- tc = "SPDBviolation9_1_3", nbViolation, nbNAViolation
    #--------------------------------------------------------- update_counts(tc)
#------------------------------------------------------------------------------ 
     #---------------------------------------------------------------- Extra log
    #-------------- t = "SPDBviolation9_1_3", int(nBytes / msecs), nBytes, msecs
    #-------------------------------------------- local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------



def scan_file_SPDBviolation10_3_1(application, pfile, fileType):
#   Description: scan_file_SPDBviolation10_3_1 
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    dtType = "bool"
    
    msecs = local_library.millis()
    nBytes = 0
    logging.debug("pfile.name----" + str(pfile.name))
    logging.info("scan_file_SPDBviolation10_3_1 : -------------------------------------------------------------------------")
    logging.info("scan_file_SPDBviolation10_3_1 : Starting scan_file_scan_file_SPDBviolation10_3_1 > " + str(pfile.name))
    
    patFunCall = "(bool)[ \t\r\n]+([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"
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
                            logging.info("scan_file_scan_file_SPDBviolation10_3_1::Result is: [%s]  [%s]  [%s]", pfile, line, p.group(2)) 
                            
                            checkMultipleVars = p.group(2).split(",")
                            for getVar in checkMultipleVars:
                                logging.debug("scan_file_SPDBviolation10_3_1 :: getVar value---" + str(getVar))
 #                               logging.info("\n@@@@ "+getVar)
                                
                                if getVar.__contains__('='):
                                    varNames = getVar.split("=")
                                    if (not varNames is None):                                          
                                        varName = varNames[0]
                                        logging.info("scan_file_SPDBviolation10_3_1 :: [PASSED] Value is initialized for " + varName)
                                        boolExist = 1
                                        scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, varName, dtType) #, "SPDBviolation10_3_1")
                                else:                              
                                    logging.debug("scan_file_SPDBviolation10_3_1 :: Violation saved for getVar value---" + str(getVar))  
                                    boolExist = 1
                                    scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, getVar, dtType) #, "SPDBviolation10_3_1")
                                    
                except Exception as e:
                    logging.error("scan_file_SPDBviolation10_3_1 : Error: %s, at line ", str(e), current_line)
                    
            if boolExist :
                for line1 in f:                  
                    logging.info(line1)

    except FileNotFoundError:
        logging.error("scan_file_SPDBviolation10_3_1 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("scan_file_SPDBviolation10_3_1 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    logging.info("scan_file_SPDBviolation10_3_1 : END %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation10_3_1", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation10_3_1", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------



def scan_file_SPDBviolation10_3_2(application, pfile, fileType):
#   Description: scan_file_SPDBviolation10_3_2
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    dtType = "int"
    
    msecs = local_library.millis()
    nBytes = 0
    logging.debug("pfile.name----" + str(pfile.name))
    logging.info("scan_file_SPDBviolation10_3_2 : -------------------------------------------------------------------------")
    logging.info("scan_file_SPDBviolation10_3_2 : Starting scan_file_scan_file_SPDBviolation10_3_2 > " + str(pfile.name))
    
    patFunCall = "(int)[ \t\r\n]+([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"
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
                            logging.info("scan_file_scan_file_SPDBviolation10_3_2::Result is: [%s]  [%s]  [%s]", pfile, line, p.group(2)) 
                            
                            checkMultipleVars = p.group(2).split(",")
                            for getVar in checkMultipleVars:
                                logging.debug("scan_file_SPDBviolation10_3_2 :: getVar value---" + str(getVar))
 #                               logging.info("\n@@@@ "+getVar)
                                
                                if getVar.__contains__('='):
                                    varNames = getVar.split("=")
                                    if (not varNames is None):                                          
                                        varName = varNames[0]
                                        logging.info("scan_file_SPDBviolation10_3_2 :: [PASSED] Value is initialized for " + varName)
                                        boolExist = 1
                                        scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, varName, dtType) #, "SPDBviolation10_3_2")
                                else:                              
                                    logging.debug("scan_file_SPDBviolation10_3_2 :: Violation saved for getVar value---" + str(getVar))  
                                    boolExist = 1
                                    scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, getVar, dtType) #, "SPDBviolation10_3_2")
                                    
                except Exception as e:
                    logging.error("scan_file_SPDBviolation10_3_2 : Error: %s, at line ", str(e), current_line)
                    
            if boolExist :
                for line1 in f:                  
                    logging.info(line1)

    except FileNotFoundError:
        logging.error("scan_file_SPDBviolation10_3_2 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("scan_file_SPDBviolation10_3_2 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    logging.info("scan_file_SPDBviolation10_3_2 : END %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation10_3_2", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation10_3_2", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------



def scan_file_SPDBviolation10_3_3(application, pfile, fileType):
#   Description: scan_file_SPDBviolation10_3_3
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    dtType = "float"
    
    msecs = local_library.millis()
    nBytes = 0
    logging.debug("pfile.name----" + str(pfile.name))
    logging.info("scan_file_SPDBviolation10_3_3 : -------------------------------------------------------------------------")
    logging.info("scan_file_SPDBviolation10_3_3 : Starting scan_file_scan_file_SPDBviolation10_3_3 > " + str(pfile.name))
    
    patFunCall = "(float)[ \t\r\n]+([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"
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
                            logging.info("scan_file_scan_file_SPDBviolation10_3_3::Result is: [%s]  [%s]  [%s]", pfile, line, p.group(2)) 
                            
                            checkMultipleVars = p.group(2).split(",")
                            for getVar in checkMultipleVars:
                                logging.debug("scan_file_SPDBviolation10_3_3 :: getVar value---" + str(getVar))
 #                               logging.info("\n@@@@ "+getVar)
                                
                                if getVar.__contains__('='):
                                    varNames = getVar.split("=")
                                    if (not varNames is None):                                          
                                        varName = varNames[0]
                                        logging.info("scan_file_SPDBviolation10_3_3 :: [PASSED] Value is initialized for " + varName)
                                        boolExist = 1
                                        scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, varName, dtType) #, "SPDBviolation10_3_3")
                                else:                              
                                    logging.debug("scan_file_SPDBviolation10_3_3 :: Violation saved for getVar value---" + str(getVar))  
                                    boolExist = 1
                                    scan_Utilities.unConditionalCheck(line, pfile, current_line, p, f, getVar, dtType) #, "SPDBviolation10_3_3")
                                    
                except Exception as e:
                    logging.error("scan_file_SPDBviolation10_3_3 : Error: %s, at line ", str(e), current_line)
                    
            if boolExist :
                for line1 in f:                  
                    logging.info(line1)

    except FileNotFoundError:
        logging.error("scan_file_SPDBviolation10_3_3 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("scan_file_SPDBviolation10_3_3 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    logging.info("scan_file_SPDBviolation10_3_3 : END %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation10_3_3", nbViolation, nbNAViolation
    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation10_3_3", int(nBytes / msecs), nBytes, msecs
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
