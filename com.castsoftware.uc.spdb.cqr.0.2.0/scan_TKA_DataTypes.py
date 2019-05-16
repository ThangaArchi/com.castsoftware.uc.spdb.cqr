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
    logging.info("SPDBviolation9_1_3 : -------------------------------------------------------------------------")
    logging.info("SPDBviolation9_1_3 : Starting scan_file_SPDBviolation9_1_3 > " + str(pfile.name))
    
    patFunCall = "(float|int|char|bool)[ \t\r\n]+([A-Za-z0-9_\-\(\),=\. \t\r\n]+);"

   
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
                            logging.debug("scan_file_SPDBviolation9_1_3 :: result value---" + str(p))
#                            logging.info("scan_file_SPDBviolation9_1_3::Result is: [%s]  [%s]  [%s]  [%s] ", pfile, line, p.group(2), p.group(7)) 
                            
                            checkMultipleVars = p.group(2).split(",")
                            for getVar in checkMultipleVars:
                                logging.debug("scan_file_SPDBviolation9_1_3 :: getVar value---" + str(getVar))
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
    logging.info("SPDBviolation9_1_3 : END scan_file_CWE_252 %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation9_1_3", nbViolation, nbNAViolation
#    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation9_1_3", int(nBytes / msecs), nBytes, msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
