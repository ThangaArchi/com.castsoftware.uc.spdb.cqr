# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------

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

# 
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


def scan_file_CWE(application, pfile, fileType):
#   Languages :                       C
#    

    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    msecs = local_library.millis()
    nBytes = 0
 
    
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
                            #logging.debug("Found Test statement %s ==> %s", str(reference.value), str(reference.bookmark))
                            try:
                                bk = Bookmark(pfile,current_line,p.start()+1,current_line,p.end())
#                                obj.save_violation('',bk)
                            except Exception as e:
                                logging.warning("Violation not allowed on this kind of object, next version")
                                nbNAViolation = nbNAViolation + 1
                            else:
                                nbViolation += 1
                        
    except FileNotFoundError:
        logging.error(" : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error(" : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    logging.info(" : END  %s - Found %s violation ", str(pfile.name), str(nbViolation))  
    
    tc = "",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)              
    


    