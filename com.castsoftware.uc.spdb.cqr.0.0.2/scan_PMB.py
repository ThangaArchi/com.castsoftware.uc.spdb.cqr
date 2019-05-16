# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

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


def scan_file(application, pfile, fileType):
    #    
    nbViolation = 0
    nbNAViolation = 0
    isInMultiLineComment = False
    isInSingleLineComment = False
    
    #SCS
    msecs = local_library.millis()
    nBytes = 0
    
    logging.info(" : -------------------------------------------------------------------------")

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
                        #logging.debug(" : Detected violation > %s at line %s, col. %s", p.group(), current_line, p.start()+1)

                        try:
                            obj.save_violation('',bk)                                
                        except:
                            logging.warning(" : Violation not allowed on this object, next version")
                            nbNAViolation = nbNAViolation + 1
                        else:
                            nbViolation +=1
                            
    except FileNotFoundError:
        logging.error(" : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error(" : Error: %s", str(e)) 
        
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1
    logging.info(" : END scan_file %s - Found %s violation ", str(pfile.name), str(nbViolation))   
    
    tc = "",nbViolation,nbNAViolation
    update_counts(tc)
    
    #Extra log
    t = "",int(nBytes/msecs),nBytes,msecs
    local_library.extraLogWrite(t)

# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

    