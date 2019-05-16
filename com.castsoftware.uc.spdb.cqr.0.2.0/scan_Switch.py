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
import linecache

# Counting register
SCSCountList = list()
SCSCountResults = dict()



boolVarsInFile = list()




def scan_file_SPDBviolation10_5_3(application, pfile, fileType):
#   Description: scan_file_SPDBviolation10_5_3 
#   NOTE
#   As the rule is widely general and largely semantic, it is tailored only on specific patterns.
#   It simply finds all function calls which are not assigned to vars.
#    
    nbViolation = 0
    nbNAViolation = 0
    
    msecs = local_library.millis()
    nBytes = 0
    logging.debug("pfile.name----" + str(pfile.name))
    logging.info("SPDBviolation10_5_3 : -------------------------------------------------------------------------")
    logging.info("SPDBviolation10_5_3 : Starting scan_file_SPDBviolation10_5_3 > " + str(pfile.name))
    
#    patswitch = "switch\s*\((.*)(?=)\)"
    patcase = "(switch|case|default)\s*(.*)(?=)"

   
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
                                     
    try:
        isInSingleLineComment = False
        isInMultiLineComment = False
        switchcheck = 0
        matchedcasedefault=0
        matchedswitch=0
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
#                    switchcheck=0
                                        
                                        
                    # Get function call patterns
#                    isswitch = re.findall(patswitch, line)
#                    if switchcheck == 0:
#                        if isswitch:
#                            logging.info("Current line %s", line)
#                            switchcheck=1
                            
#                    if switchcheck == 1:
                    if matchedswitch==1:
                        if matchedcasedefault==1:
                            nextline = line
                            if nextline.__eq__("\n") or nextline.__contains__("{"):
                                logging.info("Empty line - Check in next line %s", nextline )
                                nextline = linecache.getline(pfile.get_path(), current_line + 1)
#                            else:
#                                logging.info("CASE found  - Next line %s", nextline )
                                
#                            logging.debug("Processing next line %s", nextline )
                            resultCom = re.findall(patComment, nextline)
                            if resultCom :
                                logging.info("Proper COMMENTES are found in CASE %s", nextline )
                            else:
                                logging.info("SPDBviolation10_5_3 :: VIOLATION - Each case branch of the switch statement should have comments %s - Line %s", nextline,  line )
    #                           logging.info("Current line %s type %s", line, p.group(1))
                                bk = Bookmark(pfile, current_line, 1, current_line, -1)
                                pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation10_5_3', bk)
                                matchedcasedefault=0
                    
                    
                    
                    isswitchcase = re.finditer(patcase, line)

                    if not isswitchcase is None:
                        for p in isswitchcase:
                            
#                            logging.info("Current line %s", line)
                            if p.group(1) == "switch":
                                logging.info("SWITCH found  - Current line %s", line )
#                                logging.info("SWITCH found  - Current line %s type %s", line, p.group(1))
                                matchedswitch = 1

                            if p.group(1) == "case" or p.group(1) == "default":
                                logging.info("CASE found  - Current line %s", line )
#                                logging.info("CASE found  - Current line %s type %s", line, p.group(1))
                                matchedcasedefault = 1

                            if p.group(1) == "default":
                                logging.info("DEFAULT found  - Current line %s", line )
#                                logging.info("DEFAULT found  - Current line %s type %s", line, p.group(1))
                                matchedcasedefault = 1
                                                                                
                except Exception as e:
                    logging.error("SPDBviolation10_5_3 : Error: %s, at line ", str(e), current_line)
                                                                    
    except FileNotFoundError:
        logging.error("SPDBviolation10_5_3 : File not found > " + str(pfile.get_path()))
    except Exception as e:
        logging.error("SPDBviolation10_5_3 : Error: %s", str(e)) 
    
    msecs = local_library.millis() - msecs
    if msecs == 0: 
        msecs = 1   
    logging.info("SPDBviolation10_5_3 : END %s - Found %s violation ", str(pfile.name), str(nbViolation))    
    
    tc = "SPDBviolation10_5_3", nbViolation, nbNAViolation
#    update_counts(tc)       
    
    # Extra log
    t = "SPDBviolation10_5_3", int(nBytes / msecs), nBytes, msecs
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



