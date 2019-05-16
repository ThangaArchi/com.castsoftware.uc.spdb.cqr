##############################################################################################
#---------------------------------------------------------------------------------------------
# Created on 
#
# Aauthor: Thangadurai Kandhasamy<t.kandhasamy@castsoftware.com> - TKA
#
# Description: 
#---------------------------------------------------------------------------------------------
##############################################################################################




import logging
import re
from cast.application import ApplicationLevelExtension, ReferenceFinder, Bookmark, Object

SCSCountResults = dict()


# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def isValidatedWithIF(line, pfile, current_line, p):
    patNullCheck = "if\s*\((.*)(?=\))"
    logging.info("%s", line)
    nullRes2 = re.findall(patNullCheck, line)
    logging.info("isValidatedWithIF :: IF condition present")
    
    if nullRes2:
        memCheck = re.findall( "(NULL)", line )
        logging.info("isValidatedWithIF :: Search String %s", line)
        if memCheck :
#        if p.group(1).find("NULL") != -1:
            logging.info("isValidatedWithIF :: NO-VIOLATION MALLOC is validated with NULL - lines[1] %s", line)
        else:
            bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
            pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_1', bk)
            logging.info("isValidatedWithIF :: SPDBviolation14_1_1 :: VIOLATION: MALLOC is NOT validated with NULL - %s", line )
    else:
        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_1', bk)
        logging.info("isValidatedWithIF :: SPDBviolation14_1_1 :: VIOLATION: MALLOC is NOT validated with NULL - %s", line )
        
# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------

def markFreed(pfile, current_line, p, module_line):
    open1 = "("
    close1 = ")"
    patNullify = "\s*=\s*NULL\s*;"
#    module_line = linecache.getline(pfile.get_path(), current_line + 2)
    patNullifyConstruct = open1 + p.group(1) + close1 + patNullify
    resNullify = re.findall(patNullifyConstruct, module_line)
    logging.info("markFreed :: Pattern %s, String %s", patNullifyConstruct, module_line)
    
    if resNullify:
        logging.info("markFreed :: MEMORY is freed - True %s", module_line)
    else:
        logging.info("markFreed :: MEMORY is NOT freed - VIOLATION %s", module_line)
        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation14_1_5', bk)
    
        
# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
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
        logging.error("count_results :: Global : Error: %s", str(err))

# ..............................................................................
# ..............................................................................
