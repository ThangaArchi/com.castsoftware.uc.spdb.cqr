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
from cast.application import open_source_file
import re

from cast.application import ApplicationLevelExtension, ReferenceFinder, Bookmark, Object
from itertools import islice

# Counting register
SCSCountList = list()
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

def unConditionalCheck(line, pfile, identified_line, p, file_path, vari, dtType):

    with open_source_file(pfile.get_path()) as f:
        # current line number
        current_line = 1
        
#        boolVarsInFile = list()
#        boolExist = 0
        logging.info("Identified Variable and Line: %s %s", vari, identified_line)
        try:
            for line in f:                  
                # Line of code
    #                logging.error("Current line %s", line) 
    #            logging.info("Current line: %s", current_line)
    
                if current_line > identified_line:
    #                logging.info("STARTED READING LINES:  %s", line)
                    
                    patNullCheck = "if\s*\((.*)(?=\))"
    #                logging.error("%s", line)
                    nullRes2 = re.findall(patNullCheck, line)
     #               logging.info("unConditionalCheck :: IF condition present")
                    
                    if nullRes2:
#                    for rs in nullRes2:
#                        ress = rs.group(1)
#                        print(ress)
                        open1 = "("
                        close1 = ")"
                        patBoolInside = open1 + vari + close1
                        varExist = re.findall(patBoolInside, line)
                        if varExist :
                            if dtType == "bool" :
                                boolValidtrs = re.finditer( "(true|false|TRUE|FALSE|0|1)", line )
                                if (not boolValidtrs is None):                                          
                                    for p in boolValidtrs:   
                                        
                                        logging.error("unConditionalCheck :: VIOLATION : SPDBviolation10_3_1 : Boolean variable is directly compared to 'true', 'false', or 1, 0 => %s %s", vari, line)
                                        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation10_3_1', bk)
                                        break;
                            if dtType == "int" :
                                intValidtrs = re.finditer( "\(\s*([\w]*)\s*(?=[\)])", line )
                                if (not intValidtrs is None):                                          
                                    for p in intValidtrs:   
                                        
                                        logging.error("unConditionalCheck :: VIOLATION : SPDBviolation10_3_2 : The integer variable should use  '==' or '!=' directly compared to 0 %s %s", vari, line)
                                        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation10_3_2', bk)
                                        break;
                            if dtType == "float" :
                                floatValidtrs = re.finditer( "\(\s*([\w*|0-9.0-9]*)\s*(!=|==)\s*([\w*|0-9.0-9]*)\s*(?=[\)])", line )
                                if (not floatValidtrs is None):                                          
                                    for p in floatValidtrs:   
                                        
                                        logging.error("unConditionalCheck :: VIOLATION : SPDBviolation10_3_3 : Can not compare a floating point variable to any number with an '=='or '!=' => %s %s", vari, line)
                                        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation10_3_3', bk)
                                        break;
                            if dtType == "pointer" :
                                pointerValidtrs = re.finditer( "\((\s*\w*\s*[^==|!=]\s*\w*\s*)(?=\))", line )
                                if (not pointerValidtrs is None):                                          
                                    for p in pointerValidtrs:   
                                        
                                        logging.error("unConditionalCheck :: VIOLATION : SPDBviolation10_3_4 : Pointer variables should use '==' or '! =' compared with NULL => %s %s", vari, line)
                                        bk = Bookmark(pfile, current_line, p.start() + 1, current_line, p.end())
                                        pfile.save_violation('SPDB_CustomMetrics_C.SPDBviolation10_3_4', bk)
                                        break;
                current_line += 1
        except FileNotFoundError:
            logging.error("unConditionalCheck : File not found > " + str(pfile.get_path()))
        except Exception as e:
            logging.error("unConditionalCheck : Error: %s", str(e)) 
        

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
        logging.error("SCS Global : Error: %s", str(err))
