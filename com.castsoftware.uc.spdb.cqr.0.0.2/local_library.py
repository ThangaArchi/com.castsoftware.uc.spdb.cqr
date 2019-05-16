# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------
# Utility library
# Author:        SCS
# Last update    28/3/2017

import cast_upgrade_1_5_11 # @UnusedImport
from cast.application import open_source_file
from cast.application import ApplicationLevelExtension, ReferenceFinder, Bookmark, Object
import logging
import re
import time
     
#Globals  
ExtraLogList = list()  
ExtraLogBytes = 0
ExtraLogMsecs = 0

#Global switches
SW_VERBOSE_LOG = False

# ..............................................................................
# ..............................................................................
       
def find_all_variables(pfile, mode):
#   Author :                 SCS
#   Last modification date : 12/4/2017
#   Description:             finds all defined variables and return them as a set 
#   Parameters:    
#       pfile         File to scan
#       mode          Detection mode: 0 only not initialized, 1 only initialized, 2 all    
    varCount = 0
    
    StdTypes = {"signed long long int", \
                "signed short int", "signed long long", "signed long int", \
                "signed char", "signed int","signed long", "signed short", \
                "signed", \
                "unsigned long long int", \
                "unsigned short int", "unsigned long int", "unsigned long long", \
                "unsigned char", "unsigned long", "unsigned int", "unsigned short", \
                "unsigned", \
                "long long int", \
                "long int", "long double", "long long", \
                "long", \
                "short int", \
                "short", \
                "char", "int", "float", "double",  "wchar_t", "char16_t", "char32_t" }
    
    logging.info("SPDB find_all_variables : Scanning file " + str(pfile.name))

    allVars = set()
    
    # Pattern like int var - group(1) is the var name
    patSimple     = "\s*\**\s*([a-zA-Z0-9_]+)(\s*\[\s*[^\[\]]*\s*\])*\s*;"
    # Pattern like int var=0 - group(1) is the var name
    patSimpleInit = "\s*\**\s*([a-zA-Z0-9_]+)(\s*\[\s*[^\[\]]*\s*\])*\s*=[^;]*;"
    # Pattern like int var1, var2, var3 - group(1) is the list of vars
    patMultiple   = "\s+((\s*\**\s*[a-zA-Z0-9_]+(\s*\[\s*[^\[\]]*\s*\])*\s*\,)+\s*\**\s*[a-zA-Z0-9_]+(\s*\[\s*[^\[\]]*\s*\])*\s*);"
    # Pattern like var or var[..] - group(1) is the var name
    patSimpleVar  = "([a-zA-Z0-9_]+)(\s*\[\s*[^\[\]]*\s*\])*"
    
    # Patterns for function parameters
    patFunction       = "\s*([a-zA-Z0-9_\.]+\s*\**\s*|\(\s*[a-zA-Z0-9_\.]+\s*\**\s*\))\s+([a-zA-Z0-9_\.]+)\s*\("
    patMultipleFunPar = "(\s*[a-zA-Z0-9_]+\s*\**\s*[a-zA-Z0-9_]+\s*\,)*\s*[a-zA-Z0-9_]+\s*\**\s*[a-zA-Z0-9_]+\s*\)\s*[\{\;]"
    patFunPar       = "\s*\**\s*([a-zA-Z0-9_]+)(\s*\[\s*[^\[\]]*\s*\])*\s*"
    
    patComment = "(^[ \t]*[\/][\/])|([\/][\*])|([\*][\/])"
    
    try:
        isInSingleLineComment = False
        isInMultiLineComment = False
        
        # ..............................................................
        # Reads file into a buffer, excluding comments
        buffer = ""
        with open_source_file(pfile.get_path()) as f:
            
            for line in f:
                
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
                
                buffer = buffer + line + " "
     
        logging.info("SPDB find_all_variables : File scanned (size %s) ", len(buffer))
     
        # ..............................................................          
        # Loop on all standard types for variable definitions
        for p in StdTypes:    
            # Pattern for simple var   
            results = re.finditer(p+patSimple, buffer)
            if (not results is None):
                for m in results:
                    var = m.group(1)
                    #logging.info("SPDB find_all_variables : Single Variable with no init %s", str(var))
                    if (mode == 0 or mode == 2) and (not var in allVars):
                        allVars.add(var)
                        varCount += 1
                    
            # Pattern for simple with init       
            results = re.finditer(p+patSimpleInit, buffer)
            if (not results is None):
                for m in results:
                    var = m.group(1)
                    #logging.info("SPDB find_all_variables : Single Variable with init %s", str(var))
                    if (mode == 1 or mode == 2) and (not var in allVars):
                        allVars.add(var)
                        varCount += 1
                    
            # Pattern for multiple vars                   
            results = re.finditer(p+patMultiple, buffer)
            if (not results is None):
                for m in results:
                    mvar = m.group(1)       
                    mv = re.finditer(patSimpleVar, mvar)
                    for v in mv:
                        vi = v.group(1)
                        #logging.info("SPDB find_all_variables : Variable in a multiple definition %s (from %s)", str(vi), str(mvar).strip())
                        if (mode == 0 or mode == 2) and (not vi in allVars):
                            allVars.add(vi)
                            varCount += 1 
                            
        # ..............................................................                                              
        # Find function parameters
        results = re.finditer(patFunction+patMultipleFunPar, buffer)
        if (not results is None):
            for mFC in results:  
                mFCode = mFC.group(0)
                         
                # Get function name                 
                m = re.search(patFunction, mFCode)
                funcName = m.group(2)
                
                # Get parameters 
                for p in StdTypes:
                    m = re.finditer(p + patFunPar, mFCode)
                    if (not m is None):
                        for im in m:
                            var = im.group(1)
                            if (var != funcName) and (not var in allVars):
                                #logging.info("SPDB find_all_variables : Variable %s as parameter for function %s", str(var), funcName)
                                allVars.add(var)
                                varCount += 1
                           
    except FileNotFoundError:
        logging.error("SPDB find_all_variables : File not found > " + str(pfile.get_path()) )
    except Exception as e:
        logging.error("SPDB find_all_variables : Error: %s", str(e))     
           
    logging.info("SPDB find_all_variables : Found %s variables", str(varCount))
    
    return allVars

def is_a_keyword(strToCheck):
#   Author :                 SCS
#   Last modification date : 20/3/2017
#   Description:             Checks if a string is a C/C++/C# keyword 
#   Parameters:    
#       strToCheck           The string to check
#   Return:         
#       1 if it is a keyword, 0 otherwise   
    
    StdKWords = {"alignas","alignof","and","and_eq","asm","atomic_cancel","atomic_commit","atomic_noexcept", \
                 "auto","bitand","bitor","bool","break","case","catch","char","char16_t","char32_t","class", \
                 "compl","concept","const","constexpr","const_cast","continue","decltype","default","delete", \
                 "do","double","dynamic_cast","else","enum","explicit","export","extern","FALSE","float", \
                 "for","friend","goto","if","import","inline","int","long","module","mutable","namespace", \
                 "new","noexcept","not","not_eq","nullptr","operator","or","or_eq","private","protected", \
                 "public","register","reinterpret_cast","requires","return","short","signed","sizeof", \
                 "static","static_assert","static_cast","struct","switch","synchronized","template","this", \
                 "thread_local","throw","TRUE","try","typedef","typeid","typename","union","unsigned", \
                 "using","virtual","void","volatile","wchar_t","while","xor","xor_eq" }
        
    for p in StdKWords:
        if p == strToCheck:
            return 1
    
    return 0

def is_a_special_func(strToCheck):
#   Author :                 SCS
#   Last modification date : 20/3/2017
#   Description:             Checks if a string is a special function 
#   Parameters:    
#       strToCheck           The string to check
#   Return:         
#       1 if it is a keyword, 0 otherwise   
    
    StdKWords = {"free"}
        
    for p in StdKWords:
        if p == strToCheck:
            return 1
    
    return 0

def millis():
#   Author :                 SCS
#   Last modification date : 27/4/2017
#   Description:             Gets current time in milliseconds 
#   Return:         
#       Current time as int in milliseconds  
    return int(round(time.time() * 1000))

def extraLogWrite(t):
#   Author :                 SCS
#   Last modification date : 27/4/2017
#   Description:             Log the tuple t on an extra internal log list, and updates global stats        
    global ExtraLogList
    global ExtraLogBytes
    global ExtraLogMsecs
           
    try:
        ExtraLogList.append(t)  
        ExtraLogBytes = ExtraLogBytes + int(t[2])
        ExtraLogMsecs = ExtraLogMsecs + int(t[3])
    except Exception as err:
        logging.error("local_library : Error: %s", str(err))       
 
def extraLogResult():
#   Description:             Update the log with stats for each : throughput, duration, bytes processed
    global ExtraLogList   
    global ExtraLogBytes
    global ExtraLogMsecs
    
    regCount = dict()
    regThr = dict()
    regDur = dict()
    
    try:
        for e in ExtraLogList:
            if not e[0] in regCount.keys():
                regCount[e[0]] = 1
                regThr[e[0]] = int(e[1])
                regDur[e[0]] = int(e[3])/1000
            else:
                regCount[e[0]] = regCount[e[0]] + 1
                regThr[e[0]] = regThr[e[0]] + int(e[1])
                regDur[e[0]] = regDur[e[0]] + int(e[3])/1000
                    
        logging.info("========================================================")
        logging.info("== SPDB Performance statistics: (SPDB rule, throughput kB/s, total duration (s))")
        for k in sorted(regThr):
            if regCount[k] != 0:
                logging.info("%s \t%s \t%s",k,int(regThr[k]/regCount[k]),int(regDur[k]))
        logging.info("== Total time (s): %s - Total kBytes: %s",int(ExtraLogMsecs/1000),int(ExtraLogBytes/1024))
        logging.info("========================================================")
    except Exception as err:
        logging.error("local_library : Error: %s", str(err))

def cwefdaLoggerInfo(msg, *args, **kwargs):
#   Description:             Executes logging.info id SW_VERBOSE_LOG is true    
    
    global SW_VERBOSE_LOG
    
    if SW_VERBOSE_LOG:
        logging.info(msg, *args, **kwargs)
    
def cwefdaLoggerWarning(msg, *args, **kwargs):
#   Description:             Executes logging.warning id SW_VERBOSE_LOG is true    
    
    global SW_VERBOSE_LOG
    
    if SW_VERBOSE_LOG:
        logging.warning(msg, *args, **kwargs)  
        