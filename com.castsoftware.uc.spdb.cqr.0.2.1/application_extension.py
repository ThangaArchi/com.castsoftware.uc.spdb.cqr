##############################################################################################
#---------------------------------------------------------------------------------------------
# Created on Apr 26, 2019
#
# Aauthor: Thangadurai Kandhasamy<t.kandhasamy@castsoftware.com> - TKA
#
# Description: 
#---------------------------------------------------------------------------------------------
##############################################################################################

import cast_upgrade_1_5_11  # @UnusedImport
from cast.application import ApplicationLevelExtension, ReferenceFinder
import logging
import re

import scan_SCS
import scan_PMB
import scan_MGE
import local_library
import scan_DataTypes
import scan_Pointers
import scan_Switch


class ApplicationExtension(ApplicationLevelExtension):
    nbProgramScanned = 0

    def end_application(self, application):
        logging.info("SPDB : Running extension code at the end of an application")
        self.nbProgramScanned = 0
        
        # DEV NOTE
        # Put here property ownership
             
        try:             
                      
            logging.info("SPDB : Load ownership - START")
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation9_1_3', ['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation12_2_5',['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation14_1_1',['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation14_1_5',['C_FILE'])
            
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation10_3_1',['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation10_3_2',['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation10_3_3',['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation10_3_4',['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation10_5_3',['C_FILE'])
            
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation9_4_2',['C_FILE'])
            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation16_2_10',['C_FILE'])
            
            
            
            logging.info("SPDB : Load ownership - END")
#            application.declare_property_ownership('SPDB_CustomMetrics_C.SPDBviolation14_1_3',['C_FILE'])
            
        except Exception as e:
            logging.error("SPDB : Error defining properties %s", str(e))

        # list all files saved by C/C++/C# Analyzers
        try:
            fileCount = sum(1 for x in application.get_files(['C_FILE']))
            files_dr = application.get_files(['C_FILE'])
        except Exception as e:
            logging.error("SPDB : Error selecting C file set : %s", str(e))
            
        logging.info("SPDB : Files Found: > " + str(fileCount))

        # looping through Files
        for o in files_dr:
            fType = 0
            # logging.debug("File Name which found---" + str(o))
                        
        # ..........................................................................................................    
        # list all files saved by C/C++/C# Analyzers - without application.get_files the for cycle is not working!!!
        try:
            files = application.get_files(['C_FILE'])
        except Exception as e:
            logging.error("SPDB : Error selecting C/C++ file set : %s", str(e))
        
        for file in files:
            fType = 0
            logging.debug("File Name which found---" + str(file))
            
            #    check if file is analyzed source code, or if it generated (Unknown)
            if not file.get_path():
                continue

            if  file.get_path().lower().endswith('.c') or file.get_path().lower().endswith('.h') :
                logging.info("SPDB : Found C_FILE file")
                fType = 1

            logging.info("SPDB Scanning Step : File found: > " + str(o.get_path()))
            # C Files
            if fType == 1:
                # DEV NOTE
                # Put here calls for all C files (ONLY FOR STEP2!)
                scan_DataTypes.scan_file_SPDBviolation9_1_3(application, file, "CCPP")
                scan_Pointers.scan_file_SPDBviolation12_2_5(application, file, "CCPP")
                scan_Pointers.scan_file_SPDBviolation14_1_1(application, file, "CCPP")
                scan_Pointers.scan_file_SPDBviolation14_1_5(application, file, "CCPP")
                
                scan_DataTypes.scan_file_SPDBviolation10_3_1(application, file, "CCPP")
                scan_DataTypes.scan_file_SPDBviolation10_3_2(application, file, "CCPP")
                scan_DataTypes.scan_file_SPDBviolation10_3_3(application, file, "CCPP")
                scan_Pointers.scan_file_SPDBviolation10_3_4(application, file, "CCPP")
                scan_Switch.scan_file_SPDBviolation10_5_3(application, file, "CCPP")
                scan_Pointers.scan_file_SPDBviolation9_4_2(application, file, "CCPP")


#                scan_SCS.scan_file_SPDBviolation14_1_3(application, file, "CCPP")


        # ..........................................................................................................    
        # 
        # Final reporting in ApplicationPlugins.castlog
        logging.info("========================================================")
        logging.info("SPDB : STATISTICS for AIA expectation: Number of C# or C/C++ files scanned : " + str(self.nbProgramScanned))
        logging.info("")
        
        logging.info("========================================================")
        logging.info("== SPDB : Violation statistics:") 
        scan_SCS.count_results()  
#        scan_MGE.count_results()
#        scan_PMB.count_results()  
        for k in scan_SCS.SCSCountResults:
            logging.info("%s : %s", k, scan_SCS.SCSCountResults[k])
#        for k in scan_MGE.MGECountResults:
#            logging.info("%s : %s", k, scan_MGE.MGECountResults[k])
#        for k in scan_PMB.PMBCountResults:
#            logging.info("%s : %s", k, scan_PMB.PMBCountResults[k])
        # logging.info("")   
        
        local_library.extraLogResult()
