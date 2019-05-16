'''
Created on Mar 29, 2019

@author: TKA
'''

# import cast.analysers.dotnet
import cast.analysers.ua
import cast.analysers.log as LOG


class sactivator(cast.analysers.ua.Extension):

    def __init__(self):
        self.fielPath = ""
               
    def start_analysis(self):
        LOG.info('Successfully C/C++ Analyzer Started')
    
    def end_analysis(self):
        LOG.info("C/C++ Analyzer  Ended")
        
   
