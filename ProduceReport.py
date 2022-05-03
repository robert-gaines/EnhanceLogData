#!/usr/bin/env python3

_AUTH_='RWG' # 03102022

from concurrent.futures import thread
from fiaclient import fiaclient
from ReportMethods import *
import sqlite3 as sqlite
import xlsxwriter
import requests
import time
import json
import sys
import os
import re

class Report():

    '''
    Instantiation sequence establishes:
    -> SQLite connection with GeoIP Database
    -> XLSX Workbook
    '''
    def __init__(self,fia_server):
        try:
            self.db_conn = sqlite.connect('ip_geodata.db')
        except:
            print("[!] GEO IP Database connection failed, departing")
            sys.exit(1)
        self.fia_server = fia_server
        self.output_filename = ReportMethods.GenReportName(self,"Log_Intel_")
        self.workbook = xlsxwriter.Workbook(self.output_filename)
        self.worksheet = self.workbook.add_worksheet('Enhanced Log Data')
        # Workbook Column Headers
        self.column_headers = [
                                "Event Time",
                                "Event ID",
                                "Action",
                                "Source IP",
                                "Source Network Range",
                                "Source Port",
                                "Source RIR",
                                "Source ASN",
                                "Source Country",
                                "Source City",
                                "Threat Category",
                                "Hit Count",
                                "Blacklisted",
                                "Source Feed",
                                "Threat Classification Date"
                              ]
        ReportMethods.WriteHeaders(self,self.column_headers,self.worksheet)
        #
        print("[~] Listing candidate files...") # Lists the current directory
        #
        check_directory = os.listdir()
        for item in range(0,len(check_directory)-1):
            print(item,")",check_directory[item])
        log_file_index = int(input("[+] Enter the index that corresponds to the subject log file-> "))
        if(check_directory[log_file_index]):
            print("[*] Valid selection: %s " % check_directory[log_file_index])
            self.subject_file = check_directory[log_file_index]
        else:
            print("[!] Invalid selection, departing ")
            sys.exit(1)

    # Performs a search of a single log row for a specific value
    def ProcessEntry(self,tgt_str,str_key):
        ret_value = ""
        if(str_key in tgt_str):
            key_index    = 0
            start_index  = tgt_str.index(str_key) 
            current_char = tgt_str[start_index]
            while(current_char != "="):
                start_index += 1
                current_char = tgt_str[start_index]
            while(current_char != ' '):
                start_index += 1
                current_char = tgt_str[start_index]
                if(current_char != '"'):
                    ret_value += current_char
            return ret_value

    # Queries a log entry for port data
    def ProcessPort(self,tgt_str,str_key):
        ret_value = ""
        if(str_key in tgt_str):
            key_index    = 0
            start_index  = tgt_str.index(str_key) 
            current_char = tgt_str[start_index]
            while(current_char != "="):
                start_index += 1
                current_char = tgt_str[start_index]
            start_index += 1
            current_char = tgt_str[start_index]
            while(current_char != ' '):
                start_index += 1
                current_char = tgt_str[start_index]
                if(current_char != '"'):
                    ret_value += current_char
            return ret_value

    # queries a log entry for the device's identity
    def ProcessDeviceName(self,tgt_str,str_key):
        ret_value = ""
        if(str_key in tgt_str):
            key_index    = 0
            start_index  = tgt_str.index(str_key) 
            current_char = tgt_str[start_index]
            while(current_char != "="):
                start_index += 1
                current_char = tgt_str[start_index]
            start_index += 1
            current_char = tgt_str[start_index]
            while(current_char != '"'):
                start_index += 1
                current_char = tgt_str[start_index]
                if(current_char != '"'):
                    ret_value += current_char
            return ret_value

    # Searches a log entry for event data
    def ProcessMessage(self,tgt_str,str_key):
        ret_value = ""
        if(str_key in tgt_str):
            start_index  = tgt_str.index(str_key) 
            current_char = tgt_str[start_index]
            while(current_char != "="):
                start_index += 1
                current_char = tgt_str[start_index]
            start_index += 1
            current_char = tgt_str[start_index]
            while(current_char != '"'):
                start_index += 1
                current_char = tgt_str[start_index]
                if(current_char != '"'):
                    ret_value += current_char
            return ret_value

    # Ingests and processes log file entries
    def ProcessFile(self):
        #
        evt_time    = ''
        evt_id      = ''
        action      = ''
        src_prt     = ''
        src_ip      = ''
        src_rng     = ''
        src_asn     = ''
        src_rir     = ''
        src_ctr     = ''
        src_cty     = ''
        thr_cat     = ''
        hit_cnt     = ''
        blklstd     = ''
        srcfeed     = ''
        thr_dte     = ''
        #
        fileObject = open(self.subject_file)
        #
        line =  fileObject.readline()
        reg_exp = re.compile(r'([\S]+=)',re.VERBOSE)
        matches = reg_exp.findall(line)
        if(matches):
            refined_matches = []
            for m in matches:
                temp = m.lstrip("'")
                temp = m.rstrip("=")
                refined_matches.append(temp)
        else:
            return
            # 
        row_index = 2
        #
        for line in fileObject.readlines():
            if("id" in refined_matches):
                evt_id = self.ProcessEntry(line,"id") 
            if("time" in refined_matches):
                evt_time = self.ProcessEntry(line,"time") 
            if("action" in refined_matches):
                action = self.ProcessEntry(line,"action")
            if("srcport" in refined_matches):
                src_prt = self.ProcessPort(line,"srcport")
            if("srcip" in refined_matches):
                src_ip = self.ProcessEntry(line,"srcip")
                src_ip = src_ip.rstrip(' ')
                if(src_ip is not None):
                    is_private = ReportMethods.DetectPrivateIP(self,src_ip)
                    if(is_private == True):
                        src_rng     = "Private"
                        src_asn     = "Private"
                        src_rir     = "Private"
                        src_ctr     = "Private"
                        src_cty     = "Private"
                    if(is_private == False):
                        # GeoIP Database Query
                        geo_ip_data = ReportMethods.QueryIPV4(self,self.db_conn,src_ip)
                        # API Call to Apiary - rate limiting is not evident at the time of writing
                        bgp_data    = ReportMethods.QueryApiaryBGP(self,src_ip)
                        if(bgp_data is not None):
                            src_asn     = bgp_data[1]
                            src_rir     = bgp_data[0]
                        else:
                            src_asn     = 'Unknown'
                            src_rir     = 'Unknown'
                        src_rng     = geo_ip_data[1]
                        src_ctr     = geo_ip_data[7]
                        src_cty     = geo_ip_data[8]
                        #
            # Query the aggregator container for reputation data
            # Returns the first valid entry or yields 'No data'
            threat_feed_data = ReportMethods.FIAQuery(self,self.fia_server,src_ip)
            if(threat_feed_data is not None):
                thr_cat     = threat_feed_data[0]
                hit_cnt     = threat_feed_data[1]
                blklstd     = threat_feed_data[2]
                srcfeed     = threat_feed_data[3]
                thr_dte     = threat_feed_data[4]
                #
            else:
                thr_cat     = 'No Data'
                hit_cnt     = 'No Data'
                blklstd     = 'No Data'
                srcfeed     = 'No Data'
                thr_dte     = 'No Data'
            entry = [evt_time,evt_id,action,src_ip,src_rng,src_prt,src_rir,src_asn,src_ctr,src_cty,thr_cat,hit_cnt,blklstd,srcfeed,thr_dte]
            #print(entry)
            # populate a row in the Excel workbook with the results
            ReportMethods.WriteEntry(self,row_index,entry,self.worksheet)
            row_index += 1
        self.workbook.close()

if(__name__ == '__main__'):
    print("Log Data Enhancement Script")
    print("---------------------------")
    FireHOL_aggregator_address = input("[+] Enter the IP for the FireHOL aggregator instance-> ")
    report = Report(FireHOL_aggregator_address)
    report.ProcessFile()

