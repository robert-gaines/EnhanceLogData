#!/usr/bin/env python3

_AUTH_='RWG' # 03102022

from fiaclient import fiaclient
import sqlite3 as sqlite
import ipaddress
import requests
import time

class ReportMethods():

    def GenReportName(self,title):
        report_name = ''
        report_name = title+"_"
        timestamp = time.ctime()
        replace_colons = timestamp.replace(":",'_')
        final_timestamp = replace_colons.replace(" ","_")
        final_timestamp += ".xlsx"
        report_name += final_timestamp
        return report_name

    def WriteHeaders(self,col_header_list,current_worksheet):
        limit =len(col_header_list)
        chars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
        current_iter = 0
        alpha_iter = 0
        secondary_iter = 0
        col_index = 1
        secondary_index = 0
        while(current_iter < limit-1):
            char_index = 0
            if(current_iter == limit):
                break
            while(alpha_iter <= 25):
                if(current_iter == limit):
                    break
                if(current_iter > 25):
                    write_index = chars[secondary_index]+chars[alpha_iter]+str(col_index)
                    current_worksheet.write(write_index,col_header_list[current_iter])
                if(current_iter <= 25):
                    write_index = chars[char_index]+str(col_index)
                    current_worksheet.write(write_index,col_header_list[current_iter])
                current_iter += 1 ; char_index += 1 ; alpha_iter += 1
            if(current_iter > 50):
                secondary_index += 1
            char_index = 0
            alpha_iter = 0

    def WriteEntry(self,row_index,entry,current_worksheet):
        chars = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
        current_iter = 0
        alpha_iter = 0
        secondary_iter = 0
        secondary_index = 0
        limit = len(entry)
        while(current_iter < limit-1):
            char_index = 0
            if(current_iter == limit):
                break
            while(alpha_iter <= 25):
                if(current_iter == limit):
                    break
                if(current_iter > 25):
                    write_index = chars[secondary_index]+chars[alpha_iter]+str(row_index)
                    write_value = str(entry[current_iter])
                    current_worksheet.write(write_index,write_value)
                if(current_iter <= 25):
                    write_index = chars[alpha_iter]+str(row_index)
                    write_value = str(entry[current_iter])
                    current_worksheet.write(write_index,write_value)
                current_iter += 1 ; char_index += 1 ; alpha_iter += 1
            if(current_iter > 50):
                secondary_index += 1
            char_index = 0
            alpha_iter = 0
        current_iter  = 0

    def DetectPrivateIP(self,subject_address):
        #
        private = ipaddress.ip_address(subject_address).is_private
        #
        return private

    def FIAQuery(self,fia_host,tgt_addr):
        #
        client = fiaclient.FIAClient(fia_url="http://{0}:8000/".format(fia_host))
        result = client.search(payload=[tgt_addr])
        results = result['results']
        if(results == []):
            fia_response = None
        else:
            categories   = results[0]['categories']
            hit_count    = results[0]['hits_count']
            blacklisted  = results[0]['currently_blacklisted']
            hits         = results[0]['hits']
            feedname     = hits[0]['feed_name']
            src_date     = hits[0]['source_file_date']
            #
            fia_response = [categories,hit_count,blacklisted,feedname,src_date] 
            #
            return fia_response

    def QueryApiaryBGP(self,addr):
        #
        url       = "https://api.bgpview.io/ip/{0}".format(addr)
        request   = requests.get(url=url,timeout=3)
        data      = request.json()
        prefixes  = data['data']['prefixes']
        asn       = prefixes[0]['asn']['asn']
        rir       = data['data']['rir_allocation']['rir_name'] 
        ret_value = [rir,asn]
        return ret_value

    def QueryIPV4(self,connection,subject_ipaddress):
        candidate_ranges = {}
        addr_segments = subject_ipaddress.split('.')
        unique_octets_with_wildcard_opr = addr_segments[0]+'.'+addr_segments[1]+'%.%'
        cursor = connection.cursor()
        sql_query = "SELECT * FROM IPV4GEODATA WHERE network like '%s' " % unique_octets_with_wildcard_opr 
        cursor.execute(sql_query)
        query_results = cursor.fetchall()
        for q in query_results:
            entry   = q[0]
            network = q[2]
            candidate_ranges[entry] = list(ipaddress.ip_network(network))
        subject_ipaddress = ipaddress.IPv4Address(subject_ipaddress)
        matching_entry = ''
        for addr_range in candidate_ranges:
            if(subject_ipaddress in candidate_ranges[addr_range]):
                print("[*] Located: %s:%s " % (subject_ipaddress,addr_range))
                matching_entry = addr_range
        if(matching_entry == ''):
            print("[!] Failed to identify a corresponding address range within the database")
            return
        else:
            geo_query = "SELECT * FROM IPV4GEODATA WHERE entry_id='%s' " % matching_entry
            cursor.execute(geo_query)
            geo_query_results = cursor.fetchall()
            geo_query_results = list(geo_query_results)
            geoname_id = geo_query_results[0][1]
            network_range = geo_query_results[0][2]
            postal_code   = geo_query_results[0][3]
            latitude      = geo_query_results[0][4]
            longitude     = geo_query_results[0][5]
            accuracy      = geo_query_results[0][6]
            #
            print("[~] Querying city database for geoname ID: %i " % geoname_id)
            #
            try:
                city_data_connection = sqlite.connect('ip_geodata.db')
                city_cursor = city_data_connection.cursor()
                city_query = "SELECT * FROM CITYDATA WHERE geoname_id='%i' " %  geoname_id 
                city_cursor.execute(city_query)
                city_query_results = city_cursor.fetchall()
                city_query_results = list(city_query_results)
                continent = city_query_results[0][2]
                country   = city_query_results[0][3]
                city      = city_query_results[0][4]
                timezone  = city_query_results[0][5]
                #
                results = [subject_ipaddress,network_range,postal_code,latitude,longitude,accuracy,continent,country,city,timezone]
                #
                return results
                #
            except Exception as e:
                #
                print("[!] Failed to connect to the city database: %s " % e)
                #
                return