#!/usr/bin/python
# review office 365 audit csv
# requires ipaddress module installed https://docs.python.org/3/library/ipaddress.html
# requires https://ipstack.com API key
# tested on python v2.7.x, not tested on python v3.x
import os
import csv
import json
import urllib
import urllib2
import datetime
import ipaddress
from sys import argv
from pprint import pprint

switches = argv

class AP:
    def __init__(self, csv_file, verbose):
        self.key = '' # ipstack.com API key
        self.org_ip = '' # your organizations WAN IP (skips any logs with that IP)
        self.country = 'United States' # your country, any access from outside of this country will be reported as foreign
        self.known_ips_file = '/path/to/known_ips.json' # set your path, will be created if it doesn't exist
        
        self.csv_file = csv_file
        self.known_ip_data = self.read_json_data()
        self.known_ips = self.known_ip_data.keys()
        
        self.verbose = verbose
        
        self.get_csv_data()
    
    def not_org_ips(self, data):
        """Parses data and returns a list of JSON data with events not from your IP"""
        not_org = []
        for _ in data:
            cip = self.clean_and_validate_ip(_['ClientIP'])
            
            if cip == "continue":
                if self.verbose > 0:
                    pprint(_)
                    print("\n*"*5)
                    print("*** ERROR ***")
                    print("")
                continue
            
            try:
                if cip != self.org_ip:
                    not_org.append(_)
            except:
                pass
        
        return(not_org)
    
    def clean_and_validate_ip(self, cip):
        try:
            ipaddress.ip_address(unicode(cip))
            return(str(cip))
        except ValueError:
            if '[' in cip: # remove []:port from ipv6 address
                cip = cip.replace('[', '')
                cip = cip.replace(']', '')
                cip = cip.split(':')
                del(cip[-1])
                cip = ':'.join(cip)
            elif ':' in cip: # remove :port
                cip = cip.split(':')[0]
            else:
                print("")
                print("*** ERROR EXTRACTING IP ***")
                if self.verbose > 0:
                    print("*\n"*5)
                return("continue")
            return(str(cip))
        except:
            print("")
            print("*** ERROR VALIDATING IP ***")
            if self.verbose > 0:
                print("*\n"*5)
            return("continue")

    def unique_ips(self, not_org):
        """Parses the JSON list of non-organization WAN IPs and prints and returns all unique IPs"""
        ips = []
        
        for _ in not_org:
            cip = self.clean_and_validate_ip(_['ClientIP'])
            ips.append(cip)
            
        ips = set(ips)
        
        return(ips)

    def get_ip_geo(self, ip):
        print("calling ipstack...")
        ip_info = {}
        
        base_url = 'http://api.ipstack.com'
        url = '{0}/{1}?access_key={2}'.format(base_url, ip, self.key)
        
        try:
            page = urllib2.urlopen(url)
        except:
            print("{0!r}".format(ip))
            print(url)
            exit()
        
        data = json.loads(page.read())
        page.close()
        
        ip_info = {ip: {
            'city':data['city'],
            'country':data['country_name'],
            'region':data['region_name']
        }}
        
        return(ip_info)

    def write_json_data(self):
        with open(self.known_ips_file, 'w') as file:
            file.write(json.dumps(self.known_ip_data, file, indent=4))

    def read_json_data(self):
        if not os.path.isfile(self.known_ips_file):
            return({})
        with open(self.known_ips_file, 'r') as file:
            data = json.loads(file.read())
        
        return(data)
    
    def update_json_data(self, ip):
        if ip in self.known_ips:
            pass
        else:
            ip_info = self.get_ip_geo(ip)
            self.known_ip_data.update(ip_info)
            self.write_json_data()
    
    def get_csv_data(self):
        # read office 365 csv audit log
        with open(self.csv_file) as c:
            reader = csv.reader(c)
            next(reader)
            csv_data = [r for r in reader]

        # pull out the actual data column into a json array
        self.audit_data = []
        for _ in csv_data:
            try:
                json_data = json.loads(_[-1])
            except:
                continue
                exit(0)
            
            if 'ClientIP' not in json_data: # skips if the log doesn't contain and IP
                pass
            else:
                self.audit_data.append(json_data)
            
        self.not_org = self.not_org_ips(self.audit_data) # creates a list of json data that has an IP that doesn't belong to your org
        self.unique_audit_ips = self.unique_ips(self.not_org) # prints and returns a list of unique IPs that don't belong to your org
        
        for ip in self.unique_audit_ips:
            self.update_json_data(ip)
    
    def parse_audit_log(self):
        foreign_result = 0
        foreign_succ = 0
        foreign_fail = 0
        foreign_other = 0
        local_result = 0
        for log in self.not_org:
            ip = self.clean_and_validate_ip(log['ClientIP'])
            
            if self.known_ip_data[ip]['country'] == self.country:
                local_result += 1
                pass
            else:
                print("")
                print("IP not in {0}: {1}".format(self.country, ip))
                
                raw_date_time = log['CreationTime']
                date_time = datetime.datetime.strptime(raw_date_time, '%Y-%m-%dT%H:%M:%S')
                print("\tDate: {0}".format(date_time))
                
                print("\tUser: {0}".format(log['UserId']))
                
                for _ in self.known_ip_data[ip].keys():
                    v = self.known_ip_data[ip][_]
                    if v == None: # hack around trying to utf-8 encode
                        pass
                    else:
                        v = v.encode('utf-8')
                    print("\t{0}:  {1}".format(_, v))
                print("\tOperation: {0}".format(log['Operation']))
                print("\tResult---: {0}".format(log['ResultStatus'].upper()))
                
                if log['ResultStatus'].lower() == 'succeeded':
                    foreign_succ += 1
                elif log['ResultStatus'].lower() == 'failed':
                    foreign_fail += 1
                else:
                    foreign_other += 1
                
                foreign_result += 1
                
                if self.verbose > 1:
                    pprint(log)
                
        
        if foreign_result != 0:
            print(" ")
            print("Foreign access: {0}, {1} access: {2}".format(foreign_result, self.country, local_result))
            print("Foreign success: {0}, foreign failure: {1}, foreign other: {2}".format(foreign_succ, foreign_fail, foreign_other))
            print("")
        else:
            print("")
            print("Everything looks good here!")
            print("")
            

def switch(item):
    try:
        index = switches.index(item) + 1
        return(switches[index])
    except IndexError:
        print("Invalid arguments, exiting...")
        exit(0)

def _help():
    print("")
    print("365_audit.py help:")
    print("Usage: 365_audit.py -l /path/to/log.csv -vv")
    print("\t-l\tspecifies the path to the log file (required)")
    print("\t-v\tprints the log when it can't validate or extract the ip")
    print("\t-vv\tsame as -v and prints the log when there's foreign access")
    print("")
    exit(0)



if __name__ == '__main__':
    if '-h' in argv:
        _help()
    if '--help' in argv:
        _help()
    
    if '-v' in argv:
        verbose = 1
    elif '-vv' in argv:
        verbose = 2
    else:
        verbose = 0
    
    if '-l' in argv:
        csv_file = switch('-l')
        ap = AP(csv_file, verbose)
    else:
        print("")
        print("Please use -l [log file].")
        _help()
    
    ap.parse_audit_log()
