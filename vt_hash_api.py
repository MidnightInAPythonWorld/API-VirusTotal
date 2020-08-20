#!/usr/bin/env python
__author__ = 'MidnightInAPythonWorld'

# Check for Python3
import sys
if sys.version_info[0] != 3:
    print("[-] VirusTotal API Hash Checker requires Python 3")
    print("[-] Exiting script")
    exit()

# stdlib
import requests,json,csv,os,random,time,re,argparse


# pypi
try:
    import pandas as pd
except:
    print('[!] This script Requires Pandas to write results to CSV.')
    print('[!] To install Pandas on Linux: python3 -m pip install pandas --user')
    exit()


### Import VirusTotal hashes
def hash_data_import(input_hash_csv_filename):
    data= []
    with open(input_hash_csv_filename, 'r') as fh:
        fhReader = csv.reader(fh, delimiter=',')
        for row in fhReader:
            hash = row[0]
            data.append(hash)
    return data


### Below header is used for making the request look like a normal browswer.  
### This is required to make the requests look like normal web traffic.
### This could be required to pass proxy filtering that might be occurring on network.  
normal_headers = {}
normal_headers['Accept'] = 'application/json'
normal_headers['Accept-Language'] = 'en-US'
normal_headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36'
normal_headers['Accept-Encoding'] = 'gzip, deflate'
normal_headers['Connection'] = 'Keep-Alive'


### Below is the base URL and params used to make a request to the VirusTotal API.  
### VirusTotal API is documented here: https://developers.virustotal.com/reference#file-report


### Hash Checker to validate characters and length
def hash_verification(hash):
    """This function is used to validate MD5,SHA1, and SHA256 hashes prior to submitting to VirusTotal API.
    """   
    md5 = re.findall(r'^[a-fA-F0-9]{32}$',hash)
    sha1 = re.findall(r'^[a-fA-F0-9]{40}$',hash)
    sha256 = re.findall(r'^[a-fA-F0-9]{64}$',hash)
    if md5 or sha1 or sha256:
        return True


def virus_total_hash(hash, params, output_csv_filename):
    """This function is used to query the VirusTotal API for MD5,SHA1, and SHA256 hashes.
    """
    hash_checker = hash_verification(hash)
    if hash_checker:
        print('[*] Successfully verified Hash format for:', hash)
        print('[*] Attempting VirusTotal API request for hash:', hash)
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params['resource']=hash
        try:
            response = requests.get(url, headers=normal_headers, params=params, timeout=15.000, verify=True)
            df = pd.DataFrame(response.json())
            # if file does not exist write header 
            if not os.path.isfile(output_csv_filename):
                df.to_csv(output_csv_filename)
            else: # else file exists so append data without writing the header
                df.to_csv(output_csv_filename, mode='a', header=False)
            print('[*] Successfully queried VirusTotal for hash:', hash)
        except:
            print("[!] Failed to fetch:", url)
    else:
        print("[!] Failed to validate hash:", hash)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('input_hash_csv_filename', help='The name of input CSV file containing hashes to submit to VirusTotal API.')
    parser.add_argument('output_csv_filename', help='The name of the output CSV filename. The VirusTotal API results will be written to this file.')
    parser.add_argument('virustotal_api_key', help='The API key used to query VirusTotal API.')
    args=parser.parse_args()
    hash_lst = hash_data_import(args.input_hash_csv_filename)
    params = {}
    params['apikey'] = args.virustotal_api_key
    for hash in hash_lst:
        virus_total_hash(hash, params, args.output_csv_filename)
        delay = random.randint(15, 20)
        print('[*] Next Query in:', delay ,"seconds")
        print('[*]')
        time.sleep(delay)


if __name__== "__main__":
    main()


exit()

