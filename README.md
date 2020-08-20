# VirusTotal-API

This script is used for querying the VirusTotal API for MD5, SHA1, or SHA256 hashes using the Free API Key.  
 
To run this VirusTotal API script, perform the following:

    python3 vt_hash_api.py input output api_key
    

Below are the arguements that need to be passed to the script:

    input = the input filename that contains the MD5, SHA1, or SHA256 hashes
    output = the CSV filename that the results will be written to
    api_key = you guessed it
    

The script has a time delay in between requests so daily limits don't get exceeded should you want to check a large list of hashes.

VirusTotal is rate limiting based on the following numbers:

    Request rate 4 requests/minute
    Daily quota 1000 requests/day
    Monthly quota 30000 requests/month 


After the script completes, a CSV file will be written to the current working directory with the results of the API call.

This specific VirusTotal API is documented here: 
https://developers.virustotal.com/reference#file-report

