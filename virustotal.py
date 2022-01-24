from vtapi3 import VirusTotalAPIIPAddresses, VirusTotalAPIError
import csv
import json
import time
import argparse

parse = argparse.ArgumentParser()
parse.add_argument('csv')
args = parse.parse_args()

#Paste API Key in the Config.txt file

with open('Config.txt') as config:
    vt_api_ip_addresses = VirusTotalAPIIPAddresses(str(config.read()))

start_time = time.time()

#utility function to convert list to string

def listToString(s):
    str1 = ""
    for ele in s:
        str1 += ele
    return str1

rows=[]

ipfile=str(args.csv)

with open(ipfile) as f:
    csvreader=csv.reader(f)
    for row in csvreader:
        rows.append(row)
    for i in range(len(rows)):
        x=rows[i]
        try:
            p=listToString(x)
            result = vt_api_ip_addresses.get_report(listToString(x))
        except VirusTotalAPIError as err:
            print(err, err.err_code)

        else:
            if vt_api_ip_addresses.get_last_http_error() == vt_api_ip_addresses.HTTP_OK:
                result = json.loads(result)
                result = json.dumps(result, sort_keys=False, indent=4)
            
        x=json.loads(result)
        tot_engine_c=0
        tot_detect_c=0
        result_eng=[]
        eng_name=[]
        try:
            dict_web=x["data"]["attributes"]["last_analysis_results"]
            for i in dict_web:
                tot_engine_c=1+tot_engine_c
                if dict_web[i]["category"]=="malicious" or dict_web[i]["category"]=="suspicious":
                    result_eng.append(dict_web[i]["result"])
                    eng_name.append(dict_web[i]["engine_name"])
                    tot_detect_c =1 + tot_detect_c
            res=[]
            for i in result_eng:
                if i not in res:
                    res.append(i)
            result_eng=res

            if tot_detect_c>0:
                print("%s was rated for " %p + str(result_eng) + " on " + str(tot_detect_c)+ " engines out of " + str(tot_engine_c) + " engines.")
                with open('results.csv', 'w', newline='') as b:
                    writer = csv.writer(b)
                    writer.writerow(["IP", "Categorization", "Score"])
                    writer.writerow([p, str(result_eng), str(tot_detect_c)])

            else:
                print("%s is " %p + "Non malicious")
                with open('results.csv', 'w', newline='') as b:
                    writer = csv.writer(b)
                    writer.writerow(["IP", "Categorization","Score"])
                    writer.writerow([p, "Non malicious/Clean", 0])
            
        except KeyError:
            print("YOU HAVE ENCOUNTERED AN ERROR AT THIS ENTRY IN THE CSV, PLEASE CHECK FOR ANY EMPTY CELLS IN BETWEEN")
print("Completed in %s seconds " % str(int(time.time() - start_time)))    