
import argparse
import hashlib
import os
import sys
from dotenv import load_dotenv
import requests
import os
import sys
import time
import json

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_API_URL = os.getenv("VIRUSTOTAL_API_URL")
VIRUSTOTAL_API_URL_SCAN = os.getenv("VIRUSTOTAL_API_URL_SCAN")
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class VirusScanner:
    def __init__(self):
        self.headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "User-Agent": "VirusScanner v1.0",
            "Accept-Encoding": "gzip, deflate",
        }

    def upload(self, file_path):
        print (Colors.BLUE + "[+] File To Be Uploaded: "+ file_path + Colors.END)
        self.file_path = file_path

        upload_url = VIRUSTOTAL_API_URL + "files"

        filesize = os.path.getsize(file_path)
        if filesize > 32 * 1024 * 1024:  # 32 MB
            headers = {"x-apikey": VIRUSTOTAL_API_KEY,"accept": "application/json"}
            response = requests.get(upload_url+"/upload_url", headers=headers)
            if response.status_code == 200:
                upload_url = response.json().get("data")

        # Extracting exact file name from file_path
        # and opening the file in binary read mode, ensuring file path is absolute
        fileName = os.path.basename(file_path)
        files = {
            "file": (
                fileName,
                open(os.path.abspath(file_path), "rb"),
            )
        }

        print(Colors.YELLOW + f"[+] Uploading {fileName} To VirusTotal..." + Colors.END)
        response = requests.post(upload_url, headers=self.headers, files=files)
        if response.status_code == 200:
            result = response.json()
            self.id = result.get("data").get("id")
            print(Colors.YELLOW + f"[i] FileID: {self.id}" + Colors.END)
            print(Colors.GREEN + f"[i] Upload Successful!" + Colors.END)
        elif response.status_code == 409:
            error = response.json().get("error", {})
            self.id = error.get("resource", {}).get("id")
            print(Colors.YELLOW + f"[i] File Already Exists! FileID: {self.id}" + Colors.END)
        else:
            print(Colors.RED + f"[-] Upload for {fileName} Failed! Status Code: {response.status_code}")
            sys.exit()

    def analyze(self):
        print(Colors.BLUE+"[+] Getting Analysis Report..." + Colors.END)
        analysis_url = VIRUSTOTAL_API_URL + f"analyses/{self.id}"
        response = requests.get(analysis_url, headers=self.headers)
        if response.status_code == 200:
            result = response.json()
            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                maliciousFound = False
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                print(Colors.RED + "Malicious: "+ str(stats.get("malicious")) + Colors.END)
                print(Colors.GREEN + "Suspicious: "+ str(stats.get("suspicious")) + Colors.END)
                print(Colors.YELLOW + "Undetected: "+ str(stats.get("undetected")) + Colors.END)
                print(Colors.PURPLE + "Total: "+ str(stats.get("total")) + Colors.END + "\n")
                for r in results:
                    if results[r].get("category") == "malicious":
                        maliciousFound = True
                        print("================================================")
                        print(Colors.GREEN+ results[r].get("engine_name") + Colors.END)
                        print("version: "+ results[r].get("engine_version"))
                        print("category: "+ results[r].get("category"))
                        print("result: "+Colors.RED+ results[r].get("result") + Colors.END)
                        print("method: "+results[r].get("method"))
                        print("update: "+results[r].get("engine_update"))
                        print("================================================\n")
                if maliciousFound:
                    print(Colors.RED+"[i] MALICIOUS CONTENT FOUND!"+Colors.END)
                else:
                    print(Colors.GREEN + "[i] Analysis Successfull! Everything is clean." + Colors.END)
                sys.exit()
            elif status == "queued":
                print(Colors.YELLOW + "[i] Analysis Queued. Please Wait..." + Colors.END)
                #with open(os.path.abspath(self.file_path), "rb") as file:
                #    binary = file.read()
                #    hashsum = hashlib.sha256(binary).hexdigest()
                #    self.info(hashsum)
                while True:
                    resp = requests.get(analysis_url, headers=self.headers)
                    resp.raise_for_status()
                    status = resp.json()["data"]["attributes"]["status"]
                    if status == "completed":
                        return self.analyze()
                    print(Colors.YELLOW + "[i] Still queued, retrying in 5s…" + Colors.END)
                    time.sleep(5)
            else:
                print(Colors.RED + "[-] Analysis Failed! Status Code: " + response.status_code + Colors.END)
                sys.exit()
            
    def run(self, file_path):
        self.upload(file_path)
        self.analyze()

    def run_url(self, url):
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
        }
        print (Colors.BLUE + "[+] URL To Be Scanned: "+ url + Colors.END)
        response = requests.post(VIRUSTOTAL_API_URL_SCAN, headers=headers, data={"url": url})
        if response.status_code == 200:
            result = response.json()
            self.id = result.get("data", {}).get("id")
            print(Colors.YELLOW + f"[i] URL: {self.id}" + Colors.END)
            print(Colors.GREEN + f"[i] URL Upload Successful!" + Colors.END)
            self.analyze()
            
    def info(self, file_hash):
        print(Colors.BLUE+f" [i] Got file info by ID: "+file_hash+Colors.END)
        info_url = VIRUSTOTAL_API_URL+"files/"+file_hash

        maliciousFound = False

        response = requests.get(info_url, headers=self.headers)
        if response.status_code == 200:
            result = response.json()
            if result.get("data").get("attributes").get("last_analysis_results"):
                stats = result.get("data").get("attributes").get("last_analysis_stats")
                results = result.get("data").get("attributes").get("last_analysis_results")
                print(Colors.RED + "Malicious: "+ str(stats.get("malicious")) + Colors.END)
                print(Colors.GREEN + "Suspicious: "+ str(stats.get("suspicious")) + Colors.END)
                print(Colors.YELLOW + "Undetected: "+ str(stats.get("undetected")) + Colors.END)
                print(Colors.PURPLE + "Total: "+ str(stats.get("total")) + Colors.END + "\n")
                for r in results:
                    if results[r].get("category") == "malicious":
                        maliciousFound = True
                        print("================================================")
                        print(Colors.GREEN+ results[r].get("engine_name") + Colors.END)
                        print("version: "+ results[r].get("engine_version"))
                        print("category: "+ results[r].get("category"))
                        print("result: "+Colors.RED+ results[r].get("result") + Colors.END)
                        print("method: "+results[r].get("method"))
                        print("update: "+results[r].get("engine_update"))
                        print("================================================\n")

                if maliciousFound:
                    print(Colors.RED+"[i] MALICIOUS CONTENT FOUND!"+Colors.END)
                else:
                    print(Colors.GREEN + "[i] Analysis Successfull! Everything is clean." + Colors.END)
                sys.exit()
            else:
                print(Colors.RED + f"[-] Analysis Failed! No last_analysis_results. Status Code: {response.status_code}"+ Colors.END)
        else:
            print(Colors.RED + f"[-] Analysis Failed! Status Code: {response.status_code}"+ Colors.END)
            sys.exit()
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    #parser.add_argument('-m', '--malw', required = True, help ='Provide file path for analysis')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-m", "--malw",
        help='Provide a file path for analysis'
    )
    group.add_argument(
        "-u", "--url",
        help='Provide a URL for analysis'
    )
    args = vars(parser.parse_args())
    virusScanner = VirusScanner()
    #virusScanner.run(args["malw"])
    if args["malw"]:
        virusScanner.run(args["malw"])
    else:
        virusScanner.run_url(args["url"])


