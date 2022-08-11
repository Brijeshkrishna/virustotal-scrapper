import requests
import hashlib
from vt.core.funtions import *
import urllib.parse

class Virustotal:
    def __init__(self):
        self.session = requests.Session()
        self.update_headers()


    def update_headers(self):
        self.x_vt_header = random_header_id()
        self.basic_header = {
            "X-Tool": "vt-ui-main",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
            "content-type": "application/json",
            "x-app-version": "v1x98x0",
            "accept": "application/json",
            "Referer": "https://www.virustotal.com/",
            "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
            "X-VT-Anti-Abuse-Header": self.x_vt_header,
        }

        self.upload_headers = {
            "authority": "www.virustotal.com",
            "accept": "*/*",
            "accept-ianguage": "en-US,en;q=0.9,es;q=0.8",
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
            "cookie": "VT_PREFERRED_LANGUAGE=en",
            "origin": "https://www.virustotal.com",
            "referer": "https://www.virustotal.com/",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "sec-gpc": "1",
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
            "x-app-version": "v1x98x0",
            "x-tool": "vt-ui-main",
            "x-vt-anti-abuse-header": self.x_vt_header,
        }

    def check_file_exist(self, file_hash):
        response = self.session.get(
            f"https://www.virustotal.com/ui/files/{file_hash}",
            headers=self.upload_headers,
            allow_redirects=False
        ) 
        
        return 1 if response.status_code == 200 else 0

    def upload_file(self, filename, force=False):
        if self.check_file_exist(self.get_file_hash(filename)) and not force:
            return self.get_file_hash(filename)

        upload_url = self.get_upload_url()

        response = requests.post(
            upload_url,
            cookies={
                "VT_PREFERRED_LANGUAGE": "en",
            },
            headers=self.upload_headers,
            files={"file": open(filename, "rb")},
        )

        if response.status_code == 200:
            return self.get_file_hash(filename=filename)
        else:
            return 0

    def get_upload_url(self):
        response = self.session.get(
            "https://www.virustotal.com/ui/files/upload_url", headers=self.basic_header
        )
        if response.ok:
            return response.text[15:-3]
        else:
            raise f"Invalid response: {response.status_code}"
    

    def upload_url(self, url):            
        url_id = self.session.post("https://www.virustotal.com/ui/urls", data= f"url={urllib.parse.quote_plus(url)}",headers=self.upload_headers)
        if url_id.ok:
            url_id =url_id.json()['data']['id']
            response = self.session.get(f"https://www.virustotal.com/ui/analyses/{url_id}",headers=self.upload_headers)
            if response.ok:
                return url_id[2:66]
            else:
                raise f"Error in validing the URL {url}"
        else :
            raise "Error in uploading url"
        
    def check_url_exists(self, url):
        return 0 if self.session.get(f"https://www.virustotal.com/ui/search?query={urllib.parse.quote_plus(url)}",headers=self.upload_headers).json()['data'] == [] else 1
    
    @staticmethod
    def get_file_hash(filename):
        with open(filename, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def file_info(self,file_hash):

        if  not self.check_file_exist(file_hash):
            return None

        return file_info_fill(self.session.get(f"https://www.virustotal.com/ui/files/{file_hash}",headers=self.upload_headers).json())

    def url_info(self,url_hash):
        
        if not self.check_file_exist(url_hash):
            return None

        return self.session.get(f"https://www.virustotal.com/ui/urls/{url_hash}",headers=self.upload_headers).json()


