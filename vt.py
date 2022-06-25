import requests
import hashlib
import random
import string
import rich 

def random_header_id():
       return (''.join(random.choice(string.ascii_letters) for x in range(59)))+"=="

headers_for_id = {
        "X-Tool": "vt-ui-main",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.53 Safari/537.36",
    "content-type": "application/json",
    "x-app-version": "v1x98x0",
    "accept": "application/json",
    "Referer": "https://www.virustotal.com/",
    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
    "X-VT-Anti-Abuse-Header": random_header_id()
    }

headers = {
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
    "x-vt-anti-abuse-header": random_header_id(),
}


def get_url(session:requests.Session=requests.Session()):
    reqUrl = "https://www.virustotal.com/ui/files/upload_url"
    response = session.get( reqUrl,  headers=headers_for_id)
    if response.ok:
        return response.text[15:-3]
    else:
        raise("Invalid response: %s" % response.status_code)

def get_file_hash(filename):
    with open(filename, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def check_file_exist(hash,session:requests.Session=requests.Session()):
    response = session.get(f"https://www.virustotal.com/ui/file/{hash}",headers=headers,allow_redirects=0) 
    
    return response.ok 
        


def upload_vt(filename,verbos=False):
    if check_file_exist("a8be611542908105bb56bc4527cf7e186f22e0c4f7959c732cccfdfc928d12cd"):
        return 1

    rich.print("[blue]Geting Uploaded link[/blue]\r") if verbos else None
    url =get_url()    
    rich.print("[green]Uploaded link got.[/green]\r") if verbos else None
    rich.print("[blue]Uploading file to virustotal[/blue]") if verbos else None
    response = requests.post(
        url,
        cookies={
            "VT_PREFERRED_LANGUAGE": "en",
        },
        headers=headers,
        files={"file": open(filename, "rb")},
    )
    file_hash = get_file_hash(filename)
    if response.ok:
        rich.print("[green]Uploading file to virustotal successful[/green]") if verbos else None
        return file_hash
    else:
        rich.print("[red]Uploaded failed: %s[red]" % response.status_code) if verbos else None
        return None




