# Virustotal-scrapper

To upload file to virustotal and get the results without API

## Installation

```
pip3 install https://github.com/Brijeshkrishna/virustotal-scrapper
```
# Usage
### Import module

```python
from vt import Visustotal
```

### File upload

```python
vt= Visustotal()
vt.upload_file(file name)
```
returns a SHA256 Hash ( file id ) using that you can check the details of the file 

```
https://www.virustotal.com/gui/file/file-hash
```

## Url upload
```python
vt.upload_url(url)
```
returns a id , using that you can check the details of the website 

```
https://www.virustotal.com/gui/url/id
```

