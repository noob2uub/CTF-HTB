Pyhton Code 

```
import requests
import hashlib
from bs4 import BeautifulSoup

try:
	req = requests.session()
	url = input("URL:\r\n>>> ")

	greq = req.get(url)
	html =greq.content

	soup = BeautifulSoup(html, 'html.parser')
	hval = soup.h3.get_text().encode('utf-8')

	hash = hashlib.md5(hval).hexdigest()
	data = dict(hash=hash)
	pres = req.post(url=url,data=data)
	print("Flag:\r\r\r\n",pres.text)
except Exception as e:
	print(e)
```

  Running the code to get the flag
  
  ```console 
  noob2uub@kali:~/ctf/htb/emdee$ python3 htbexploit.py 
URL:
>>> http://167.71.137.246:31878 
Flag:
 <html>
<head>
<title>emdee five for life</title>
</head>
<body style="background-color:powderblue;">
<h1 align='center'>MD5 encrypt this string</h1><h3 align='center'>WKRRi6VatCg5oXsA6JiA</h3><p align='center'>HTB{N1c3_ScrIpt1nG_B0i!}</p><center><form action="" method="post">
<input type="text" name="hash" placeholder="MD5" align='center'></input>
</br>
<input type="submit" value="Submit"></input>
</form></center>
</body>
</html>

```
