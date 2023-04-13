# -*- coding:utf-8 -*-
import os
import importlib
import threading

#手动导入插件
#from plugins.CVE_2014_3704 import *

#获取扫描插件名称
def get_modules(pluginspath):
	modules = []
	files  = os.listdir(pluginspath)
	for file in files:
		if not file.startswith("__"):#排除缓存文件
			module_name = file[:-3] #去除文件扩展名
			modules.append(module_name)
	return modules
	
#调用检测模块相应函数 
def check(mod,mod_name,ip,port):
	try:
		#mod  = auto_import()
		res = mod.check_vuln(ip,port)
		#print(ip+":"+str(port))
		if res == True:#根据模块返回值判断是否存在漏洞
			print("{mod_name}->{ip}:{port}->vuln exists".format(mod_name=mod_name,ip=ip,port=port))
			res_output(mod_name,ip,port,'vuln exists\n') #若存在漏洞则输出结果至文档
			
		else:
			pass
			#print("{mod_name}->{ip}:{port}->No vuln".format(mod_name=mod_name,ip=ip,port=port))
			#res_output(mod_name,ip,port,'No vuln\n')
	except Exception as msg:
		#print(msg)
		return Flase

#自动导入模块并检测漏洞
def auto_import_and_check(ip,port):
	pluginspath = "./plugins/"
	modules = get_modules(pluginspath)
	#print(modules)
	for module in modules:
		#print(module)
		mod = importlib.import_module('plugins.'+module)#逐个导入poc模块并检测
		#print(dir(mod))
		check(mod,module,ip,port)

#写入漏洞检测结果
def res_output(mod_name,ip,port,result):
	try:
		fp = open('./res.txt','r')
		fp.close()
	except IOError:
		fp = open('./res.txt','w')
		fp.close()
	data  = "{mod_name}->{ip}:{port}->{result}".format(mod_name=mod_name,ip=ip,port=port,result=result)
	with open('./res.txt','a+') as fp:
		fp.write(data)
	fp.close()

#读取txt文件中的待检测目标
def get_target():
	with open('targets.txt','r') as fp:
		for item in fp:
			#print(item,type(item))
			try:
				if ":" not in item:
					port = '80'.strip()
					ip = item.strip()
					auto_import_and_check(ip,port)
				else:
					ip,port = item.split(':')
					ip = ip.strip()
					port = port.strip()
					auto_import_and_check(ip,port)
			except Exception as msg:
				#print(msg)
				return False
	fp.close()


def main():#使用多线程加快检测速度
	threads = []
	threads_count = 5
	try:
		for i in range(threads_count):
			t = threading.Thread(target=get_target)
			threads.append(t)
		
		for i in range(threads_count):
			threads[i].start() #启动子线程
			threads[i].join() #确保thread子线程执行完毕后才能执行下一个线程，避免如主线程在子线程之前便执行完毕的情况
	except Exception as msg:
		print(msg)
		return False

if __name__ == "__main__":
	main()
