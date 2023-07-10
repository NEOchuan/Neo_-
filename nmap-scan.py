import nmap
import time
import os
import platform
import subprocess
import pyttsx3
import ipaddress
import re


# 创建一个Nmap扫描器对象
scanner = nmap.PortScanner()

# 定义函数执行Nmap扫描并输出指定信息
def run_nmap_scan(target, arguments):

    # 记录扫描开始时间
    start_time = time.time()
    result = scanner.scan(hosts=target, arguments=arguments)
     # 记录扫描结束时间
    end_time = time.time()
    scan_time = end_time - start_time

    scan_results = ""
    
    # 遍历扫描结果，输出每个主机的信息
    for host in scanner.all_hosts():
        scan_results += f"[*]HOST: {host}\n"
        print(f"[*]HOST: {host}")
        scan_results += f"[*]Status: {scanner[host].state()}\n"
        print(f"[*]Status: {scanner[host].state()}")
    
        try:
            if 'osmatch' in scanner[host]:
                scan_results += f"[*]操作系统: {scanner[host]['osmatch'][0]['name']}\n"
                print(f"操作系统: {scanner[host]['osmatch'][0]['name']}")
                scan_results += f"[*]系统版本: {scanner[host]['osmatch'][0]['osclass'][0]['osfamily']} {scanner[host]['osmatch'][0]['osclass'][0]['osgen']}\n"
                print(f"系统版本: {scanner[host]['osmatch'][0]['osclass'][0]['osfamily']} {scanner[host]['osmatch'][0]['osclass'][0]['osgen']}")
            else:
                scan_results += "无法检测到操作系统信息\n"
        except (IndexError, KeyError):
            scan_results += "无法检测到操作系统信息\n"
        
        for proto in scanner[host].all_protocols():
            print('-------OPEN PORTs-------')
            print(f"协议: {proto}")
            lport = scanner[host][proto].keys()
            for port in lport:
                scan_results += f"[*]Port: {port} 状态: {scanner[host][proto][port]['state']}\n"
                print(f"[*]Port: {port} 状态: {scanner[host][proto][port]['state']}")
                scan_results += f"[*]Service: {scanner[host][proto][port]['name']}\n"
                print(f"[*]Service: {scanner[host][proto][port]['name']}")
                scan_results += f"[*]Version: {scanner[host][proto][port]['version']}\n" + "\n"
                print(f"[*]Version: {scanner[host][proto][port]['version']}\n")
            scan_results += '\n'
        print()
    # 扫描完成，显示提示信息
    print(f"扫描完成! 耗时:{scan_time}")
    return scan_results

def save_scan_results(filename, scan_results):
    with open(filename, 'w+', encoding='utf-8') as file:
        file.write(str(scan_results))
        print(f"[*]成功写入文件; {filename}")

def modify_network_address(network):
        # 使用正则表达式从网段中提取 IP 地址和子网掩码长度
        ip_pattern = r'(\d+\.\d+\.\d+)\.\d+/\d+'
        match = re.match(ip_pattern, network)
        
        if match:
            ip_address = match.group(1)
            modified_network = f"{ip_address}.0/24"
            return modified_network
        
        return None

def get_network_address():
    choice = input("请选择获取网段的方式：\n1. 手动输入网段\n2. 自动获取当前网段\n")
    
    if choice == '1':
        network = input("请输入网段(例如:192.168.0.0/24):")
        return network
    
    elif choice == '2':
        if platform.system() == 'Linux':
            # 执行系统命令 ifconfig，并获取输出结果
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            output = result.stdout
            
            # 在输出结果中查找当前网段的地址信息
            # 这里假设您的网段地址在 inet 地址后面，格式为 xxx.xxx.xxx.xxx/yy
            start = output.find('inet ') + len('inet ')
            end = output.find(' ', start)
            address = output[start:end]
            
            # 获取当前网段的 C 类地址
            ip = ipaddress.ip_interface(address)
            network = f"{ip.network.network_address}/24"
            modified_network = modify_network_address(network)
            return modified_network
        
        # 如果不是 Linux 系统，您可以根据操作系统类型使用相应的命令来获取网段地址
        
    return None


if __name__ == "__main__":

    # 设置要扫描的目标网段（示例为获取当前的网段地址）
    target = get_network_address()
    if not target:
        print('[*]无法获取当前网段!!')
        target = input("请输入要扫描的目标/网段：")
    
    # 提示用户是否添加额外的参数
    print("请选择要执行的扫描类型：")
    print("1. 快速扫描(建议对网段进行扫描)")
    print("2. 全面扫描(建议对单个主机扫描)")
    print("3. 脚本扫描")
    print("4. 自定义参数扫描")
    choice = input("请输入选项(1.2或3)")
    
     # 根据用户的选择执行对应的扫描函数
    if choice == "1":
        arguments = "--min-rate 10000 -p-"
    elif choice == "2":
        arguments = "-sTVC -A -O"
    elif choice == "3":
        arguments = "--script=vuln,ssl-heartbleed"
    elif choice == "4":
        arguments = input("请输入自定义的参数：")
    else:
        print("无效的选项！")
        exit()
    
    # 打印提示信息
    print("开始扫描.....")
    print(f"目标网段: {target}")
    print(f"扫描参数: {arguments}")
    print()
    
    # 执行Nmap扫描并输出指定信息
    scan_results = run_nmap_scan(target, arguments)

    save_results = input("是否保存扫描记录？(Y/N) ")
    if save_results.lower() == "y":
        filename = input("请输入保存的文件名(包括路径):")
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        save_scan_results(filename, scan_results)
        print(f"扫描结果已保存至文件：{filename}")

