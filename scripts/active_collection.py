from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from queue import Queue
import nmap
import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

from my_scanner.common import headers_dic
from utils.utils import Log, command
from scapy.all import *
from random import randint
import ipaddress
from scapy.layers.inet import ICMP, IP


#使用scapy进行icmp扫描
def send_icmp_scapy(target_ip):
    ip_id = randint(1, 65535)
    icmp_id = randint(1, 65535)
    icmp_seq = randint(1, 65535)

    packet = IP(dst=target_ip, id=ip_id) / ICMP(id=icmp_id, seq=icmp_seq)
    response = sr1(packet, timeout=2, verbose=0)
    if response:
        Log.success(f"{target_ip} 是在线的")
    else:
        Log.warning(f"{target_ip} 没有响应")

#使用scapy进行icmp扫描-线程处理
def worker_icmp_scapy(queue):
    while not queue.empty():
        target_ip = queue.get()
        if target_ip is None:
            break
        try:
            send_icmp_scapy(target_ip)
        finally:
            queue.task_done()

#使用scapy进行icmp扫描-ip处理
def scan_ip_icmp_scapy(ip, level=1):
    Log.info(f"开始扫描: {ip}，线程等级: {level}")

    target_ips = []
    if '/' in ip:
        # 子网扫描
        try:
            network = ipaddress.ip_network(ip, strict=False)
            target_ips = [str(host) for host in network.hosts()]
        except ValueError as e:
            Log.error(f"无效的子网: {e}")

    elif '-' in ip:
        # IP范围扫描，格式为"start_ip-end_suffix"
        try:
            start_ip, end_suffix = ip.split('-')
            start_ip = ipaddress.ip_address(start_ip)
            start_ip_base = start_ip.packed[:-1]
            end_suffix = int(end_suffix)
            start_suffix = int(start_ip.packed[-1])
            if start_suffix > end_suffix:
                raise ValueError("起始后缀应小于或等于结束后缀")
            target_ips = [str(ipaddress.ip_address(start_ip_base + bytes([suffix]))) for suffix in range(start_suffix, end_suffix + 1)]
        except ValueError as e:
            Log.error(f"无效的IP范围: {e}")

    else:
        # 单个IP扫描
        try:
            ipaddress.ip_address(ip)  # 验证IP地址
            target_ips = [ip]
        except ValueError as e:
            Log.warning(f"无效的IP地址: {e}")

    if target_ips:
        queue = Queue()
        for ip in target_ips:
            queue.put(ip)

        threads = []
        for _ in range(level):
            thread = threading.Thread(target=worker_icmp_scapy, args=(queue,))
            thread.start()
            threads.append(thread)

        queue.join()

        for thread in threads:
            thread.join()

def ttl_scan(ip):
    ttlstrmatch = re.compile(r'ttl=\d+')
    ttlnummatch = re.compile(r'\d+')
    result = os.popen('ping -c 1 '+ip)
    res = result.read()
    for line in res.splitlines():
        result = ttlstrmatch.findall(line)
        if result:
            ttl = ttlnummatch.findall(result[0])
            if int(ttl[0]) <= 64:
                Log.success('Linux/UNIX')
            else:
                Log.success('Windows')

def scan_nmap(target_ip, level=None, prot=None, icmp=False, tcp=False, version=False, os_detect=False):
    nm = nmap.PortScanner()
    arguments = f""

    if prot:
        arguments += f" -p {prot}"
    if icmp:
        arguments += " -sn"
    if tcp:
        arguments += " -sT"
    if version:
        arguments += " -sV"
    if os_detect:
        # scan_nmap(target_ip, level=level,os_detect=os_detect)
        arguments += " -O"
    if level is not None:
        arguments += f" --min-parallelism {level} --max-parallelism {level}"

    Log.info(f"使用Nmap进行扫描，目标: {target_ip}，参数: {arguments}")

    try:
        nm.scan(hosts=target_ip, arguments=arguments)
        Log.success("扫描完成。")

        for host in nm.all_hosts():
            if nm[host].state() == "up":
                Log.info(f"{host} 是在线的")

                if prot or tcp:
                    for proto in nm[host].all_protocols():
                        Log.info(f"协议: {proto}")
                        lport = nm[host][proto].keys()
                        for port in lport:
                            Log.info(f"端口: {port}\t状态: {nm[host][proto][port]['state']}")

                if version:
                    for proto in nm[host].all_protocols():
                        if proto == 'tcp':
                            Log.info(f"检测到版本信息:")
                            for port in nm[host][proto]:
                                service = nm[host][proto][port]
                                Log.info(f"端口: {port}\t服务: {service['name']}\t版本: {service['version']}")

                if os_detect:
                    if len(nm[host]['osmatch']) == 0:
                        ttl_scan(target_ip)
                        pass
                    else:
                        Log.info(f"操作系统检测结果:")
                        Log.info(f"{nm[host]['osmatch']}")

            else:
                Log.warning(f"{host} 没有响应")

    except Exception as e:
        Log.error(f"扫描出错: {e}")

def scan_ip_nmap(ip, level=1, prot=None,icmp=None,tcp=None,Version=None,os_detect=None):
    Log.info(f"开始扫描: {ip}，线程等级: {level}")
    if '/' in ip:
        # 子网扫描
        try:
            network = ipaddress.ip_network(ip, strict=False)
            Log.info(f"子网扫描: {network}")
            scan_nmap(str(network), level, prot,icmp,tcp,Version,os_detect)
        except ValueError as e:
            Log.error(f"无效的子网: {e}")
    elif '-' in ip:
        # IP范围扫描，格式为"start_ip-end_suffix"
        try:
            start_ip, end_suffix = ip.split('-')
            start_ip = ipaddress.ip_address(start_ip)
            end_suffix = int(end_suffix)
            start_suffix = int(start_ip.packed[-1])
            if start_suffix > end_suffix:
                raise ValueError("起始后缀应小于或等于结束后缀")
            scan_nmap(ip, level, prot, icmp,tcp,Version,os_detect)
        except ValueError as e:
            Log.error(f"无效的IP范围: {e}")
        except Exception as e:
            Log.error(f"扫描过程中出错: {e}")
    else:
        # 单个IP扫描
        try:
            ipaddress.ip_address(ip)  # 验证IP地址
            Log.info(f"单个IP扫描: {ip}")
            scan_nmap(ip, level, prot, icmp, tcp, Version, os_detect)
        except ValueError as e:
            Log.warning(f"无效的IP地址: {e}")

def check_directory(base_url, directory):
    directory = directory.strip()
    url = os.path.join(base_url, directory)
    try:
        headers = headers_dic(base_url)  # 假设这里定义了获取请求头的函数
        response = requests.get(url, headers=headers, allow_redirects=False, timeout=10)

        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            title = soup.title.string if soup.title else '未找到标题'
            tqdm.write(f"[+] 找到目录: {url} 标题: {title}")
        elif 300 <= response.status_code < 400:
            tqdm.write(f"[>] 从 {url} 重定向到 {response.headers['Location']}")
        # 可以添加其他状态码的处理

    except requests.RequestException as e:
        pass
        # tqdm.write(f"[-] 请求 {url} 时出错: {e}")

def directory_bruteforce(base_url, wordlist, level=10):
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'https://' + base_url

    with open(wordlist, 'r') as file:
        directories = file.readlines()

    progress_bar = tqdm(total=len(directories), desc=' 扫描目录')

    def thread_worker(directory):
        check_directory(base_url, directory)
        progress_bar.update(1)

    # 使用线程池管理线程，控制并发数量
    with ThreadPoolExecutor(max_workers=level) as executor:
        futures = [executor.submit(thread_worker, directory) for directory in directories]

        # 等待所有任务完成
        wait(futures, timeout=None, return_when=ALL_COMPLETED)

    progress_bar.close()
if __name__ == '__main__':
    directory_bruteforce('www.baidu.com','../db/dic.txt',1)
    # scan_ip_nmap('110.242.68.66/30', level=200,)
