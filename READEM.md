## 前言

写了一个简单的信息收集的小工具练手，这里简单记录一下

## 被动信息收集

被动信息搜集主要通过搜索引擎或者社交等方式对目标资产信息进行提取，通常包括IP查询、Whois 查询、子域名搜集等。进行被动信息搜集时不与目标产生交互，可以在不接触到目标系统的情况下挖掘目标信息。主要方法包括: DNS解析、子域名挖掘、邮件爬取等。

### DNS解析

DNS ( Domain Name System,域名系统)是一种分布式网络目录服务，主要用于域名与IP地址的相互转换，能够使用户更方便地访问互联网，而不用去记住长串数字(能够被机器直接读取的IP)。

#### IP查询

IP查询是通过当前所获取到的URL去在询对应1P地址的过程，可以应用Socket库函数中的gethostbyname()获取域名所对应的IP值。

例如要查询www.baidu.com的ip代码如下

```python
def getIp(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        Log.error(f"域名：{domain}，解析失败，请检查域名和网络情况！")
        return "unknow"                         
```

输出结果如下图所示

![image-20240708151201331](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151201331.png)

#### Whois查询

Whois是用来查询域名的IP以及所有者信息的传输协议。简单地说，Whois就是一个数据库，用来查询域名是否已经被注册，以及注册域名的详细信息(如域名所有人、域名注册商等)。Python中的模块python-whois可用于Whois的查询。

例如查询whios信息代码如下

```python
def getWhois(domain):
    data = whois(domain)
    return data
```

输出结果如下图所示：

![img](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/clip_image004.png)

### 子域名挖掘

域名可以分为顶级域名、一级域名、二级域名等。子域名( subdomain)是顶级域名(一级域名或父域名)的下一级。例如，mail.example.com 和calendar.example.com是example.com的两个子域，而example.com则是顶级域.com 的子域。在测试过程中，测试目标主站时如果未发现任何相关漏洞，此时通常会考虑挖掘目标系统的子域名。子域名挖掘方法有很多种，例如，搜索引擎、子域名破解、字典查询等。

下面代码展示了如何使用bing挖掘子域名

```python
def fetch_page(domain, page, referer, subdomain_set, lock):
    url_Bing = f"https://cn.bing.com/search?q=site:{domain}&sp=-1&lq=0&sc=10-4&qs=n&sk=&cvid=F993D91E93DA4D41A87332F46DCCE8D9&ghsh=0&ghacc=0&ghpl=&FPIG=A5413BF8850E43A6A63AFD447FF4FFB2%2cA905EB2EEAA244B0B446E1179BFBBAB0&first={str((int(page) - 1) * 10)}&FORM=PERE2"
    html = requests.get(url_Bing, headers=common.headers_dic(referer=referer))
    soup = BeautifulSoup(html.text, 'html.parser')
    job_bt = soup.findAll('h2')
    with lock:
        for i in job_bt:
            link = i.a.get('href')
            domain_l = urlparse(link).netloc  # 取域名
            subdomain_set.add(domain_l)

def getDomain_by_Bing(domain, pages):
    subdomain_set = set()
    subdomain_set.add(domain)
    referer = "https://www.google.com/"
    lock = threading.Lock()
    threads = []
    for i in range(1, int(pages) + 1):
        thread = threading.Thread(target=fetch_page, args=(domain, i, referer, subdomain_set, lock))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    return list(subdomain_set)

# 使用收集到的子域名进行再一次收集
def secondary_collection(subdomains, pages, all_subdomains):
    referer = "https://www.google.com/"
    lock = threading.Lock()
    threads = []

    for subdomain in subdomains:
        thread = threading.Thread(target=fetch_page, args=(subdomain, pages, referer, all_subdomains, lock))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

```

![image-20240708151226724](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151226724.png)

**2.3** **邮件爬取**

在针对目标系统进行渗透的过程中，如果目标服务器安全性很高，通过服务器很难获取目标权限时，通常会采用社工的方式对目标服务进行进一步攻击。 邮件钓鱼攻击是常见的攻击方式之一。在进行钓鱼之前，需要针对目标相关人员的邮件信息进行全面采集。

此处邮件采集工具主要通过国内常见的搜索引擎(百度、Bing等)进行搜集。针对搜索界面的相关邮件信息进行爬取、处理等操作之后。利用获得的邮箱账号批量发送钓鱼邮件，诱骗、欺诈目标用户或者管理员进行账号登录或者点击执行，进而获取目标系统的权限。

代码如下

```python
#使用Bing检索邮箱
def bing_search_email(domain,page,key_word):
    reffer = "https://www.bing.com/"
    url_Bing = f"https://cn.bing.com/search?q={key_word}+site:{domain}&qs=n&sp=-1&pq={key_word}site:{domain}&first={str((int(page)-1)*10)}&FORM=PERE1"
    # print(url_Bing)
    conn = requests.session()
    conn.get(reffer, headers=common.headers_dic(reffer))
    html = conn.get(url_Bing, stream=True, headers=common.headers_dic(reffer))
    return common.re_email(html.text)

#使用百度检索邮箱
def baidu_search_email(domain,page,key_word):
    email_list = []
    emails = []
    reffer = "https://www.baidu.com/"
    # print(page)
    url_Baidu = f"https://www.baidu.com/s?ie=utf-8&wd={key_word}+site:{domain}&pn={str((int(page)-1)*10)}"
    # print(url_Baidu)

    conn = requests.session()
    conn.get(reffer, headers=common.headers_dic(reffer))
    html = conn.get(url_Baidu, headers=common.headers_dic(reffer))
    soup = BeautifulSoup(html.text, 'lxml')
    tagh3 = soup.findAll('h3')

    for h3 in tagh3:
        href = h3.find('a').get('href')

        try:
            r = requests.get(href, headers=common.headers_dic(reffer))
            emails = common.re_email(r.text)
        except Exception:
            pass

        for email in emails:
            email_list.append(email)
    return email_list

def search_emails(domain, page, key_word, email_set, lock):
    bing_emails = bing_search_email(domain, page, key_word)
    baidu_emails = baidu_search_email(domain, page, key_word)
    all_emails = bing_emails + baidu_emails
    # all_emails = bing_emails

    with lock:
        for email in all_emails:
            email_set.add(email)

def launcher_mail(domain, pages):
    email_set = set()
    key_words = ['email', 'mail', 'mailbox', 'postbox', '邮件', '邮箱']
    lock = threading.Lock()
    threads = []

    for page in range(1, int(pages) + 1):
        for key_word in key_words:
            thread = threading.Thread(target=search_emails, args=(domain, page, key_word, email_set, lock))
            thread.start()
            threads.append(thread)

    for thread in threads:
        thread.join()

return list(email_set)

```

使用如下图所示：

![image-20240708151243970](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151243970.png)

## 主动信息收集

在内网中，好的信息搜集能力能够帮助开发者更快地拿到权限及达成目标。内网里数据多种多样，需要根据需求寻找任何能对下一步渗透行动有所帮助的信息。信息搜集能力是渗透过程中不可或缺的重要一步。

### 基于 ICMP的主机发现

ICMP ( Internet Control Message Protocol, Internet 报文协议)是TCP/IP的一种子协议，位于OSI7层网络模型中的网络层，其目的是用于在IP主机、路由器之间传递控制消息。Ping命令是ICMP中较为常见的一种应用，经常使用这个命令来测试本地与目标之间的连通性，发送一个ICMP请求消息给目标主机，若源主机收到目标主机的应答响应消息，则表示目标可达，主机存在。

使用nmap实现代码如下

```python
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

```

使用scapy实现代码如下

```python
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
```

使用scapy扫描效果如下图所示

![image-20240708151328047](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151328047.png)

使用nmap扫描如下

![image-20240708151354573](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151354573.png)

### 基于TCP、UDP的主机发现

基于TCP、UDP的主机发现属于四层主机发现，是一个位于传输层的协议。可以用来探测远程主机存活、端口开放、服务类型以及系统类型等信息，相比于三层主机发现TCP是一种面向连接的、可靠的传输通信协议，位于IP层之上，应用层之下的中间层。

每一次建立连接都基于三次握手通信，终止-一个连接也需要经过四次握手，建立完连接之后，才可以传输数据。当主动方发出SYN连接请求后，等待对方回答TCP的三次握手SYN + ACK，并最终对对方的SYN执行ACK确认。这种建立连接的方法可以防止产生错误的连接，所以TCP是一一个可靠的传输协议。因此，我们可以利用TCP三次握手原理进行主机存活的探测。当向目标主机直接发送ACK数据包时，如果目标主机存活，就会返回一个RST数据包以终止这个不正常的TCP连接。也可以发送正常的SYN数据包，如果目标主机返回SYN/ACK或者RST数据包，也可以证明目标主机为存活状态。其工作原理主要依据目标主机响应数据包中flags字段，如果flags字段有值，则表示主机存活，该字段通常包括SYN、FIN、ACK、PSH、RST、URG六种类型。SYN表示建立连接，FIN表示关闭连接，ACK表示应答，PSH表示包含DATA数据传输，RST表示连接重置，URG表示紧急指针。

这里选择使用调用nmap来实现，代码如下

```python
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

```

使用演示如下：

![image-20240708151429340](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151429340.png)

4 网络空间搜索引擎

随着互联网、物联网、传感网、社交网络等信息系统所构成的泛在网络不断发展，网络终端设备数量呈指数级上升。这为企业进行终端设备资产清点和统一管控带来了巨大挑战，同时也引发了一系列安全问题，网络攻击与防御的博弈从单边代码漏洞发展到了大数据对抗阶段，网络空间搜索引擎应运而生。

搜索引擎是指从互联网搜集信息，经过一定整理以后，提供给用户进行查询的系统。传统搜索引擎对我们来说并不陌生，像Google、百度等，每天我们几乎都会用它们来搜索消息。与传统搜索引擎相比，网络空间搜索引擎有很大不同，其搜索目标为全球的IF地址，实时扫描互联网和解析各种设备，对网络中的设备进行探测识别和指纹分析，并将其扫描的目标信息进行分布式存储，供需求者检索使用。传统的网络空间搜索模型柜架一-般由五部分组成:扫描和指纹识别、分布存储、索引、UI界面以及调度程序。

这里选择使用调用zoomeye，代码如下

```python
def zoomeye_search(query, page):
    url = 'https://api.zoomeye.hk/web/search'
    params = {
        'query': f"{query}",
        'page': f"{page}"
    }
    headers = {
        'API-KEY': '',#替换为自己的key
        'User-Agent': 'Mozilla/5.0'  # 设置用户代理，通常需要提供
    }
    proxy_host = 'localhost'
    proxy_port = 7897

    proxy_handler = request.ProxyHandler({
        'http': f'http://{proxy_host}:{proxy_port}',
        'https': f'https://{proxy_host}:{proxy_port}'
    })

    opener = request.build_opener(proxy_handler)
    request.install_opener(opener)

    try:
        full_url = f"{url}?{parse.urlencode(params)}"
        req = request.Request(full_url, headers=headers)
        response = request.urlopen(req)

        if response.getcode() == 200:
            data = response.read()
            return json.loads(data.decode('utf-8'))
        else:
            Log.error(f"请求失败，状态码: {response.getcode()}")
            return None
    except Exception as e:
        Log.error(f"请求发生异常: {e}")
        return None

def extract_site_info(json_data):
    matches = json_data['matches']
    if not matches:
        return "No matches found."

    reports = []

    for match in matches:
        # 网站概况
        site_info = {
            "网站": match.get("title", ""),
            "网址": match.get("site", ""),
            "标题": match.get("title", ""),
            "关键词": match.get("keywords", ""),
            "描述": match.get("description", ""),
            "关联域名": ", ".join(match.get("domains", []))
        }

        # 服务器信息
        server_info = {
            "服务器": match.get("headers", "").split("Server: ")[1].split("\r\n")[0] if "Server: " in match.get("headers", "") else "",
            "IP地址": match.get("ip", [''])[0],
            "端口信息": match.get("portinfo", ""),
            "位置": match.get("geoinfo", {}).get("subdivisions", {}).get("names", {}).get("zh-CN", "") + "省" +
                   match.get("geoinfo", {}).get("city", {}).get("names", {}).get("zh-CN", ""),
            "组织": match.get("geoinfo", {}).get("organization", "")
        }

        # 地理信息
        geoinfo = {
            "洲": match.get("geoinfo", {}).get("continent", {}).get("names", {}).get("zh-CN", ""),
            "国家": match.get("geoinfo", {}).get("country", {}).get("names", {}).get("zh-CN", ""),
            "城市": match.get("geoinfo", {}).get("city", {}).get("names", {}).get("zh-CN", ""),
            "区": match.get("geoinfo", {}).get("district", {}).get("names", {}).get("zh-CN", ""),
            "时区": match.get("geoinfo", {}).get("timezone", "")
        }

        # 生成单个报告
        report = (
            "网站概况\n"
            f"网站：{site_info['网站']}\n"
            f"网址：{site_info['网址']}\n"
            f"标题：{site_info['标题']}\n"
            f"关键词：{site_info['关键词']}\n"
            f"描述：{site_info['描述']}\n"
            f"关联域名：{site_info['关联域名']}\n\n"
            "服务器信息\n"
            f"服务器：{server_info['服务器']}\n"
            f"IP地址：{server_info['IP地址']}\n"
            f"端口信息：{server_info['端口信息']}\n"
            f"位置：{server_info['位置']}\n"
            f"组织：{server_info['组织']}\n\n"
            "地理信息\n"
            f"洲：{geoinfo['洲']}\n"
            f"国家：{geoinfo['国家']}\n"
            f"城市：{geoinfo['城市']}\n"
            f"区：{geoinfo['区']}\n"
            f"时区：{geoinfo['时区']}\n"
        )
        reports.append(report)

    # 合并所有报告
    final_report = "\n\n".join(reports)
    return final_report

def fetch_all_pages(query, max_page):
    reports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_page = {executor.submit(zoomeye_search, query, page): page for page in range(1, int(max_page) + 1)}
        for future in as_completed(future_to_page):
            page = future_to_page[future]
            try:
                data = future.result()
                if data:
                    report = extract_site_info(data)
                    reports.append(report)
            except Exception as e:
                Log.error(f"页面 {page} 处理时发生异常: {e}")

    final_report = "\n\n".join(reports)
    return final_report
```

使用效果图如下：

![image-20240708151520653](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151520653.png)

![image-20240708151457827](https://note-1311335427.cos.ap-shanghai.myqcloud.com/images/image-20240708151457827.png)

