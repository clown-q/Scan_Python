import socket
import threading
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from whois import whois
from my_scanner import common
from utils.utils import Log

# 解析域名
def getIp(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        Log.error(f"域名：{domain}，解析失败，请检查域名和网络情况！")
        return "unknow"

def cdn_test(domain):
    domain_first = getIp(domain)
    if domain_first == "unknow":#如果解析失败就不再测试
        pass
    else:
        for i in range(10):
            domain_secend = getIp(domain)
            if domain_first != domain_secend:
                Log.warning(f"域名:{domain}使用了CDN")
                return False
        return True

def get_CDNlist(domain):  # 获取域名解析出的IP列表
    ip_list = []
    number = 0
    try:
        addrs = socket.getaddrinfo(domain, 'http')
        for item in addrs:
            # print(item)
            if item[4][0] not in ip_list:
                ip_list.append(item[4][0])
                number += 1
    except Exception as e:
        Log.error(str(e))

    if number > 1:  # getaddrinfo的返回结果中，多于一个ip，即存在cdn
        Log.warning(f"域名{domain}存在cdn")
        return True
    else:
        return ip_list

#查询whois
def getWhois(domain):
    data = whois(domain)
    return data

#根据bing收集子域名，多线程
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


#被动信息收集
if __name__ == '__main__':
    #这是一个测试
    domain = "www.baidu.com"
    print(getDomain_by_Bing(domain))