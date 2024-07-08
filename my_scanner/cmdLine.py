import argparse

from Mysql_utils.mysql_passive import save_to_domain_info, save_to_whois_info, insert_domain_collection, \
    insert_email_collection
from Mysql_utils.mysql_zoom import inst_zoom
from my_scanner import common
from scripts import passive_collection
from scripts import active_collection
from utils.utils import command, Log

def cmdLine():
    parser = LineParse_common()
    LineParse_passive(parser)
    LineParse_initiative(parser)
    LineParse_dir(parser)
    LineParse_zoomeye(parser)
    # 解析命令行参数
    args = parser.parse_args()
    # print(args)  # 显示输入信息
    cmdLine_passive(args)


def LineParse_common():
    # 创建主 ArgumentParser 对象
    # 关闭自定义帮助选项
    parser = argparse.ArgumentParser(description="示例程序", add_help=False)
    # 自定义帮助选项
    parser.add_argument('-h', '--help', action='help', help='显示自定义帮助信息')
# 通用配置
    # 添加版本信息的参数
    parser.add_argument("-v", "--version", help="显示版本号并退出",action="store_true")
    # 添加默认选项确认
    parser.add_argument("-y","--yes",help="确定",action="store_true")
    return parser

def LineParse_passive(parser):
    # 被动信息收集的命令行参数
    passivecmdline = parser.add_argument_group("passivecmdline", "被动信息收集")
    passivecmdline.add_argument('-d', '--domain', help="指定域名")
    passivecmdline.add_argument("-P", "--passive", help="指定模式为被动信息收集模式", action="store_true")
    passivecmdline.add_argument("-gi", "--getip", help="根据域名获取ip", action="store_true")
    passivecmdline.add_argument("-w", "--whois", help="根据域名查询whois信息", action="store_true")
    passivecmdline.add_argument("-sd", "--subdomain", help="通过bing收集子域名", type=int, nargs='?', const=1)
    passivecmdline.add_argument("-sm", "--submail", help="收集域名的邮箱信息", type=int, nargs='?', const=1)

def cmdLine_passive(args):
    # 显示版本和帮助信息
    if args.version == True:
        print(command.return_green(command.Version))
        exit(0)

    Flag = False
    if args.yes:  # 快速确认参数
        Flag = True

    if args.passive == True:  # 被动信息收集
        extract_doamin = ''  # 获取二级域名
        # 指定域名，校验域名合法性
        if args.domain is not None:
            domain = args.domain
            if common.is_valid_domain(domain):  # 判断是否满足域名
                extract_doamin = common.second_level_Standard(domain, Flag)  # 判断是否为二级并尝试提取域名
                if extract_doamin is not None and extract_doamin != 'unknow':
                    Log.info(f"提取二级域名{extract_doamin}成功！")
            else:
                pass
        else:
            Log.error("域名不能为空")
            exit(1)

        if args.getip == True:
            Log.success(f"根据域名:{domain},获取到ip为：{passive_collection.getIp(args.domain)}")
            # passive_collection.get_CDNlist(domain)
            save_to_domain_info(domain=domain,ip_address=passive_collection.getIp(args.domain),is_cdn=passive_collection.get_CDNlist(domain))
            if extract_doamin is not None and extract_doamin != 'unknow':
                Log.success(
                    f"根据提取的二级域名:{extract_doamin},获取到ip为：{passive_collection.getIp(extract_doamin)}")
                # passive_collection.get_CDNlist(extract_doamin)
                save_to_domain_info(domain=extract_doamin, ip_address=passive_collection.getIp(extract_doamin),
                                    is_cdn=passive_collection.get_CDNlist(extract_doamin))

        if args.whois == True:
            wwww = passive_collection.getWhois(domain)
            Log.info(wwww)
            save_to_whois_info(wwww)

        if args.subdomain is not None:
            all_subdomains = set()
            subdomains1 = passive_collection.getDomain_by_Bing(domain=domain, pages=args.subdomain)
            all_subdomains.update(subdomains1)
            if extract_doamin is not None and extract_doamin != 'unknow':
                subdomains2 = passive_collection.getDomain_by_Bing(domain=extract_doamin, pages=args.subdomain)
                all_subdomains.update(subdomains2)

            # 将集合转换为列表并打印
            unique_subdomains = list(all_subdomains)
            insert_domain_collection(key_name=domain,domain_list=unique_subdomains)
            Log.info(unique_subdomains)

            # 判断是否需要根据域名二次收集
            flag = input(command.return_purple("是否根据收集的域名进行二次收集?(Y|N)")).strip().upper()
            if Flag:
                passive_collection.secondary_collection(unique_subdomains, args.subdomain, all_subdomains)
                # 打印二次收集后的结果
                unique_subdomains = list(all_subdomains)
                insert_domain_collection(key_name=domain, domain_list=unique_subdomains)
                # Log.info(unique_subdomains)
            else:
                if flag == 'N' or flag == 'n':
                    pass
                else:
                    passive_collection.secondary_collection(unique_subdomains, args.subdomain, all_subdomains)
                    # 打印二次收集后的结果
                    unique_subdomains = list(all_subdomains)
                    Log.info(unique_subdomains)

        if args.submail is not None:
            Log.info("开始收集")
            all_submails = set()
            submails1 = passive_collection.launcher_mail(domain, args.submail)
            all_submails.update(submails1)
            if extract_doamin is not None and extract_doamin != 'unknow':
                submails2 = passive_collection.launcher_mail(extract_doamin, args.submail)
                all_submails.update(submails2)
            Log.info(all_submails)
            insert_email_collection(domain, all_submails)
    else:
        cmdLine_initiative(args)

def LineParse_initiative(parser):
    # 主动信息收集
    initiativecmdline = parser.add_argument_group("initiativecmdline", "主动信息收集")
    # 添加指定主动信息收集的参数，类型为bool
    initiativecmdline.add_argument("-I", "--initiative", help="指定模式为主动信息收集模式", action="store_true")
    initiativecmdline.add_argument('-iin', '--ipicmpnmap', help='通过icmp协议探测主机存活')
    initiativecmdline.add_argument('-iic', '--ipicmpscapy', help='通过icmp协议探测主机存活')
    initiativecmdline.add_argument("-it",'--iptcp',help='通过tcp协议探测主机存活')
    initiativecmdline.add_argument("-i", '--ip', help='通过四种协议探测主机存活')
    initiativecmdline.add_argument("-p",'--prot',help='指定端口范围')
    initiativecmdline.add_argument('-sv','--ServerVersion',help='探测版本信息',action='store_true')
    initiativecmdline.add_argument('-O','--OS',help='探测服务器版本',action='store_true')
    # 添加线程大小
    initiativecmdline.add_argument("-level",'--level',help='指定线程大小',type=int, nargs='?', const=1)


def cmdLine_initiative(args):
    if args.initiative == True:  # 主动信息收集
        if args.ipicmpscapy is not None:  # 通过icmp探测ip是否存活
            if args.level is None:
                args.level = 1
            active_collection.scan_ip_icmp_scapy(args.ipicmpscapy,args.level)
        elif args.ipicmpnmap is not  None:
            active_collection.scan_ip_nmap(ip=args.ipicmpnmap,level=args.level,icmp=args.ipicmpnmap)
        elif args.iptcp is not None:
            active_collection.scan_ip_nmap(ip=args.iptcp,level=args.level,tcp=args.iptcp,os_detect=args.OS)
        elif args.ip is not None:
            if args.prot is not None:
                if args.ServerVersion is not None:
                    active_collection.scan_ip_nmap(ip=args.ip, prot=args.prot, level=args.level,Version=args.ServerVersion,os_detect=args.OS)
                else:
                    active_collection.scan_ip_nmap(ip=args.ip,prot=args.prot,level=args.level,os_detect=args.OS)
            else:
                active_collection.scan_ip_nmap(ip=args.ip,level=args.level,os_detect=args.OS)
        else:
            cmdLine_dir(args)
            pass
    else:
        cmdLine_zoomeye(args)
        pass

def LineParse_dir(parser):
    dircmdLine = parser.add_argument_group('dircmdline','主动信息收集目录扫描')
    dircmdLine.add_argument('-u','--url',help='要扫描的url地址')
    dircmdLine.add_argument('-r','--read',help='指定文件路径')


    pass
def cmdLine_dir(args):
    if args.url is not None:
        if args.level is None:
            args.level = 1
        if args.read is None:
            args.read = './db/dic.txt'
        active_collection.directory_bruteforce(args.url,args.read,args.level)
    else:
        pass

def LineParse_zoomeye(parser):
    zoomeyecmdLine = parser.add_argument_group('zoomeyecmdline', '主动信息收集目录扫描')
    zoomeyecmdLine.add_argument('-Z','--zoomeye',help='使用zoomeye探测',action='store_true')
    zoomeyecmdLine.add_argument('-query',help='指定查询的语法')
    zoomeyecmdLine.add_argument('-page',help='指定查询的最大页数')

def cmdLine_zoomeye(args):
    if args.zoomeye:
        if args.query is not None:
            if args.page is None:
                args.page = 1
            Log.query('该检索时间较长，请耐心等候')
            # Log.info(fetch_all_pages(args.query, args.page))
            inst_zoom(args.query, args.page)
        else:
            Log.warning("需要指定query参数")