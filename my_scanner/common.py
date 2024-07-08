import random
import re

# 判断是不是二级域名
def is_subdomain(domain):
    return len(domain.split('.')) == 2

# 判断是不是域名
def is_valid_domain(domain):
    # 定义域名的正则表达式
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9]' # 域的第一个字符
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)' # 子域名+主机名
        r'+[a-zA-Z]{2,6}$' # 一级顶级域名
    )
    return re.match(domain_regex, domain) is not None

# 尝试提取二级域名
def extract_subdomain(domain):
    parts = domain.split('.')

    # 判断域名中点号的数量
    if len(parts) >= 3:
        # 如果域名中点号数量大于等于3，提取倒数第二部分和最后一部分作为二级域名
        return '.'.join(parts[-2:])
    else:
        # 否则，整个域名视为二级域名
        return domain


# 二级域名标准
def second_level_Standard(domain,flag_bool):
    # 判断domain是不是只有二级域名
    if not is_subdomain(domain):
        domain = extract_subdomain(domain)
        if flag_bool:
            return domain
        flag = input(f"提取二级域名：{domain}（Y|N）").strip()
        if flag == 'N' or flag == 'n':
            return 'unknow'
            # exit("结束运行!!")
        elif flag == 'Y' or flag == 'y':
            return domain
        else:
            return domain

#headers
# def headers_dic(referer):
#     headers = {
#         "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
#         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
#         "Referer": referer,
#     }
#     return headers
def get_random_user_agent(file_path):
    with open(file_path, 'r') as file:
        user_agents = file.readlines()
    return random.choice(user_agents).strip()

def headers_dic(referer):
    user_agent = get_random_user_agent('./db/user-agents.txt ')
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Referer": referer,
    }
    return headers

# 匹配邮箱,对畸形图片和提取错误的邮箱二次处理
def re_email(html):
    # 使用正则表达式提取电子邮件
    emails = re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", html, re.I)

    # 过滤无效的电子邮件
    valid_emails = []
    for email in emails:
        if re.match(r"[^@]+@[^@]+\.[a-z]{2,}$", email) and not re.search(r"\.(png|jpg|jpeg|gif)$", email, re.I):
            valid_emails.append(email)

    return valid_emails