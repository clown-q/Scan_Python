import json
from urllib import parse, request
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.utils import Log


def zoomeye_search(query, page):
    url = 'https://api.zoomeye.hk/web/search'
    params = {
        'query': f"{query}",
        'page': f"{page}"
    }
    headers = {
        'API-KEY': 'key',#使用自己的key替换
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


def parse_report(report):
    Log.info(report)
    results = []
    report_entries = report.split("\n\n\n")  # Split individual reports by double newlines

    for entry in report_entries:
        site_info = {}
        lines = entry.split("\n")

        for line in lines:
            if "：" in line:
                key, value = line.split("：", 1)
                site_info[key] = value

        results.append(site_info)

    return results


if __name__ == '__main__':
    pass
    print(extract_site_info(zoomeye_search('site:"baidu.com"', 1)))
    # conn = create_connection()
    # create_table(conn,"baidu.com".replace('.','_'))
    # insert_multiple_scan_results(parse_report(extract_site_info(fetch_all_pages('site:"baidu.com"', 1))),"baidu.com".replace('.','_'))
