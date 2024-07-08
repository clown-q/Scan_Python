import re
from mysql.connector import Error
from Mysql_utils.mysql_utlis import create_connection, close_connection
from scripts.zoomeye_api import parse_report, fetch_all_pages
from utils.utils import Log

def create_table(conn,tables_name):
    """创建表格"""
    if conn:
        try:
            cursor = conn.cursor()

            # 检查表是否存在
            cursor.execute(f"SHOW TABLES like '{tables_name}'")
            result = cursor.fetchone()
            if re.search(r'\W', tables_name) or re.match(r'^[0-9]', tables_name):
                tables_name = f"`{tables_name}`"
            else:
                tables_name = tables_name
            if result:
                cursor.execute(f"DROP TABLE IF EXISTS {tables_name}")
                Log.info(f"表 {tables_name} 删除成功")
            else:
                pass

            cursor.execute(f'''
                CREATE TABLE {tables_name} (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    website VARCHAR(255),
                    domain VARCHAR(255),
                    title TEXT,
                    keywords TEXT,
                    description TEXT,
                    associated_domains TEXT,
                    server VARCHAR(255),
                    ip_address VARCHAR(50),
                    prot VARCHAR(255),
                    location VARCHAR(255),
                    organization VARCHAR(255),
                    continent VARCHAR(100),
                    country VARCHAR(100),
                    city VARCHAR(100),
                    district VARCHAR(100),
                    timezone VARCHAR(50)
                )
            ''')
            conn.commit()
            Log.info(f"表 {tables_name} 创建成功")
        except Error as e:
            pass
            Log.error(f"创建 {tables_name} 表时出错: {e}")

def insert_scan_result(scan_result,tables_name):
    connection = create_connection()
    if connection is not None:
        cursor = connection.cursor()
        insert_query = f"""
        INSERT INTO {tables_name} (
           website, domain, title, keywords, description, associated_domains, server, ip_address, prot, location, organization,
            continent, country, city, district, timezone
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        try:
            cursor.execute(insert_query, (
                scan_result["网站"], scan_result["网址"], scan_result["标题"], scan_result["关键词"], scan_result["描述"],
                scan_result["关联域名"], scan_result["服务器"], scan_result["IP地址"], str(scan_result['端口信息']),scan_result["位置"], scan_result["组织"],
                scan_result["洲"], scan_result["国家"], scan_result["城市"], scan_result["区"], scan_result["时区"]
            ))
            connection.commit()
            Log.success("数据插入成功")
        except Error as e:
            Log.error(f"插入数据失败: {e}")
        finally:
            cursor.close()
            close_connection(connection)

# 插入多个扫描结果
def insert_multiple_scan_results(scan_results,tables_name):
    for result in scan_results:
        insert_scan_result(result,tables_name)

def inst_zoom(query,page):
    if re.search(r'\W', query) or re.match(r'^[0-9]', query):
        tables_name = f"`{query}`"
    else:
        tables_name = query

    conn = create_connection()
    create_table(conn,query)
    insert_multiple_scan_results(parse_report(fetch_all_pages(query, page)),tables_name)
    close_connection(conn)
    conn.close()

# 示例的关闭和创建数据库连接的例子
if __name__ == "__main__":
    inst_zoom('site:"baidu.com"',2)
    pass