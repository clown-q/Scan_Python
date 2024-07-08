from mysql.connector import Error
from Mysql_utils.mysql_utlis import create_connection, close_connection, table_exists
from utils.utils import Log



def create_table_getip(conn):
    """创建数据库表"""
    if conn:
        try:
            cursor = conn.cursor()
            # 创建表的 SQL 语句
            create_table_query = """
            CREATE TABLE IF NOT EXISTS domain_info (
                id INT AUTO_INCREMENT PRIMARY KEY,
                domain VARCHAR(255) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                is_cdn BOOLEAN
            )
            """
            # 执行创建表的 SQL 语句
            cursor.execute(create_table_query)
            Log.success("表 domain_info 创建成功")
        except Error as e:
            Log.error(f"创建表时出错: {e}")
        finally:
            if cursor:
                cursor.close()

def save_to_domain_info(domain, ip_address, is_cdn):
    conn = create_connection()
    if conn:
        try:
            # 检查表是否存在，如果不存在则创建表
            if not table_exists(conn, 'domain_info'):
                create_table_getip(conn)

            cursor = conn.cursor()

            # 查询是否已经存在相同的 domain
            cursor.execute("SELECT id FROM domain_info WHERE domain = %s", (domain,))
            existing_record = cursor.fetchone()

            if existing_record:
                # 如果已存在记录，则更新数据
                sql = "UPDATE domain_info SET ip_address = %s, is_cdn = %s WHERE domain = %s"
                cursor.execute(sql, (ip_address, is_cdn, domain))
                conn.commit()
                Log.success(f"更新域名 '{domain}' 的信息成功")
            else:
                # 否则，插入新数据到表中
                sql = "INSERT INTO domain_info (domain, ip_address, is_cdn) VALUES (%s, %s, %s)"
                cursor.execute(sql, (domain, ip_address, is_cdn))
                conn.commit()
                Log.success(f"插入域名 '{domain}' 的信息成功")
        except Error as e:
            Log.error(f"存入数据库时出错: {e}")
        finally:
            if cursor:
                cursor.close()
            if conn.is_connected():
                conn.close()
                Log.info('MySQL 数据库连接已关闭')
    else:
        Log.error("无法连接到数据库")

def create_whois_info_table(conn):
    """创建 whois_info 表"""
    try:
        cursor = conn.cursor()

        # 定义创建表的 SQL 语句
        create_table_query = """
        CREATE TABLE IF NOT EXISTS whois_info (
            id INT AUTO_INCREMENT PRIMARY KEY,
            domain_name VARCHAR(255) NOT NULL,
            registrar VARCHAR(255),
            whois_server VARCHAR(255),
            updated_date DATETIME,
            creation_date DATETIME,
            expiration_date DATETIME,
            name_servers TEXT,
            status TEXT,
            emails TEXT,
            dnssec VARCHAR(50),
            org VARCHAR(255),
            state VARCHAR(100),
            country VARCHAR(100)
        )
        """

        # 执行创建表的 SQL 语句
        cursor.execute(create_table_query)
        conn.commit()
        print("whois_info 表创建成功")

    except Error as e:
        print(f"创建 whois_info 表时出错: {e}")

    finally:
        if cursor:
            cursor.close()

def save_to_whois_info(whois_data):
    conn = create_connection()
    if conn:
        try:
            cursor = conn.cursor()
            if not table_exists(conn, 'whois_info'):
                create_whois_info_table(conn)

            # 查询是否已存在相同的 domain_name
            cursor.execute("SELECT id FROM whois_info WHERE domain_name = %s", (', '.join(whois_data.get('domain_name', [])),))
            existing_record = cursor.fetchone()

            if existing_record:
                # 执行更新操作
                update_query = """
                UPDATE whois_info SET
                    registrar = %s,
                    whois_server = %s,
                    name_servers = %s,
                    status = %s,
                    emails = %s,
                    dnssec = %s,
                    org = %s,
                    state = %s,
                    country = %s
                WHERE domain_name = %s
                """
                cursor.execute(update_query, (
                    whois_data.get('registrar', ''),
                    whois_data.get('whois_server', ''),
                    ', '.join(whois_data.get('name_servers', [])),
                    ', '.join(whois_data.get('status', [])),
                    ', '.join(whois_data.get('emails', [])),
                    whois_data.get('dnssec', ''),
                    whois_data.get('org', ''),
                    whois_data.get('state', ''),
                    whois_data.get('country', ''),
                    ', '.join(whois_data.get('domain_name', []))
                ))
                conn.commit()
                print(f"已更新 domain_name '{', '.join(whois_data.get('domain_name', []))}' 的 WHOIS 信息")
            else:
                # 执行插入操作
                insert_query = """
                INSERT INTO whois_info (
                    domain_name, registrar, whois_server, name_servers, status, emails,
                    dnssec, org, state, country
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, (
                    ', '.join(whois_data.get('domain_name', [])),
                    whois_data.get('registrar', ''),
                    whois_data.get('whois_server', ''),
                    ', '.join(whois_data.get('name_servers', [])),
                    ', '.join(whois_data.get('status', [])),
                    ', '.join(whois_data.get('emails', [])),
                    whois_data.get('dnssec', ''),
                    whois_data.get('org', ''),
                    whois_data.get('state', ''),
                    whois_data.get('country', '')
                ))
                conn.commit()
                print(f"已插入新的 WHOIS 信息")

        except Error as e:
            print(f"存入数据库时出错: {e}")

        finally:
            if cursor:
                # 显式获取所有结果，确保游标操作完成
                cursor.fetchall()
                cursor.close()
            if conn.is_connected():
                conn.close()
                print('MySQL 数据库连接已关闭')

    else:
        print("无法连接到数据库")


def create_domains_table(conn):
    """创建域名数据表"""
    if conn:
        try:
            cursor = conn.cursor()
            # 创建 domains 表
            cursor.execute("""
                CREATE TABLE  domain_collections (
                    id int AUTO_INCREMENT PRIMARY KEY,
                    key_name VARCHAR(255) ,
                    domains VARCHAR(255) 
                )
            """)
            print("成功创建 domains 表")
        except Error as e:
            print(f"创建表时出错: {e}")
        finally:
            cursor.close()

def insert_domain_collection(key_name, domain_list):
    conn = create_connection()
    if conn:
        try:
            cursor = conn.cursor()
            if not table_exists(conn, 'domain_collections'):
                create_domains_table(conn)

            # 检查是否已经存在记录
            cursor.execute("SELECT * FROM domain_collections WHERE key_name = %s", (key_name,))
            existing_record = cursor.fetchone()

            if existing_record:
                # 更新已存在的记录
                domain_str = ', '.join(domain_list)
                cursor.execute("UPDATE domain_collections SET domains = %s WHERE key_name = %s", (domain_str, key_name))
                Log.success(f"成功更新域名集合到数据库")
            else:
                # 插入新记录
                domain_str = ', '.join(domain_list)
                cursor.execute("INSERT INTO domain_collections (key_name, domains) VALUES (%s, %s)", (key_name, domain_str))
                Log.success(f"成功插入域名集合到数据库")

            conn.commit()
        except Error as e:
            conn.rollback()
            Log.error(f"插入数据时出错: {e}")
        finally:
            cursor.close()
            close_connection(conn)


def create_email_table(conn):
    """创建邮箱数据表"""
    if conn:
        try:
            cursor = conn.cursor()
            # 创建 email_collections 表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_collections (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    domain_key VARCHAR(255),
                    email VARCHAR(255)
                )
            """)
            print("成功创建 email_collections 表")
        except Error as e:
            print(f"创建表时出错: {e}")
        finally:
            cursor.close()

def insert_email_collection(domain_key, email_list):
    conn = create_connection()
    if conn:
        try:
            if not table_exists(conn, 'email_collections'):
                create_email_table(conn)

            cursor = conn.cursor()

            # 将 email_list 转换为逗号分隔的字符串
            email_str = ', '.join(email_list)

            # 检查 domain_key 是否存在
            cursor.execute("SELECT 1 FROM email_collections WHERE domain_key = %s", (domain_key,))
            exists = cursor.fetchone()

            if exists:
                # 如果存在，则更新数据
                cursor.execute("""
                    UPDATE email_collections 
                    SET email = %s 
                    WHERE domain_key = %s
                """, (email_str, domain_key))
                print(f"成功更新邮箱集合到数据库")
            else:
                # 如果不存在，则插入数据
                cursor.execute("""
                    INSERT INTO email_collections (domain_key, email) 
                    VALUES (%s, %s)
                """, (domain_key, email_str))
                print(f"成功插入邮箱集合到数据库")

            conn.commit()
        except Error as e:
            conn.rollback()
            print(f"插入或更新数据时出错: {e}")
        finally:
            cursor.close()
            close_connection(conn)

if __name__ == "__main__":
    create_table_getip('domain_info')