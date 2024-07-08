import mysql.connector
from mysql.connector import Error

from utils.utils import Log

# MySQL 连接配置
MYSQL_CONFIG = {
    'host': 'localhost',
    'database': 'scan',  # 替换为你的数据库名称
    'user': 'root',            # 替换为你的数据库用户名
    'password': 'root',        # 替换为你的数据库密码
    # 'charset': 'utf8_bin',               # 根据需要调整字符集
    # 'collation': 'utf8mb4_unicode_ci'
}

def create_connection():
    """创建数据库连接"""
    try:
        conn = mysql.connector.connect(**MYSQL_CONFIG)
        if conn.is_connected():
            Log.success('已连接到 MySQL 数据库')
            return conn
    except Error as e:
        Log.error(f"连接到 MySQL 数据库时出错: {e}")
        return None

def close_connection(conn):
    """关闭数据库连接"""
    if conn:
        conn.close()
        Log.info('MySQL 数据库连接已关闭')

def table_exists(conn, table_name):
    """检查表是否存在"""
    if conn:
        cursor = conn.cursor()
        cursor.execute(f"SHOW TABLES LIKE '{table_name}'")
        result = cursor.fetchone()
        cursor.close()
        if result:
            return True
    return False