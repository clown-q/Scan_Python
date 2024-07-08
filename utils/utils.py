import sys

class command:
    Version = "Scan v1.0"#版本号
    #将字符串替换为绿色
    def return_green(message):
        return f"\033[32m{message}\033[0m"

    #将字符串替换为红色
    def return_red(message):
        return f"\033[31m{message}\033[0m"

    #将字符串替换为蓝色
    def return_blue(message):
        return f"\033[94m{message}\033[0m"

    #将字符串替换为黄色
    def return_yellow(message):
        return f"\033[93m{message}\033[0m"

    def return_lightPurple(message):
        return f"\033[94m{message}\033[0m"

    def return_purple(message):
        return f"\033[95m{message}\033[0m"

    def return_underline(message):
        return f"\033[4m{message}\033[0m"

class Log():
    @staticmethod
    def _print(word):
        sys.stdout.write(word)
        sys.stdout.flush()

    @staticmethod
    def info(word):
        Log._print("[+] %s\n" % command.return_lightPurple(word))

    @staticmethod
    def warning(word):
        Log._print("[!] %s\n" % command.return_yellow(word))

    @staticmethod
    def error(word):
        Log._print("[-] %s\n" % command.return_red(word))

    @staticmethod
    def success(word):
        Log._print("[+] %s\n" % command.return_purple(word))

    @staticmethod
    def query(word):
        Log._print("[?] %s\n" % command.return_underline(word))

    @staticmethod
    def context(context):
        Log._print("%s" % (command.return_red(context)))

    @staticmethod
    def conventional():
        Log._print(" >> ")