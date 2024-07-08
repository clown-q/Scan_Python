import time

from my_scanner import cmdLine
from utils.utils import Log


def VPrint():
    Scan = '''\033[32m
    .oooooo..o                                 
d8P'      `Y8                                 
Y88bo.       .ooooo.   .oooo.   ooo. .oo.   
 `"Y8888o.  d88' `"Y8 `P  )88b  `888P"Y88b  
     `"Y88b 888        .oP"888   888   888  
oo     .d8P 888   .o8 d8(  888   888   888  
8""88888P'  `Y8bod8P' `Y888""8o o888o o888o 
                                            
\033[0m'''
    print(Scan)

#主函数
def main():
    VPrint()
    try:
        cmdLine.cmdLine()
        pass
    except KeyboardInterrupt:
        Log.warning("程序暂停。")
        exit(0)



if __name__ == "__main__":
    main()