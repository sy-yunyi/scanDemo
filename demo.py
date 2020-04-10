from socket import * 

def portScanner(host,port):
    try:
        s = socket(AF_INET,SOCK_STREAM)
        print(s.connect((host,port)))
        print("[+] %d open " % port)
        s.close()
    except Exception as e:
        print(e)

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 5353
    portScanner(host,port)

        