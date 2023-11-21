from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl

#from cairo._cairo import Content
from passlib.hash import bcrypt
from os.path import isfile

hostName = "localhost"
serverPort = 4443
filename = "cred.txt"
CHECK_NAME = 1
CHECK_BOTH = 2
NO_MATCH = 0
MATCH = 3

class MyServer(BaseHTTPRequestHandler):
    def check_matches(self, operation, name, pwd):
        if isfile(filename):

            with open(filename, "r", encoding="utf-8") as f:

                while True:

                    line = f.readline()
                        
                    if not line:
                        break
                            
                    res = line.split(':')

                    if len(res) > 1 and name == res[0] and (operation == CHECK_NAME or bcrypt.verify(pwd.encode('utf-8'), res[1])):
                        print("USERNAME AND MAYBE PASSWORD IN USE")
                        return MATCH

        return NO_MATCH

    def return_credentials(self):
        content_length = int(self.headers['Content-Length'])
        post_data_bytes = self.rfile.read(content_length)
        print ("MY SERVER: The post data I received from the request has following data:\n", post_data_bytes)
       
        post_data_str = post_data_bytes.decode("UTF-8")
        list_of_post_data = post_data_str.split('&')

        post_data_dict = {}
        for item in list_of_post_data:
            variable, value = item.split('=')
            post_data_dict[variable] = value
        return post_data_dict['fname'], post_data_dict['passwd']

    def handle_except(self):
        self.wfile.write(bytes("<html><head><title>https://pythonbasics.org</title></head>", "utf-8"))
        #self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
        self.wfile.write(bytes("<body>", "utf-8"))
        self.wfile.write(bytes("<p>No content</p>", "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))

    def set_response(self, response):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<body>", "utf-8"))
        self.wfile.write(bytes("<p>" + response + "</p>", "utf-8"))
        self.wfile.write(bytes("</body></html>", "utf-8"))

    def set_front_page(self):
        try:
            with open('html/login.html', 'rb') as content:
                self.wfile.write(content.read())
        except:
            self.handle_except()
            
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if self.path == '/':
            self.set_front_page()
                
        if self.path == '/verify':
            try:
                with open('html/index.html', 'rb') as content:
                    self.wfile.write(content.read())
            except:
                self.handle_except()
                
        if self.path == '/register':
            try:
                with open('html/register.html', 'rb') as content:
                    self.wfile.write(content.read())
            except:
                self.handle_except()

    def do_POST(self):
        print ("MY SERVER: I got a POST request from user")

        if self.path == '/register':
            print("HERE2")
            return MyServer.do_GET(self)
        
        if self.path == '/store':
            name, pwd = self.return_credentials()
            try:

                if self.check_matches(CHECK_NAME, name, pwd) == MATCH:
                    self.set_response("USERNAME IS ALREADY RESERVED")
                    return
                 
                with open(filename, "a", encoding="utf-8") as f:
                
                    hasher = bcrypt.using(rounds=13)
                    password = hasher.hash(pwd)
                    f.write(name + ':' + password + ':\n')
                    self.set_response("USERNAME AND PASSWORD FOR USER " + name + " REGISTERED")

            except:
                print ("Exception")
            
        if self.path == '/verify':
            name, pwd = self.return_credentials()
                
            hasher = bcrypt.using(rounds=13)

            if self.check_matches(CHECK_BOTH, name, pwd) == MATCH:
                return MyServer.do_GET(self)
            else:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers() 
                self.set_front_page()
                return

if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), MyServer)
    webServer.socket = ssl.wrap_socket(webServer.socket, keyfile="key.pem", certfile="cert.pem",
                                       server_side=True)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()

    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
    