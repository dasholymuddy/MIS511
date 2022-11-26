import socketserver
import http.server
import urllib

PORT = 9097


class MyProxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        url = self.path[1:]
        self.send_response(200)
        self.end_headers()
        self.copyfile(urllib.urlopen(url), self.wfile)


httpd = socketserver.ForkingTCPServer(('', PORT), MyProxy)

print(f"Now serving at  {str(PORT)}")

httpd.serve_forever()
