# Streams a chunked SSE reply; /slow takes 3 s, /fast 0.3 s.
import http.server, ssl, sys, time, json
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); self.rfile.read(n)
        slow = self.path == "/slow"
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        for i in range(6):
            data = f"data: {json.dumps({'path': self.path, 'i': i})}\n\n".encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data)); self.wfile.flush()
            time.sleep(0.5 if slow else 0.05)
        self.wfile.write(b"0\r\n\r\n"); self.wfile.flush()
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("cert.pem", "key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
