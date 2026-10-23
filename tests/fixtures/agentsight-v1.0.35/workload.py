"""DR-170 parity workload (v1.0.35). Runs as PID 1 of its own PID namespace."""
import os, socket, subprocess, sys, time
go = sys.argv[1]; work = sys.argv[2]
while not os.path.exists(go):
    time.sleep(0.1)
time.sleep(0.5)
def lsock(fam, addr, port=None, kind=socket.SOCK_STREAM, listen=True):
    s = socket.socket(fam, kind)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0 if addr == "::" else 1)
    if port is not None:
        s.bind((addr, port))
    if listen:
        s.listen(4)
    return s
keep = [
    lsock(socket.AF_INET, "127.0.0.1", 18170),
    lsock(socket.AF_INET, "0.0.0.0", 0),
    lsock(socket.AF_INET, None),            # autobind
    lsock(socket.AF_INET6, "::", 0),
    lsock(socket.AF_INET6, "::1", 18171),
    lsock(socket.AF_INET, "127.0.0.1", 18172, socket.SOCK_DGRAM, listen=False),
]
for fam, addr, port, srv in ((socket.AF_INET, "127.0.0.1", 18170, keep[0]),
                             (socket.AF_INET6, "::1", 18171, keep[4])):
    c = socket.socket(fam); c.connect((addr, port)); a, _ = srv.accept(); keep += [c, a]
open("/etc/hostname").read()
with open(f"{work}/out.txt", "w") as f: f.write("x")
with open(f"{work}/out.txt", "a") as f: f.write("y")
open(os.path.join(work.encode(), b"n\xff\xfe"), "wb").close()
open(os.path.join(work.encode(), b"n\xfe\xff"), "wb").close()
deep = work + "/" + "/".join(["d" * 60] * 11)
os.makedirs(deep, exist_ok=True)
open(deep + "/f.txt", "w").close()
subprocess.run(["/bin/true"])
# A sandboxed tool call: a PID namespace nested inside this one (agentsight#238).
subprocess.run(["unshare", "--pid", "--fork", sys.executable, "-c",
    "import socket,time;s=socket.socket();s.bind(('0.0.0.0',7000));s.listen();"
    f"open('{work}/nested.txt','w').write('n');time.sleep(1)"])
# A forked worker thread's child (agentsight#240 shape): fork from a thread.
import threading
def worker():
    pid = os.fork()
    if pid == 0:
        s = socket.socket(); s.bind(("127.0.0.1", 7001)); s.listen()
        open(f"{work}/thread-child.txt", "w").write("t"); time.sleep(1); os._exit(0)
    os.waitpid(pid, 0)
t = threading.Thread(target=worker); t.start(); t.join()
open(f"{work}/ready", "w").close()
time.sleep(int(sys.argv[3]) if len(sys.argv) > 3 else 12)
