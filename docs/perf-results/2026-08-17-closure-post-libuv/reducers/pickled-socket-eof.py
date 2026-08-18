import multiprocessing as mp, socket
from multiprocessing import connection

def _listener(conn, families):
    for fam in families:
        l = connection.Listener(family=fam)
        conn.send(l.address)
        new_conn = l.accept()
        conn.send(new_conn)
        new_conn.close()
        l.close()
    l = socket.create_server(("127.0.0.1", 0))
    conn.send(l.getsockname())
    new_conn, addr = l.accept()
    conn.send(new_conn)
    new_conn.close()
    l.close()
    conn.recv()

def _remote(conn):
    for (address, msg) in iter(conn.recv, None):
        client = connection.Client(address)
        client.send(msg.upper())
        client.close()
    address, msg = conn.recv()
    client = socket.socket()
    client.connect(address)
    client.sendall(msg.upper())
    client.close()
    conn.close()

if __name__ == '__main__':
    families = list(connection.families)
    lconn, lconn0 = mp.Pipe()
    lp = mp.get_context('fork').Process(target=_listener, args=(lconn0, families), daemon=True)
    lp.start(); lconn0.close()
    rconn, rconn0 = mp.Pipe()
    rp = mp.get_context('fork').Process(target=_remote, args=(rconn0,), daemon=True)
    rp.start(); rconn0.close()
    for fam in families:
        msg = ('conn family %s' % fam).encode()
        address = lconn.recv()
        rconn.send((address, msg))
        new_conn = lconn.recv()
        got = new_conn.recv()
        print(f"{fam}: {'ok' if got == msg.upper() else 'BAD'}", flush=True)
        new_conn.close()
    rconn.send(None)
    msg = b'this connection uses a normal socket'
    address = lconn.recv()
    rconn.send((address, msg))
    new_conn = lconn.recv()
    buf = []
    while True:
        s = new_conn.recv(100)
        if not s: break
        buf.append(s)
    got = b''.join(buf)
    print("raw:", "ok" if got == msg.upper() else f"GOT {got!r}", flush=True)
    lconn.send(None)
