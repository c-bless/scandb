import sqlite3


def get_host_list(db, status):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT distinct address FROM host WHERE status like ? ;", (status,))
    rows = cur.fetchall()
    ips = [ x[0] for x in rows]
    conn.close()
    return ips


def get_host_list_by_udp(db, udp):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    sql = "SELECT distinct address FROM port where port in ({seq_udp}) and protocol = 'udp'".format(
            seq_udp=','.join(['?'] * len(udp)))
    cur.execute(sql, udp)
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips


def get_host_list_by_tcp(db, tcp):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    sql = "SELECT distinct address FROM port where port in ({seq_tcp}) and protocol = 'tcp'".format(
        seq_tcp=','.join(['?'] * len(tcp)))
    cur.execute(sql, tcp)
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips


# temp. unused by cli command
def get_host_list_by_both(db, tcp, udp):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    sql = "SELECT distinct address FROM port WHERE port in ({seq_tcp}) and protocol = 'tcp' " \
          "or port in ({seq_udp})  and protocol ='udp'".format(
            seq_tcp=','.join(['?'] * len(tcp)),
            seq_udp=','.join(['?'] * len(udp)))
    cur.execute(sql, (tcp,udp,))
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips

