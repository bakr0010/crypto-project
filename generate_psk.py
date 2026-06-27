import os

psk = os.urandom(32)
with open("psk.bin", "wb") as f:
    f.write(psk)
print(f"PSK generated and saved to psk.bin ({len(psk)} bytes)")
print("Copy psk.bin to both the client and server machines before running.")
