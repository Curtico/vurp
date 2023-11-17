import ret2win
import threading

def bruh(binary):
    print(f"{binary}: {ret2win.exploit(binary)}")

for i in range(10):
    binary = f"bin-ret2win-{i}"
    threading.Thread(target=bruh, args=(binary,)).start()
