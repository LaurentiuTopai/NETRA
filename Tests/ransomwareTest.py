
import time
import sys
import os

N_WRITES = 50
DELAY = 0.05

def main():
    print(f"[TEST][RANSOMWARE] scriu de {N_WRITES} in {DELAY} secunde")
    for i in range(N_WRITES):
        FILENAME = f"/tmp/test_target{i}.txt"
        with open(FILENAME,"w") as f:
            f.write(f"linia {i}\n")
        print(f"trec la liina {i+1}")
        os.rename(FILENAME,FILENAME+".locked")
        time.sleep(DELAY)

print("[TEST][RANSOMWARE] s-a terminat")

if __name__ == "__main__":
    main()


