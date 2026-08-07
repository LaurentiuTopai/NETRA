import os
import glob
import time

def test_camera():
    print("\n--- [TEST] Accesare CAMERA ---")
    devices = glob.glob("/dev/video*")
    if not devices:
        devices = ["/dev/video0"]

    for dev in devices:
        print(f"Incerc deschiderea: {dev}")
        try:
            with open(dev, "rb") as f:
                print(f"  [OK] Am deschis {dev}")
        except Exception as e:
            print(f"  [BLOCAT / EROARE] {dev}: {e}")

def test_microphone():
    print("\n--- [TEST] Accesare MICROFON (Capture - 'c') ---")
    devices = glob.glob("/dev/snd/pcm*c")
    if not devices:
        devices = ["/dev/snd/pcmC0D0c"]

    for dev in devices:
        print(f"Incerc deschiderea: {dev}")
        try:
            with open(dev, "rb") as f:
                print(f"  [OK] Am deschis {dev}")
        except Exception as e:
            print(f"  [BLOCAT / EROARE] {dev}: {e}")

def test_speaker():
    print("\n--- [TEST] Accesare DIFUZOR (Playback - 'p') ---")
    devices = glob.glob("/dev/snd/pcm*p")
    if not devices:
        devices = ["/dev/snd/pcmC0D0p"]

    for dev in devices:
        print(f"Incerc deschiderea: {dev}")
        try:
            with open(dev, "rb") as f:
                print(f"  [OK] Am deschis {dev}")
        except Exception as e:
            print(f"  [BLOCAT / EROARE] {dev}: {e}")

def main():
    print(f"[TEST HARDWARE] PID proces: {os.getpid()}")
    test_camera()
    time.sleep(0.5)
    test_microphone()
    time.sleep(0.5)
    test_speaker()

if __name__ == "__main__":
    main()
