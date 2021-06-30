import os

from common import isASCII
from common import startMenu, line, newLine, cls
from common import VIDEO_PATH, RESULT_OUTPUT
from generator import Generator, Video
from des import DES

cls()

print(f"{newLine} Setting up generator...\n{newLine} Loading video file ({VIDEO_PATH}).. ")
video = Video(VIDEO_PATH)
print(f"{newLine} Done.")
trng = Generator(video, RESULT_OUTPUT)

while True:
    try:
        while True:
            cls()
            text = input(f"{newLine} Enter a text to encrypt or leave blank to read from file: ")
            if text == "":
                while True:
                    cls()
                    inputFile = input(f"{newLine} Enter a filename: ")
                    if not os.path.exists(inputFile) or not inputFile[4:].lower() != ".txt":
                        input(f"{newLine} Enter correct filename from root dir.. Press any key to continue..")
                        continue
                    with open(inputFile, "r") as f:
                        text = f.read().replace('\n', '')
                        if text == "":
                            input(f"{newLine} File is empty.. Press any key to continue..")
                            continue
                    break
            if not isASCII(text):
                input(f"{newLine} ASCII only.. Press any key to continue..")
            break

        while True:
            cls()
            print(newLine + f" Plain text: {text[:300]}")
            key = input(f"{newLine} Enter the 8-char ASCII key or leave to generate: ")
            if key == "":
                for i in range(8):
                    value = (trng.next() / (256/126) / (126/94)) + 32  # cast to ASCII range
                    key += chr(round(value))
                input(f"{newLine} Initial key: {key}\n{newLine} Done. Press any key to continue..")
                assert isASCII(key), "Generated key is not ASCII only."
                break
            elif len(key) != 8 or not isASCII(key):
                input(f"{newLine} 8-chars ASCII needed.. Press any key to continue..")
                continue
            else:
                input(f"{newLine} Initial key: {key}\n{newLine} Done. Press any key to continue..")
                break
        cls()
        encryptor = DES(text, key)
        encryptor.init()
    except EOFError:
        print("Finishing...")
        break
