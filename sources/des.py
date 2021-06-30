from sources.common import *

INPUT_FILE = "./encrypted.txt"
DEBUG_FILE = "./debug.txt"


def createSubkeys(key: str) -> list[str]:
    """ Creating subkeyses from key """
    res = []
    for i in range(16):
        key = rotateLeft(key, shiftValues[i])
        res.append(key)
    return res


def permutation(binary: str, bins: int, table: list[int]) -> str:
    """ Permute binary representation """
    permuted = ""
    for i in range(bins):
        permuted += binary[table[i] - 1]
    return permuted


def concatAndPermute(left: list[str], right: list[str]) -> list[str]:
    """ Concating left and right subkeys and permute with PC2"""
    subkeys = []
    for i in range(16):
        subkey = left[i] + right[i]
        tmp = permutation(subkey, 48, PC2)
        subkeys.append(tmp)
    return subkeys


def bitsSelection(text: str) -> str:
    """ Selecting bits using bitSelection table """
    res = ""
    for i in range(48):
        res += text[bitSelection[i] - 1]
    return res


def permuteSBox(bins: list[str]) -> str:
    """ Permuting using SBoxes """
    res = ""
    for i in range(8):
        extreme = bins[i][0] + bins[i][5]
        rest = bins[i][1] + bins[i][2] + bins[i][3] + bins[i][4]
        tmp = SBoxes[i][int(extreme, 2)][int(rest, 2)]
        resBin = "{0:04b}".format(tmp)
        res += resBin
    return res


class DES:
    """ DES Encryptor Class """

    def __init__(self, plain: str, key: str):
        """ Init DES encryptor object """
        self.debug_file = open(DEBUG_FILE, "w")  # change to sys.stdout to CLI output
        self.original_text = plain
        self.plain_text = stringToASCII(self.original_text)  # plain text to ascii
        self.initial_key = key
        print(f"Input text ASCII: {self.plain_text}\t"
              f"Input key: {self.initial_key}", file=self.debug_file)   # forward out stream to file

        textLen = len(self.plain_text)
        self.ECBRounds = textLen // 16 + 1 if textLen % 16 != 0 else textLen // 16

        self.splittedText = [self.plain_text[i:i + 16] for i in range(0, len(self.plain_text), 16)]
        print(self.splittedText, file=self.debug_file)
        self.ciphers = []

    def __del__(self):
        self.debug_file.close()

    def init(self):
        """ Start """
        print(f"{newLine} Started encrypting..")
        self.encrypt()  # encryption
        print(f"{newLine} Encryption is done. Saving to file..")
        self.printResult()  # cipher output
        print(f"{newLine} Done. See the result in encrypted.txt.")

    def encrypt(self):
        """ Encryption """
        for currentRound in range(self.ECBRounds):
            print(f"{currentRound + 1}. ECB Round started", file=self.debug_file)

            self.splittedText[currentRound] = self.splittedText[currentRound].ljust(16, '0')  # adding possible padding

            binaryText = ASCIIToBinary(self.splittedText[currentRound])
            print(f"\nBinary representation of plain text: {binaryPrint(binaryText)}", file=self.debug_file)

            asciiKey = stringToASCII(self.initial_key)  # key -> ASCII
            binaryKey = ASCIIToBinary(asciiKey)  # ASCII -> binary representation
            print(f"\nBinary representation of key: {binaryPrint(binaryKey)}", file=self.debug_file)

            permutedText = permutation(binaryText, 64, IP)
            print(f"\nAfter Initial Permutation: {permutedText}", file=self.debug_file)

            print("\nText", end='', file=self.debug_file)
            leftText, rightText = self.splitting(permutedText, 64)

            permutedKey = permutation(binaryKey, 56, PC1)  # permutation using PC1
            print(f"\nKey after PC1 permutation: {permutedText}", file=self.debug_file)

            print("\nKey", end='', file=self.debug_file)
            leftKey, rightKey = self.splitting(permutedKey, 56)

            leftSubkeys = createSubkeys(leftKey)
            rightSubkeys = createSubkeys(rightKey)
            print(f"\nSubkeys:\n"
                  f"Left: {leftSubkeys}\n"
                  f"Right: {rightSubkeys}", file=self.debug_file)

            subkeys = concatAndPermute(leftSubkeys, rightSubkeys)
            print(f"\nPermuted subkeys:\n"
                  f"{binaryPrint(subkeys, 48)}", file=self.debug_file)

            for i in range(16):  # Feistel network
                print(f"{i + 1}. round...", file=self.debug_file)
                nextLeft = rightText

                selected = bitsSelection(rightText)
                print(f"\nResult of bits selection:\n"
                      f"{binaryPrint(selected, 48)}", file=self.debug_file)

                xorResult = xor(selected, subkeys[i])
                print(f"\nL0 XOR f(R{i}, K{i + 1}) result:\n"
                      f"{binaryPrint(xorResult, 48)}", file=self.debug_file)

                splitted = splitBinary(xorResult, 6)
                permutedBins = permuteSBox(splitted)
                print(f"\nPermuted bits using S-boxes:\n"
                      f"{binaryPrint(permutedBins, 32)}", file=self.debug_file)

                permutedBins = permutation(permutedBins, 32, Permutation)
                print(f"\nPermuted bits using P-table:\n"
                      f"{binaryPrint(permutedBins, 32)}", file=self.debug_file)

                xorResult = xor(permutedBins, leftText)
                print(f"\nPermuted bins XOR left:\n"
                      f"{binaryPrint(xorResult, 32)}\n", file=self.debug_file)

                rightText = xorResult
                leftText = nextLeft

                print(f"{line}{i + 1}. round results:\n"
                      f"Left: {binaryPrint(nextLeft, 32)}\n"
                      f"Left: {binaryPrint(rightText, 32)}\n{line}\n", file=self.debug_file)

            swapped = permutation(rightText + leftText, 64, IPreversed)
            print(f"\nBinary final result:\n"
                  f"{binaryPrint(swapped, 64)}", file=self.debug_file)

            cipherASCII = binaryToASCII(swapped)
            print(f"\nASCII final result:\n"
                  f"{cipherASCII}\n", file=self.debug_file)
            print(f"ECB Round finished", file=self.debug_file)

            cipherText = ASCIIToString(cipherASCII)
            self.ciphers.append(cipherText)

        print(f"\n{newLine}Finished.\n{line}", file=self.debug_file)

    def printResult(self):
        """ Print result ciphers """
        res = ""
        for i, cip in enumerate(self.ciphers):
            res += cip

        cipher = ' '.join(hex(ord(x))[2:].zfill(2) for x in res)
        self.saveToFile(cipher)

        input("\n>> CTRL-Z to terminate DES or any key to encrypt again..")

    def saveToFile(self, cipher: str) -> None:
        """ Saving result to file """
        with open(INPUT_FILE, "w") as f:
            f.write(f"Plain text: {self.original_text}\n"
                    f"Initial key: {self.initial_key}\n"
                    f"Cipher: {cipher}")

    def splitting(self, permuted: str, bins: int):
        """ Split string to left and right """
        left = permuted[:round(bins / 2)]  # separate
        right = permuted[round(bins / 2):]
        print(f"after splitting:\n"
              f"Left: {binaryPrint(left, bins)}\n"
              f"Right: {binaryPrint(left, bins)}", file=self.debug_file)
        return left, right
