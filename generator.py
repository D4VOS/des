import time

import cv2
import numpy as np


def prime_dict():
    arr = primes(264)
    prime_dict = {}
    for value in range(3, 259):
        for i in range(len(arr)):
            if arr[i] == value:
                prime_dict[value] = [arr[i - 1], arr[i + 1]]
                break
            elif arr[i] > value:
                prime_dict[value] = [arr[i - 1], arr[i]]
                break
    return prime_dict


def primes(n):
    """ Input n>=6, Returns a list of primes, 2 <= p < n """
    n, correction = n - n % 6 + 6, 2 - (n % 6 > 1)
    sieve = [True] * (n // 3)
    for i in range(1, int(n ** 0.5) // 3 + 1):
        if sieve[i]:
            k = 3 * i + 1 | 1
            sieve[k * k // 3::2 * k] = [False] * ((n // 6 - k * k // 6 - 1) // k + 1)
            sieve[k * (k - 2 * (i & 1) + 4) // 3::2 * k] = [False] * (
                    (n // 6 - k * (k - 2 * (i & 1) + 4) // 6 - 1) // k + 1)
    return [2, 3] + [3 * i + 1 | 1 for i in range(1, n // 3 - correction) if sieve[i]]


class Video:
    GOLDEN_RATIO = 1.61803398875
    PI = 3.14159265359

    def __init__(self, path):
        captured = cv2.VideoCapture(path)
        self.frame_count = int(captured.get(cv2.CAP_PROP_FRAME_COUNT))  # frames count
        self.height = int(captured.get(cv2.CAP_PROP_FRAME_HEIGHT))  # frame height
        self.width = int(captured.get(cv2.CAP_PROP_FRAME_WIDTH))  # frame width
        self.seed_base = 0

        self.frames = np.empty((self.frame_count, self.height, self.width, 3), np.dtype("uint8"))
        frameIndex = 0
        flag = True
        while (frameIndex < self.frame_count) and flag:
            ret, self.frames[frameIndex] = captured.read()
            frameIndex += 1
        captured.release()  # del captured frames
        del captured

    def __del__(self):
        del self.width
        del self.height
        del self.frames
        del self.frame_count
        del self.seed_base

    def getPixelValue(self) -> int:
        """Returns pixel value based on system clock value"""
        current_time = time.time() * 1000  # get system_clock

        posX = int((current_time + self.seed_base) % self.width)
        self.seed_base = (self.seed_base + self.GOLDEN_RATIO) % 4294967295

        posY = int((current_time + self.seed_base) % self.height)
        self.seed_base = (self.seed_base + self.GOLDEN_RATIO) % 4294967295

        no_frame = (posX * posY) % self.frame_count

        return self.frames[no_frame, posY, posX, ((posX * posY) % 3)]  # [frame_no, height, width, [R,G,B]]


class Generator:
    M = 257

    def __init__(self, video: Video, output_path: str):
        self.source = video
        self.output = output_path
        self.result = self.source.getPixelValue()
        self.primes = prime_dict()

    def __del__(self):
        del self.primes
        del self.source
        del self.output
        del self.result

    def next(self):
        while True:
            f = self.source.getPixelValue() + 3
            previous_prime, next_prime = self.primes[f]

            a = previous_prime * next_prime  # incr
            b = (f * previous_prime * next_prime) % self.M  # multi
            x = (self.result * b + a) % self.M  # next

            if x not in [0, self.result]:
                self.result = x - 1
                return self.result
