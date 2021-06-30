# DES Encryptor

> DES is a symmetric-key algorithm for the encryption of digital data. Although its short key length of 56 bits makes it too insecure for applications,
> it has been highly influential in the advancement of cryptography. [Wikipedia]


### What is it for?
In a nutshell, a program to encrypt text using a key.


### How to use it?
After executing `python main.py`, you will be prompted to enter the ASCII text you want to encrypt. If you leave the field blank, you will be asked for
the name of the text file from which the text will be loaded. It is similar with entering the key, but it will be generated online using a [generator].

You can find the result of the encryption in the file `encrypted.txt`.

### Output
- `encrypted.txt` file with result of encryption
- `debug.txt` file with the debug stuff of the encryption process

### Requirements
- `opencv-python`
- `numpy`

[Wikipedia]:<https://en.wikipedia.org/wiki/Data_Encryption_Standard>
[generator]:<https://github.com/D4VOS/true-random-number-generator>