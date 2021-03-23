# cryptography

OpenSSL RSA and AES cryptography, RSA signing and verification & more.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

This project is intended for Linux operating systems.
You need `OpenSSL` library to be installed on your machine. Type this command in your terminal:

`openssl version`

If you see something similar to this: `OpenSSL 1.1.1g  21 Apr 2020`, it means that you have OpenSSL installed. Otherwise checkout [OpenSSL](https://www.openssl.org/) for details about installation process.

### Installing

You need a copy of source code. Clone the repository using git:

`git clone https://github.com/m3sserschmitt/cryptography.git` 

OR

Download the `.zip` file and extract it.

Change the directory to newly downloaded source code:

`cd /path/to/local/repository`

Then

`cd build`

You are ready to build the library:

`make`

Last command will create the file `./build/libcryptography.so.*` which can be linked in other C/C++ projects.

Also you can checkout `./tests/main.cc` file for some examples on basic encryption & decryption with AES or RSA, RSA signing & verification with RSA and base64 encoding & decoding.

After you checked out encryption / decryption, you may want to install the library on your system. By default, headers will be located into `/usr/local/include/libcryptography` and library will be located into `/usr/local/lib` directory. Type:

`
sudo make install
`

## Authors

* **Romulus-Emanuel Ruja** <<romulus-emanuel.ruja@tutanota.com>>

## License

This project is licensed under the MIT License. Feel free to copy, modify and distribute it - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This code is just a **proof of concept** of using `OpenSSL` for basic cryptography. Use it on your own risk.

## Changelog

* **_New in version v5.0.0 (March 2021):_**
    * All code was rewritten.
    * AES, RSA (encrypt, decrypt, sign, verify) and base64 available.
    * Not backward compatible.

* **_New in version v4.0.5 (November 2020):_**
    * Code refactoring and bugs fixed.
    * This release it's not backward compatible with previous releases.
