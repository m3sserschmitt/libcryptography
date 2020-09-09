# cryptography

OpenSSL RSA and AES cryptography.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

You need OpenSSL library to be installed on your machine. Type this command in your terminal:

`openssl version`

If you see something similar to this: `OpenSSL 1.1.1g  21 Apr 2020`, it means that you have OpenSSL installed.

### Installing

You need a copy of source code. Download the repository using git:

`git clone https://github.com/m3sserschmitt/cryptography.git`

Extract the source code, then:

`cd /your/source/code/path`

You are ready to build the library from source code:

`make`

Last command will create the file `cryptography.so` which can be linked in other
C/C++ projects.

## Authors

* **Romulus-Emanuel Ruja** (romulus-emanuel.ruja@tutanota.com)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

Keep in mind that this library it's just a **proof of concept** and **not** intended for production use.