# Password Cracker

Password Cracker is a C-based application that attempts to crack MD5 hashed passwords using a dictionary file. The dictionary file can contain either plain text passwords or hashed entries. The program uses predefined key ranges for MD5 hashing and can handle both hashed and plain text user inputs.

## Features

- Supports both plain text and hashed dictionary files.
- Can handle both plain text and hashed user inputs.
- Uses predefined key ranges for enhanced MD5 hashing.
- Simple and efficient command-line interface.

## Prerequisites

Before you begin, ensure you have the following installed:

- GCC (GNU Compiler Collection)
- OpenSSL library

## Installation

1. **Install OpenSSL**:

2. **Compile the code**:

`gcc password_cracker.c -o password_cracker -lssl -lcrypto`

## Usage

Run the compiled binary with the required command-line arguments:


`./password_cracker <dictionary_path> <is_hashed> <user_input> <is_input_hashed>`
like this
`./password_cracker /home/bhanu/Desktop/passwords.txt 1 5d41402abc4b2a76b9719d911017c592 1`

- `<dictionary_path>`: Path to the dictionary file.
- `<is_hashed>`: `1` if the dictionary file contains hashed entries in the format `password:hash`, `0` if it contains plain text passwords.
- `<user_input>`: The hashed MD5 sum or plain text password to be cracked.
- `<is_input_hashed>`: `1` if `<user_input>` is a hashed MD5 sum, `0` if it is a plain text password.



### Sample Output

```
Comparing: dictionary='07787964a1e74335c923a46348e1e865', generated='5d41402abc4b2a76b9719d911017c592'
Comparing: dictionary='0acf4539a14b3aa27deeb4cbdf6e989f', generated='5d41402abc4b2a76b9719d911017c592'
Comparing: dictionary='2345f10bb948c5665ef91f6773b3e455', generated='5d41402abc4b2a76b9719d911017c592'
Comparing: dictionary='00bfc8c729f5d4d529a412b12c58ddd2', generated='5d41402abc4b2a76b9719d911017c592'
Comparing: dictionary='aae039d6aa239cfc121357a825210fa3', generated='5d41402abc4b2a76b9719d911017c592'
Comparing: dictionary='5badcaf789d3d1d09794d8f021f40f0e', generated='5d41402abc4b2a76b9719d911017c592'
Comparing: dictionary='5d41402abc4b2a76b9719d911017c592', generated='5d41402abc4b2a76b9719d911017c592'
Match found! Entry: 'hello'
```

## Contributing

Contributions are welcome! Please fork this repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License.
