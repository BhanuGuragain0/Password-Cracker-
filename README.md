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
Comparing: dictionary='0ae59ed3a84c4e78b3cdc7b483da3d5a', generated='69a329523ce1ec88bf63061863d9cb14'
Comparing: dictionary='47c7f26eea02b53f49937fc90bef32a6', generated='69a329523ce1ec88bf63061863d9cb14'
`Match found! Entry: 'hello'`
```

## Contributing

Contributions are welcome! Please fork this repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License.

