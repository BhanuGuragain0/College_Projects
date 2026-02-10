

```markdown
# Password Cracker

Password Cracker is an advanced, C-based password cracking tool that attempts to crack hashed passwords (MD5 and SHA256) using a dictionary file. The dictionary file can contain either plain text passwords or hashed entries. The tool leverages predefined key ranges for enhanced salting and includes configurable thread count, signal handling for graceful shutdown, and performance measurement. It is designed for efficient, real-world usage.

## Features

- **Dual Dictionary Support:**  
  Works with both plain text and hashed dictionary files.

- **Flexible Input Handling:**  
  Accepts both plain text and pre-hashed user inputs.

- **Multiple Hash Algorithms:**  
  Supports MD5 and SHA256 hashing.

- **Enhanced Salting:**  
  Uses a predefined key range to improve hash diversity and cracking potential.

- **Configurable Thread Count:**  
  Optimize performance by setting the number of worker threads.

- **Graceful Shutdown:**  
  Supports SIGINT/SIGTERM to safely terminate processing.

- **Performance Measurement:**  
  Displays the total processing time for each cracking attempt.

- **Simple Command-Line Interface:**  
  Easily run the tool with a few parameters.

## Prerequisites

Before you begin, ensure you have the following installed:

- **GCC (GNU Compiler Collection)**
- **OpenSSL library**

### Installing OpenSSL

- **Ubuntu/Debian:**  
  `sudo apt-get install libssl-dev`

- **CentOS/Fedora:**  
  `sudo yum install openssl-devel`

- **macOS (with Homebrew):**  
  `brew install openssl`

## Installation

1. **Compile the Code:**

   ```bash
   gcc password_cracker.c -o password_cracker -lssl -lcrypto -lpthread
   ```

## Usage

Run the compiled binary with the required command-line arguments:

```bash
./password_cracker <dictionary_path> <is_hashed> <user_input> <is_input_hashed> <algorithm> [num_threads]
```

### Example

```bash
./password_cracker /home/user/passwords.txt 1 5d41402abc4b2a76b9719d911017c592 1 md5 4
```

Where:
- `<dictionary_path>`: Path to the dictionary file.
- `<is_hashed>`: `1` if the dictionary file contains hashed entries, `0` if it contains plain text passwords.
- `<user_input>`: The hashed value (MD5/SHA256) or plain text password to be cracked.
- `<is_input_hashed>`: `1` if `<user_input>` is already hashed, `0` if it is plain text.
- `<algorithm>`: The hash algorithm to use (`md5` or `sha256`).
- `[num_threads]`: *(Optional)* Number of threads to use (default is 4).

## Sample Output

```
Generated hash for input 'hello': 5d41402abc4b2a76b9719d911017c592
Processing dictionary '/home/user/passwords.txt' using 4 thread(s)...
Match found! Entry: 'hello', Key: 'FD469501'
Processing complete in 0.532 seconds.
```

## Contributing

Contributions are welcome! Please fork this repository, create a feature branch, and submit a pull request. For major changes, open an issue first to discuss your proposed modifications.

## License

This project is licensed under the MIT License.
```

