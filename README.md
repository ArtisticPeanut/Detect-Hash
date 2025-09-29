:

🔐 Hash Identifier CLI

A lightweight Python-based interactive CLI tool to quickly identify the most likely hashing algorithm (MD5, SHA-1, SHA-256, SHA-512, etc.) from a given hash string.
Supports both single hash lookups and batch processing of files.

✨ Features

Detects common hash types based on length & format

Interactive CLI mode (type & analyze on the fly)

Batch mode: process files containing multiple hashes

Simple, dependency-free Python script

Educational tool for security enthusiasts & CTF players

📦 Installation

Clone this repository and cd into it:

git clone https://github.com/ArtisticPeanut/Detect-Hash.git

cd hash-identifier-cli


Run with Python 3:

python hash_identifier.py


No external libraries required 🎉

🚀 Usage
1. Interactive mode
python hash_identifier.py


Example:

Hash Identifier CLI
====================
Enter a hash (or type 'exit' to quit): 482c811da5d5b4bc6d497ffa98491e38
Likely type(s): MD5

2. Batch mode

Prepare a file hashes.txt with one hash per line:

482c811da5d5b4bc6d497ffa98491e38
b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3
2bb80d537b1da3e38bd30361aa855686bde0baefb712b6a2d6c9d3a7a7e9a0d3


Run:

python hash_identifier.py -f hashes.txt


Output:

Hash: 482c811da5d5b4bc6d497ffa98491e38
Likely type(s): MD5
----------------------------------------
Hash: b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3
Likely type(s): SHA-1
----------------------------------------
Hash: 2bb80d537b1da3e38bd30361aa855686bde0baefb712b6a2d6c9d3a7a7e9a0d3
Likely type(s): SHA-256
----------------------------------------

🛡️ Disclaimer

This tool is for educational and defensive purposes only.
Do not use it for illegal activities — use it to learn how to protect systems.

🤝 Contributing

Contributions are welcome!

Fork the repo

Create a feature branch

Submit a pull request

📄 License

MIT License © 2025 Billy Paul
