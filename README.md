# Hashy 
## A Python Hash Generator
### Description:
Hashy is a command-line tool written in Python that allows users to generate hashes using various hashing algorithms. It supports popular hashing algorithms such as MD5, SHA-1, SHA-256, bcrypt, Argon2, and more. This tool is useful for tasks involving data integrity verification, password hashing, and cryptographic operations.

![Alt text](https://raw.githubusercontent.com/j4ik2i5x0/Hashy/main/img/Screenshot%202024-03-25%20002428.png)

### Features:
- **Multiple Hashing Algorithms:** Supports a variety of hashing algorithms, including
   - MD5
   - SHA-1
   - SHA-224
   - SHA-256
   - SHA-384
   - SHA-512
   - blake2s
   - blakw2b
   - RIPEMD-160
   - crc32c
   - bcrypt
   - Argon2
    
- **Customizable Hash Length**: Option to specify the length of the generated hash.
- **Secure Password Storage:** Utilizes bcrypt and Argon2 for secure password hashing, enhancing data security by employing robust cryptographic techniques.
- **Clear Output:** Generates hash values corresponding to selected algorithms with clear and concise output, accompanied by informative descriptions for user guidance.
- **Interactive Mode**: Interactive mode for user-friendly operation with guided prompts.

 ### Installation steps:

1. Clone the repository:
   
   ```bash
   git clone https://github.com/j4ik2i5x0/Hashy/
   ```
2. Install packages required for the tool:
   
   ```bash
   pip install -r requirements.txt
   ```
3. Navigate to the repository directory:

   ```bash
   cd Hashy
   ```
4. Make the script executable:

   ```bash
   chmod +x hashy.py
   ```
5. Move the script to the /usr/bin directory:

   ```bash
   sudo mv hashy.py /usr/bin/hashy
   ```

### After completing these steps, you'll be able to run the Hash tool from any directory in your terminal by simply typing "hashy".

### Usage:

![Alt text](https://raw.githubusercontent.com/j4ik2i5x0/Hashy/main/img/Screenshot%202024-03-25%20002344.png)
   Method-1: Enter the tool name in CLI
  
   ```bash
   hashy
   ```
![Alt text](https://raw.githubusercontent.com/j4ik2i5x0/Hashy/main/img/Screenshot%202024-03-25%20005420.png)
   Method-2: Enter the tool name with the options in CLI

   ```bash
   hashy -d helloworld -a sha512
   ```


> Note : If your script depends on any external libraries not included in the standard Python library, make sure to install them on your Kali Linux system using pip or the appropriate package manager before running the script.
   
### Contributions:
Contributions to Hashy are welcome! If you'd like to contribute, please fork the repository, make your changes, and submit a pull request.
