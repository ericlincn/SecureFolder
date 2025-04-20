# SecureFolder - Folder Encryption Tool

🔒 A simple yet efficient folder encryption/decryption tool with filename obfuscation and batch processing

## Key Features

- **Secure Encryption**: Uses AES-256-CBC encryption with HMAC-SHA256 verification
- **Filename Obfuscation**: Optional hiding of original filenames for enhanced privacy
- **Batch Processing**: Encrypt/decrypt entire folders at once
- **Parallel Processing**: Multi-threading for faster bulk operations
- **Exclusion Filters**: Configurable file and directory exclusions
- **Activity Logging**: Detailed operation logs for auditing

## Use Cases

- Protecting sensitive files and data
- Securely backing up important documents
- Privacy protection before file sharing
- Encrypting files for cloud storage

## Quick Start

### Install Dependencies
```bash
pip install cryptography
```

### Basic Usage
Encrypt a folder:
```bash
python securefolder.py encrypt /path/to/folder
```

Decrypt a folder:
```bash
python securefolder.py decrypt /path/to/folder
```

Encrypt a folder with filename and foldername obfuscation:
```bash
python securefolder.py encrypt /path/to/folder --log --obfuscate
```

Decrypt a folde with filename and foldername obfuscation:
```bash
python securefolder.py decrypt /path/to/folder --log --obfuscate
```

## Complete Parameter Reference
```
usage: securefolder.py [-h] [--password PASSWORD] [--parallel] [--log] 
                      [--log-file LOG_FILE] [--exclude-files [EXCLUDE_FILES ...]]
                      [--exclude-dirs [EXCLUDE_DIRS ...]] [--obfuscate]
                      {encrypt,decrypt} path

positional arguments:
  {encrypt,decrypt}     Encrypt or decrypt
  path                  Target folder path

optional arguments:
  -h, --help            show this help message and exit
  --password PASSWORD   Password (optional, will prompt if not provided)
  --parallel            Enable parallel processing
  --log                 Enable logging
  --log-file LOG_FILE   Specify log file path
  --exclude-files [EXCLUDE_FILES ...]
                        List of files to exclude
  --exclude-dirs [EXCLUDE_DIRS ...]
                        List of directories to exclude
  --obfuscate           Enable filename obfuscation
```

## Technical Details
### Encryption Process
1. Derives encryption and HMAC keys from password using PBKDF2HMAC-SHA256
2. Uses randomly generated salt and IV for each file
3. Encrypts file contents with AES-256-CBC
4. Adds HMAC-SHA256 signature for integrity verification

## Security Notes
1. Always remember your password - lost passwords cannot recover files
2. Test with sample files before processing important data
3. Maintain backups before encryption
4. Avoid processing sensitive files on public computers
5. **When using obfuscation, NEVER delete the .pathmap file - it's essential for filename and foldername recovery**
