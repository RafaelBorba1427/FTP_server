# C++ FTP Server and Client

A learning project implementing a basic FTP server and command-line client in C++17, using standalone Asio for networking and Linux PAM for authentication.

## Features

- Authentication with local Linux accounts through PAM
- Passive data connections
- File uploads and downloads
- Directory navigation, creation, and deletion
- File renaming
- Asynchronous server replies with a queue to preserve their order

## Dependencies

- A C++ compiler supporting C++17
- Make
- Standalone Asio
- Linux PAM headers and library
- libsodium, currently included and linked by the server

## PAM Configuration

PAM (Pluggable Authentication Modules) lets the server authenticate users through the operating system.

The server selects the service name `myftp` when calling `pam_start()`. On Arch Linux, create `/etc/pam.d/myftp` with:

```text
#%PAM-1.0
auth    include system-auth
account include system-auth
```

Creating this file requires administrator permission.

Each line has a specific purpose:

- `#%PAM-1.0` is a conventional comment identifying the file as a PAM configuration.
- `auth include system-auth` uses the authentication rules in `/etc/pam.d/system-auth` to verify the supplied credentials.
- `account include system-auth` uses that file's account rules to check whether the authenticated account is allowed access, including expiration and other restrictions.

`include` imports rules of the corresponding type. The first rule imports authentication rules; the second imports account-validation rules.

Users log in with an existing Linux username and its password. A correct password alone does not guarantee access: the account must also pass the configured account checks.

PAM verifies credentials without exposing the stored password to the server. Authentication does not change the filesystem permissions of the process running the FTP server.

## Running

From the project directory, compile both programs before starting them:

```bash
make
```

Then start the server:

```bash
./Server
```

In another terminal, open the same project directory and start the client:

```bash
./Client
```

Run `make` again after changing the source files, then restart the affected program.

Both programs currently use `127.0.0.1:2121`, so they communicate on the same computer.

## Commands

| Command | Purpose |
|---|---|
| `PWD` | Show the server's current directory |
| `CWD directory` | Change directory |
| `PASV` | Prepare a passive data connection |
| `LIST` | List directory entries |
| `STOR filename` | Upload a local file |
| `RETR filename` | Download a server file |
| `MKD directory` | Create a directory |
| `DELE filename` | Delete a file |
| `RMD directory` | Remove an empty directory |
| `RNFR filename` | Begin renaming a file |
| `RNTO new-name` | Complete the rename |
| `QUIT` | Disconnect |

The client negotiates passive mode automatically for transfers when needed. After `RNFR`, it prompts for the destination name.

Downloads are saved in the client's working directory using the remote file's basename. Existing destination files are overwritten.

## Current Limitations

- This implements a subset of FTP; compatibility with arbitrary FTP clients has not been verified.
- Active mode, TLS, and commands such as `TYPE`, `SYST`, and `EPSV` are not implemented.
- Directory listings currently contain paths rather than a conventional FTP listing format.
- Credentials and file data travel without encryption.
- The client currently displays the password while it is entered.
- The initial directory is not an enforced filesystem boundary.

The updated client and server compile successfully. End-to-end manual testing is still pending.

## Planned Improvements

- Add TLS support (FTPS) to encrypt authentication credentials and file transfers.

## Acknowledgments

The PAM authentication implementation was adapted from
[OpenBMC's bmcweb](https://github.com/openbmc/bmcweb/blob/master/include/pam_authenticate.hpp).

The referenced code carries an Apache-2.0 license notice.
