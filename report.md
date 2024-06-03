<style> 
    body { 
        background-color: white; 
        color: black;
        margin-top: 2.5cm;
        margin-left: 1.5cm;
        margin-right: 1.5cm;
    }
</style>

# Hack The Bob: 1.0.1

- [**Discovery**](disco) &rightarrow; network scanning and services enumeration
- [**Initial Access**](ini) &rightarrow; expoit RCE vulnerability on web application
- [**Execution**](exe) &rightarrow; establish reverse shell with netcat
- [**Credential Access**](cre) &rightarrow; use of unsecured credentials
- [**Privilege Escalation**](pri) &rightarrow; abuse of valid accounts with root privileges
- [**Persistence**](per)

The aim of this demo is to gain root priviledges on a web server in order to capture flag. The "[Hack The Bob: 1.0.1](https://www.hackingarticles.in/hack-the-bob-1-0-1-vm-ctf-challenge/)" walkthorugh is the baseline of this report.


The initial step is aimed to scan the local network in order to look for the IP address of the target machine. This step is taken running the following command 

```bash
netdiscover -r 10.0.2.0/24
```

Then the command

```bash
nmap -p- -A 10.0.2.10 
```
was performed in order to have a pretty accurate enumeration of the servers, on which port numbers and with which protocols were running on target 

For comodità this IP was added to the file ```/etc/hosts``` on the Kali machine ad linked to the name "hackthebob"

The result of ```nmap``` command is shown in the following screenshot

[primo screenshot](nmap output.gpg)



Interesting things to notice:
- there is a web server reachable via HTTP on port 80 
- there is an ssh server listening on port 25468


