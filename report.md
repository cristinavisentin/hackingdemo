

<style> 
    body { 
        background-color: white; 
        color: black;
        margin-top: 2.5cm;
        margin-left: 1.5cm;
        margin-right: 1.5cm;
    }
</style>

# titol

For the following demo was decided to follow this *metti link* particular writeup.
So the hacking scenario is the presence of two different vm installed on the physical machine: the first is the vm attacker, a kali linux while the second is the target machine called "Bob"

The initial step is aimed to scan the local network in order to look for the IP address of the target machine. This step is taken running the following command 

```bash
netdiscover -i eth0 -r 10.0.2.0/24
```

For time reasons only the sopracitata subnet was scanned 

Then the command

```bash
nmap -p- -A 10.0.2.10 
```
was performed in order to have a pretty accurate enumeration of the servers, on which port numbers and with which protocols were running on target 

For comodità this IP was added to the file ```/etc/hosts``` on the Kali machine ad linked to the name "hackthebob"

The result of ```nmap``` command is shown in the following screenshot



