# Machine : InfosecPrep

# Vulnerability: Privilege Escalation

# The severity of the issue: High

# Decryption:

	with the vulnerabilty an attacker can gain unauthorized privileged access to a system

# Reproduction :

Going to our browser with the provided IP_Address = 

With it (IP Address of the machine) the first thing got in mind is to grab a series of ports with the use of Nmap

	nmap -a IP_Address
  
Then with The help of Nikto, we can scan web servers for known vulnerabilities 

	nikto --host IP_Address
  

After that we've some directories we've tested the common robots.txt which tells the search engines which directories not to enter :
 
	IP_Address/robots.txt
  
This seems like an interesting place to visit, after that we've got a text seems like a base64 encoded file with the equal the end first guess i thought let's decoded it
 
	wget IP_Address/secret.txt | cat secret.txt | base64 -d > ssh_key.txt 
 
This is actually a private key and based on our previous scan we've noticed a port for ssh connection 22 
 
then we thought why not connect with the user 'oscp' and the host IP_Address using the private key after change their permission (Secure) : 
 
	chmod 600 ssh_key.txt ; ssh -i ssh_key.txt user@IP_Address -p 22 
 
Bingo we've login and we've got our first flag called local;
 
 
Let's scan with a tool just trying to search for possible and available exploits :

though the search we've noticed a suid in the bash builtin command which means we can gain access through a :

	/bin/bash -p
	whoami 

I gain access and I become a root

	cd /root/ ; cat proof.txt
	
Done !
