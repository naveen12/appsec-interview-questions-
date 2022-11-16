# appsec-interview-questions-



Read request headers
Read response headers
Asset: An asset is any data, device or other component of an organization's systems that is valuable
Threat: Anything that can exploit a vulnerability, intentionally or unintentionally, to obtain, damage or destroy an asset.
Vulnerability: Weaknesses or gaps in a network, software or system that can be exploited by any threats to gain unauthorized access to an asset
Risk: Risk is any potential loss of, damage, or destruction of an asset as a result of threat exploiting a vulnerability. Risk is the intersection of assets, threats and vulnerabilities.
What is a Document object model (Dom) ?
The Document Object Model (DOM) is a programming API for HTML and XML documents. It defines the logical structure of documents and the way a document is accessed and manipulated.
what is the difference between cors and csp
SameOriginPolicy is the default policy followed in all browsers which prevents data sharing between two different domains.
Cross Origin resource sharing (CORS) provides relaxation to SameOriginPolicy which enables data sharing between two domains in a secure way if it is configured properly. CORS can set a policy to allow xyzapp.com to access details from abcapp.com/userinfo by setting CORS Header in abcapp.com application as
Content Security Policy(CSP) header is used to define what content can run on its own domain. For example, abcapp.com domain wants to access a javascript library only from “userscripts.example.com” and not from any other third-party libraries then abcapp.com can set the header as
what is xxe
This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser
There are various types of XXE attacks:
Exploiting XXE to retrieve files, where an external entity is defined containing the contents of a file, and returned in the application's response.
Exploiting XXE to perform SSRF attacks, where an external entity is defined based on a URL to a back-end system.
XXE via file upload
XXE attack via modified content type
 
Exploiting blind XXE exfiltrate data out-of-band, where sensitive data is transmitted from the application server to a system that the attacker controls.
Exploiting blind XXE to retrieve data via error messages, where the attacker can trigger a parsing error message containing sensitive data.
 
Mitigations:-
Whenever possible, use less complex data formats such as JSON, and avoid serialization of sensitive data.
Patch or upgrade all XML processors and libraries in use by the application or on the underlying operating system. Use dependency checkers. Update SOAP to SOAP 1.2 or higher.
Disable XML external entity and DTD processing in all XML parsers in the application, as per the OWASP Cheat Sheet 'XXE Prevention'.
Implement positive ("whitelisting") server-side input validation, filtering, or sanitization to prevent hostile data within XML documents, headers, or nodes.
Verify that XML or XSL file upload functionality validates incoming XML using XSD validation or similar.
SAST tools can help detect XXE in source code, although manual code review is the best alternative in large, complex applications with many integrations
Avoid allowing application functionality that parses XML documents
Implement input validation that prevents malicious data from being defined with the SYSTEM identifier portion of the entity within the document type declaration (DTD)
Configure the XML parser to not validate and process any declarations within the DTD
Configure the XML parser to not resolve external entities within the DTD

what is xss
Definition:-
Cross-site scripting (XSS) is a flaw in a web application that allows an attacker to execute malicious JavaScript through a code injection attack in another victim’s browser.

Types():- there are 3 types
Persistent
A persistent XSS also was known as stored XSS because through this vulnerability the injected malicious script gets permanently stored inside the web server and the application server gives it back to the user when he visits the respective website.
Non-Persistent
The non-persistent XSS is also known as reflected XSS occurs when the web application responds immediately on user’s input without validating the inputs that lead an attacker to inject browser executable code inside the single HTML response. The malicious script does not get stored inside the web server, therefore the attacker will send the malicious link through phishing to trap the user.
DOM Based XSS (TYPE 0):
The DOM-Based Cross-Site Scripting is a vulnerability which appears in a document object model instead of the html page. An attacker is not allowed to execute malicious script on the website although on his local machine in URL, it is quite different from reflected and XSS because in this attack developer cannot able to find malicious script in HTML source code as well as in HTML response, it can be observed at execution time.
Script: <script>alert(document.cookie)</script>
Mitigation: 
sanitize all untrusted data, even if it is only used in client-side scripts. 
always use user input in the text context, never as HTML tags or any other potential code.
Countermeasures / Preventions:-
Input validation
Strong output encoding
Do not use blacklist
Watch out for canonicalization error
Never Insert Untrusted Data from non-allowed Locations
Avoid JavaScript URL's
Prevent DOM-based XSS
Use HTTPOnly cookie flag
Implement Content Security Policy
Use an Auto-Escaping Template System
Use the X-XSS-Protection Response Header	
URL Escape Before Inserting Untrusted Data into HTML URL Parameter Values
Sanitize HTML Markup with a Library Designed for the Job
Properly use modern JS frameworks

XSS Filter Bypass Techniques
Character encoding tricks (in payload encode one character ex: <a href="&#106;avascript:alert('Successful XSS')">Click this link!</a>)
Whitespace embedding (in payload use spaces ex: <img src="java    script:al ert('Successful XSS')">)
Tag manipulation (in payload add tags extra ex: <scr<script>ipt>document.write("Successful XSS")</scr<script>ipt>)
Internet explorer abuse (use payloads in ie browser ex: <a href='vbscript:MsgBox("Successful XSS")'>Click here</a>)
Legacy methods (<body background="javascript:alert('Successful XSS')">)

what is sql injection
Definition:- SQL injection is a technique where a malicious user can inject SQL Commands into an SQL statement via a web page
In Band:- 
The attacker uses the same channel of communication to launch their attacks and to gather their results. In-band SQLi’s simplicity and efficiency make it one of the most common types of SQLi attack. There are two sub-variations of this method:
i). Error-based SQLi—the attacker performs actions that cause the database to produce error messages. The attacker can potentially use the data provided by these error messages to gather information about the structure of the database.
ii). Union-based SQLi—this technique takes advantage of the UNION SQL operator, which fuses multiple select statements generated by the database to get a single HTTP response. This response may contain data that can be leveraged by the attacker.
Inferential (Blind) SQLi:- 
The attacker sends data payloads to the server and observes the response and behavior of the server to learn more about its structure. This method is called blind SQLi because the data is not transferred from the website database to the attacker, thus the attacker cannot see information about the attack in-band.
Blind SQL injections rely on the response and behavioral patterns of the server so they are typically slower to execute but may be just as harmful. Blind SQL injections can be classified as follows:
i). Boolean:-  that attacker sends a SQL query to the database prompting the application to return a result. The result will vary depending on whether the query is true or false. Based on the result, the information within the HTTP response will modify or stay unchanged. The attacker can then work out if the message generated a true or false result.
ii). Time-based:- attacker sends a SQL query to the database, which makes the database wait (for a period in seconds) before it can react. The attacker can see from the time the database takes to respond, whether a query is true or false. Based on the result, an HTTP response will be generated instantly or after a waiting period. The attacker can thus work out if the message they used returned true or false, without relying on data from the database.
Ex: ,(select * from (select(sleep(10)))a)
%2c(select%20*%20from%20(select(sleep(10)))a)
';WAITFOR DELAY '0:0:30'--
 
Out-of-band SQLi
The attacker can only carry out this form of attack when certain features are enabled on the database server used by the web application. This form of attack is primarily used as an alternative to the in-band and inferential SQLi techniques..
Countermeasures / Preventions:-
Primary Defenses:
Input validation
Use whitelist
Use strongly typed parameterised query API
Use stored procedure
Enforce least privileges
Avoid detailed error messages
Do not use dynamic query interface
Do not use simple escaping functions
Escaping All User Supplied Input
Watch out for canonicalization error
Avoid accessing external interpreters whenever possible


Command injection ?
No

What is a Parameterized query ?
Parameterized query:- its a query in which placeholders are used for parameters and the parameter values are supplied at execution time.
What is Stored procedure
A stored procedure is a prepared SQL code that you can save and it can be reused over and over again. We can also pass parameters to a stored procedure, so that the stored procedure can act based on the parameter value(s) that is passed.
what is csrf
Definition: CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated.
CSRF have another name Session riding
	Examples include:
Submitting or deleting a record.
Submitting a transaction.
Purchasing a product.
Changing a password.
Sending a message.
Mitigation:-
A CSRF token is a secure random token (e.g., synchronizer token or challenge token) that is used to prevent CSRF attacks. The token needs to be unique per user session and should be of large random value to make it difficult to guess
Use samesite(Strict, None, Lax) attribute in cookie
CSRF bypass techniques
Using a existing csrf token across accounts(login A/ collect csrf token / logout /loginB use first collected CSRF token )
Replacing value of same length
Removing the CSRF token from request entirely 
Decode CSRF token
Extracting token via HTML injection
Using only the static parts of the token

what is the privilege escalation and types
horizontal privilege escalation:An attacker acts as a specific user and gains access to resources belonging to another user with a similar level of access.
Vertical privilege escalation: when the attacker gains higher privileges, most often root privileges (administrative privileges).
what is Second order sql injection
a user is supplying a sql statement which is stored by the application. Later that statement is used by the same user on the same web application to perform the attack
Mitigations: 
use parameterized queries which are also known as prepared statement
use stored procedures for database access
double up any single quotation marks appearing within user input before incorporating that input into a SQL query
	Example:- In this example, the data submitted by the user will be parameterized meaning that a vicious input will not affect the database. Now as the statement is parametrized if the following MySql is submitted  user = '; DROP TABLE Users; --
For example, we have a list user page in the admin panel of an application and for speed the developer wrote a basic select script, skipping the use of parameterized variables as they believed the data must be fine in the following database. The simple MySQL statement:
$sql = "SELECT * FROM user WHERE username = '{$userName}'";
$stmt = $conn->query($sql);
$user = $stmt->fetch();
Now becomes SELECT * FROM user WHERE username = ''; DROP TABLE User; --';

what is algorithm used in SSL
SSL uses symmetric cryptography using the session key after the initial handshake is done. The most widely used symmetric algorithms are AES-128, AES-192 and AES-256.
what is SSL handshaking
The SSL handshake is an asymmetric cryptography which allows the browser to verify the web server, get the public key and establish a secure connection before the beginning of the actual data transfer.
The client sends a "client hello" message. This includes the client's SSL version number, cipher settings, session-specific data and other information that the server needs to communicate with the client using SSL.
The server responds with a "server hello" message. This includes the server's SSL version number, cipher settings, session-specific data, an SSL certificate with a public key and other information that the client needs to communicate with the server over SSL.
The client verifies the server's SSL certificate from CA (Certificate Authority) and authenticates the server. If the authentication fails, then the client refuses the SSL connection and throws an exception. If the authentication succeeds, then proceed to step d.
The client creates a session key, encrypts it with the server's public key and sends it to the server. 
The server decrypts the session key with its private key and sends the acknowledgement to the client encrypted with the session key.

What is ServerSideTemplate injection
attacker injects malicious input into a template to execute commands on the server-side. This vulnerability occurs when invalid user input is embedded into the template engine which can generally lead to remote code execution (RCE).
Mitigation:
Sanitization: Sanitize user input before passing it into the templates to minimize vulnerabilities from any malicious.
Sandboxing: In case using risky characters is a business need, it is recommended to use a sandbox within a safe environment.

what is Ping explain process
the ping command sends out an echo request. If it finds the target system, the remote host sends back an echo reply.
what is SSL pinning
SSL Pinning is a technique to prevent MITM attacks. This security measure pins the identity of trustworthy certificates on mobile apps and blocks unknown documents from the suspicious servers.
Advantages of SSL Pinning
Enhanced user privacy and in-app data security
Cost reduction
Reduces threat of compromised certificates
Reduces exposure of user device malware and eavesdropping
Reports Man-in-the-middle attacks
Limitations of SSL Pinning
Less flexibility to change certificates – By pinning an app, it becomes cumbersome to change the security certificate. You must update an android app and send it again to Google play for your users to reinstall it.
Further, when the app has a pinned SSL certificate, it is hard to introduce any additional security solutions, which functions on reverse proxy technology due to SSL termination.

what is the approach to test android application
1.Discovery 2) Assessment and analysis 3) Exploitation 4) Reporting

https://docs.google.com/document/d/16RLGBknUYnduYR6ADq-n8M-sAyS4g6lgw4jPo_Vm56I/edit#heading=h.ez9jf8645yxd 
what is the approach to test Thick client application
The process is 4 steps: 1. Information gathering, 2. Client side attacks, 3. Network side attacks, 4. Server side attacks
Detailed explanation visit   https://docs.google.com/document/d/1HLj5PaBk5jF57cSrmj1lku8QUWaoc0CTL6Nmb6MvXOs/edit#heading=h.2uqrb2nnt5s2 

What is the dll hijacking and dllinjection, difference
DLL Hijacking is a way for attackers to run unwanted code on your system. This means that if an attacker can get a file/program on your system (by social engineering, remote control, etc.) that file could be performed when the user runs an application that is vulnerable to DLL Hijacking.
DLL injection is a method used for running code within the address space of another process by forcing it to load a dynamic-link library. DLL injection is often used by outer programs to manipulate the performance of another program in a way its creators did not expect or intend.

Test cases, Business test cases
What is session hijacking and session fixation attacks
Session hijacking and Session fixation are both attacks that attempt to gain access to a user’s client and web server session
session hijacking: the attacker attempts to steal the ID of a victim's session after the user logs in. 
session fixation: the attacker already has access to a valid session and tries to force the victim to use that particular session for his or her own purposes. The session fixation attack “fixes” an established session on the victim's browser, so the attack starts before the user logs in.
Tools:- Javasnoop, SQLmap commands, burp 
SSRF attack ? difference between CSRF and SSRF ?
Owasp ASVS
Active scan & passive scan
Active scanners send transmissions to the network's nodes, examining the responses they receive to evaluate whether a specific node represents a weak point within the network.
Passive scanners identify the active operating systems, applications and ports throughout a network, monitoring activity to determine the network's vulnerabilities
Cover android testing flow and some test cases, ssl pinning, 
how to bypass otp
how to bypass bruteforce
What is the assessment process to approach thick client application to do
What is the assessment process to 
What authentication and Authorization
In simple terms, authentication is the process of verifying who a user is, while authorization is the process of verifying what they have access to.
Root detection in Android device
Attackers can ‘root’ a device in order to bypass the Android application sandbox
How to bypass Root detection
After finding the XXE vulnerability what you will do ? how you will exploit it ?
Buffer overflow:
Definition:
Buffers are memory storage regions that temporarily hold data while it is being transferred from one location to another. A buffer overflow (or buffer overrun) occurs when the volume of data exceeds the storage capacity of the memory buffer. As a result, the program attempting to write the data to the buffer overwrites adjacent memory locations.
What is Http Parameter pollution
HTTP Parameter Pollution (HPP) is a vulnerability in which an attacker appends extra parameters to an HTTP request making a website perform unexpected behavior.


What are the HTTP Security Headers
X-Frame-Options (it prevents clickjacking attack)
X-XSS-Protection ( it prevents XSS)
X-Content-Type-Options ( To prevent the browser from sniffing the page's content and deciding on which MIME type to use, use the X-Content-Type-Options header with the nosniff directive)
X-Download-Options
Content-Security-Policy (which allows only specific data from website)
Strict-Transport-Security (it restrict web app to use SSL connection only)
Referrer policy (it gives some reference to a web-A when it directed to web-B)
 Cookie Attributes
Secure
Domain
Path
HTTPOnly
Expires

What is Password Salting ?
Password Salting is a technique used to help protect passwords stored in a database from being reverse-engineered by hackers who might breach the environment. Password salting involves adding a string of between 32 or more characters to a password and then hashing it

What is HSTS ?
HSTS stands for HTTP Strict Transport Security. It is a method used by websites to declare that they should only be accessed using a secure connection (HTTPS). If a website declares an HSTS policy, the browser must refuse all HTTP connections and prevent users from accepting insecure SSL certificates.

How HSTS works ?
Typically, when you enter a URL in the web browser, you skip the protocol part. For example, you type www.acunetix.com, not http://www.acunetix.com. In such a case, the browser assumes that you want to use the HTTP protocol so it makes an HTTP request to www.acunetix.com.
At this stage, the web server replies with a redirect (301 response code) that points to the HTTPS site. The browser makes an HTTPS connection to www.acunetix.com. This is when the HSTS security policy protection begins using an HTTP response header:
Ex: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

HSTS max-age is refreshed every time your browser reads the header and the maximum value is two years. This means that the protection is permanent as long as no more than two years pass between your visits

**The only currently known method that could be used to bypass HSTS is an NTP-based attack. If a computer is vulnerable to an NTP attack, an attacker can trick the computer into expiring the HSTS policy and access a web application once with HTTP requests

What is cross frame scripting ?
Cross-Frame Scripting is a web attack technique that exploits specific browser bugs to eavesdrop on the user through JavaScript. This type of attack requires social engineering and completely depends on the browser selected by the user, therefore it is perceived as a minor web application security threat.

XFS attack is possible when below conditions met
all the following conditions must be met:
1. The website or web application must be vulnerable to XFS attacks and must control valuable user input (login data or other sensitive information).
2. The attacker must place malicious JavaScript code on a web page that they control.
3. The attacker must use social engineering (e.g. a phishing attack) to trick the victim to visit the web page that the attacker controls.
4. The victim must use a vulnerable browser version (for example, IE6 on Windows XP)

Preventions: 
Framebusting: The legitimate website owner only needs to modify the web page HTML code.
The Content-Security-Policy: frame-ancestors header: The legitimate website owner must modify web server configuration and have this header automatically included with every page.
The X-Frame-Options header: The legitimate website owner must modify web server configuration and have this header automatically included with every page.


What is HTTPOnly ?
If we set HTTPOnly attribute on cookie then cookie value cannot read or set by client side java script. It protects from Xss attacks
Ex: Set-Cookie: sessionid=QmFieWxvbiA1; HttpOnly

Other Flags For Secure Cookies
The HttpOnly flag is not the only flag that you can use to protect your cookies. Here are two more that can be useful.

Secure Flag
The Secure flag is used to declare that the cookie may only be transmitted using a secure connection (SSL/HTTPS). If this cookie is set, the browser will never send the cookie if the connection is HTTP. This flag prevents cookie theft via man-in-the-middle attacks.
Ex: Set-Cookie: sessionid=QmFieWxvbiA1; HttpOnly; Secure

SameSite flag
The SameSite flag is used to declare when web browsers should send the cookie, depending on how a visitor interacts with the site that set the cookie. This flag is used to help protect against cross-site request forgery (CSRF) attacks.

The SameSite attribute may have one of the following values:

SameSite=Strict: The cookie is only sent if you are currently on the site that the cookie is set for. If you are on a different site and you click a link to a site that the cookie is set for, the cookie is not sent with the first request.
SameSite=Lax: The cookie is not sent for embedded content but it is sent if you click on a link to a site that the cookie is set for. It is sent only with safe request types that do not change state, for example, GET.
SameSite=None: The cookie is sent even for embedded content.
Ex: Set-Cookie: sessionid=QmFieWxvbiA1; HttpOnly; Secure; SameSite=Strict


what is http trace
The HTTP TRACE method is designed for diagnostic purposes. If enabled, the web server will respond to requests that use the TRACE method by echoing in its response the exact request that was received. the TRACK method works in the same way but is specific to Microsoft’s IIS web server.
What is Cross site tracing ?
Cross-site tracing (XST) is an advanced form of cross-site scripting that can pass protection measures against cross-site scripting. XST allows attackers to get authentication data like session cookies using a simple client-side script. It starts with a compromised server: when a user visits such a server, it downloads the malicious code that sends HTTP TRACE requests to other websites. As a response, these websites send authentication data to the compromised server, which in turn can be later used by attackers to launch further attacks.

Though XST is a form of XSS, it is a bit different from XSS. XST relies on HTTP TRACE method whereas XSS relies on HTTP GET and POST methods. Otherwise, they both can perform almost the same level of damage to the victims.

XST could be used as a method to steal user’s cookies via Cross-site Scripting (XSS). This will even work if the cookie has the “HttpOnly” flag set and/or exposes the user’s Authorization header.
Ex: https://www.blackhillsinfosec.com/three-minutes-with-the-http-trace-method/

What happens if the response contains a valid session ?
As per the security concern it not recommended 

What type of attacks possible in response modifier  (Response manipulation attacks)

What does Burp Intruder do ? What type of attacks are there when we have to use ?
Sniper:- This uses a single set of payloads. It targets each payload position in turn, and places each payload into that position in turn.  The total number of requests generated in the attack is the product of the number of positions and the number of payloads in the payload set.
Uses one payload set to payload position

Battering Ram:- This uses a single set of payloads. Sends the same payload into all of the defined payload positions at once. The total number of requests generated in the attack is the number of payloads in the payload set.
Use one payload set to different positions

PitchFork:- This uses multiple payload sets for each position. It places the first payload set in the first position, the second payload set in the second position 
Use same number of payload set and position; no permutations

Cluster bomb:- This uses multiple payload sets. There is a different payload set for each defined position (up to a maximum of 20). The attack iterates through each payload set in turn, so that all permutations of payload combinations are tested. The total number of requests generated in attack is equal to payload sets permutation.

By using Burp intruder what type of attacks are possible ?
It is a fuzzer. This is used to run a set of values through an input point. The values are run and the output is observed for success/failure and content length. Usually, an anomaly results in a change in response code or content length of the response. BurpSuite allows brute-force, dictionary file and single values for its payload position. The intruder is used for:
Brute-force attacks on password forms, pin forms, and other such forms.
The dictionary attack on password forms, fields that are suspected of being vulnerable to XSS or SQL injection, file path traversal
Testing and attacking rate limiting on the web-app.


How to bypass client side validation ?
By inspecting the web page we can disable validations
By intercepting the request we can insert malicious script

Java based thick client application testing process and different tools
https://www.cyberark.com/resources/threat-research-blog/thick-client-penetration-testing-methodology 
Procedure https://medium.com/@david.valles/security-testing-of-thick-client-application-15612f326cac 
https://www.happiestminds.com/wp-content/uploads/2016/03/Thick-client-application.pdf 

Read owasp testing guide


What is Local file inclusion (LFI)?
An attacker can use Local File Inclusion (LFI) to trick the web application into exposing or running files on the web server.
An LFI attack may lead to information disclosure, remote code execution, or even Cross-site Scripting (XSS).

What is Remote File inclusion (RFI) ?
Remote file inclusion attacks usually occur when an application receives a path to a file as input for a web page and does not properly sanitize it.
never include files based on user input if not possible then use Whitelist

What is a threat vector ??
A threat vector is a path or a means by which a cybercriminal gains access through one or more of six main routes into a computer system by exploiting a route vulnerability
What is threat surface
threat surface refers to all the available endpoints that a threat actor may attempt to exploit in Internet-connected devices within the cyber threat environment.
Dll hijacking ?
DLL hijacking is an attack that exploits the Windows search and load algorithm, allowing an attacker to inject code into an application through disk manipulation. In other words, simply putting a DLL file in the right place causes a vulnerable application to load that malicious DLL
How it works? 
a Windows application needs to be tricked into loading an infected DLL file instead of the legitimate DLL. By exploiting the publicized DLL search order of Microsoft applications, this trickery is relatively simple to execute. The standard DLL search order of Microsoft applications depends upon whether safe DLL search is enabled.
If a cybercriminal deposits an infected DLL file in this location, the application will open it instead of the original because its location was searched first, before the system directory.
This technique is also known as DLL search order hijacking.
Prevention:
Keep antivirus software up-to-date
Educate staff about phishing and social engineering warning signs
Strengthen your security posture
 


Dll injection ?
DLL injection is used to manipulate the execution of a running process. Most DLL injection attacks are performed to do reverse engineering attacks.

DLL injection can be divided into 4 steps-
1. Attach to the process
2. Allocate Memory within the process
3. Copy the DLL or the DLL Path into the processes memory and determine appropriate memory addresses
4. Instruct the process to Execute your DLL
Prevention:
we need to ensure no untrusted process gets Administrator access as your application. 
The other way is to have an updated antivirus software; though antivirus software can’t be fully trusted always, 
it is generally recommended to download software from genuine websites.
What is Process hooking and process injection
Hooking is a technology for intercepting function calls in other processes
Echo mirage tool  ?
Android manifest file ?
The AndroidManifest.xml file contains information of your package, including components of the application such as activities, services, broadcast receivers, content providers etc.
Soap accepts which type of request ? xml or Json ?
SOAP is a protocol that means a set of rules. JSON is an object.
SOAP can use JSON for communication, but the reverse is not at all possible.
SOAP uses XML format, whereas JSON uses a key-value pair.
The error message can be declared with SOAP, but the same is not possible with JSON.
Postman accepts which type of request ? xml or Json ?
Yes. it supports both
Difference between Web service and API
KEY DIFFERENCE
Web service is a collection of open source protocols and standards used for exchanging data between systems or applications whereas API is a software interface that allows two applications to interact with each other without any user involvement.
Web service is used for REST, SOAP and XML-RPC for communication while API is used for any style of communication.
Web service supports only HTTP protocol whereas API supports HTTP/HTTPS protocol.
Web service supports XML while API supports XML and JSON.
All Web services are APIs but all APIs are not web services.

Name the tools other than SoapUI and Postman to test API’s
Fiddler, karate, dsl, parasoaft
DOM xss ? how it occurred ? why it occurred ? Preventions
SSRF - complete
SSRF is a class of vulnerability that lets you make requests from a backend server to internal or external systems. 
Ex:
Let’s say you have an e-commerce website that has different servers on the backend. The application has different categories with various products in each category, and the specifications for a product are stored on a different service. So, when you click on a product, the current server (where the application is hosted) sends a request to the other server to get specifications for the product. For simplicity, let’s consider that the request is as follows: 
https://bestproducts.com/products?url=https://productspecs.com/specs?id=34
So the server is sending a request to the productspecs server to send details for the product with id 34. When this request is made, the productspecs server will find details for that product and send it to the main server. And the main server will display the contents. This setup is vulnerable to SSRF. 
In this example of a request, hackers can manipulate the URL parameter to make malicious requests. For example, let’s say the hacker modifies the request as follows: 
https://bestproducts.com/products?url=file:///etc/passwd
If there’s no protection from SSRF and if this request is executed, then the contents of the /etc/passwd file would be displayed. This is an example where SSRF is on the server making the request. But SSRF can be used on other servers as well. Let’s look at an example of that scenario.
Impacts:
Data exposure
Internal recon
Denial of attack
Remote code execution

Mitigations:
Use whitelist


What is deserialization and Serialization ? 
Serialization is a mechanism of converting the state of an object into a byte stream. Deserialization is the reverse process where the byte stream is used to recreate the actual object. This mechanism is used to persist the object.


Mobile application testing process
Sqlmap tool ?
Its open source tools and find the sql injection vulnerabilities


What is Single sign on ? how it works
How roles are moved ?


O auth technology?
How credit card information stored in database side ?
What is encoding
Encoding :
In the Encoding method, data is transformed from one form to another. The main aim of encoding is to transform data into a form that is readable by most of the systems or that can be used by any external process. It can’t be used for securing data, various publicly available algorithms are used for encoding
Example: ASCII, BASE64, UNICODE
What is hashing and when do we use it  ?
In hashing, data is converted to the hash using some hashing function, which can be any number generated from string or text. Various hashing algorithms are MD5, SHA256. Data once hashed is non-reversible.
Hash function can be any function that is used to map data of arbitrary size to data of fixed size. 
What is encryption and when do we use it ?
encryption algorithm in such a way that only authorized personnel can access the message or information. It is a special type of encoding that is used for transferring private data, for example sending a combination of username and password over the internet for email login

SOP and CORS used in same domain
What is token and how many types of tokens there ?
Access tokens and refresh tokens
How a android application stores token and uses it ?
The token lives long time or reset to certain time ?
What is clickjaking ?
What is iframe injection ?
What is the difference between clickjaking and iframe injection
Soap vs RESP
Differences:
REST API has no has no official standard at all because it is an architectural style. SOAP API, on the other hand, has an official standard because it is a protocol.
REST APIs uses multiple standards like HTTP, JSON, URL, and XML while SOAP APIs is largely based on HTTP and XML.
As REST API deploys multiple standards, so it takes fewer resources and bandwidth as compared to SOAP that uses XML for the creation of Payload and results in the large sized file.
The ways both APIs exposes the business logics are also different. REST API takes advantage of URL exposure like @path("/WeatherService") while SOAP API use of services interfaces like @WebService.
SOAP API defines too many standards, and its implementer implements the things in a standard way only. In the case of miscommunication from service, the result will be the error. REST API, on the other hand, don't make emphasis on too many standards and results in corrupt API in the end.
REST API uses Web Application Description Language, and SOAP API used Web Services Description language for describing the functionalities being offered by web services.
REST APIs are more convenient with JavaScript and can be implemented easily as well. SOAP APIs are also convenient with JavaScript but don't support for greater implementation.
































What are the phases in the penetration testing life cycle?	
The main phases are planning & reconnaissance, where the goals, timeline and scope are defined and initial information is gathered, Enumeration where active scans and tests are performed to identify any vulnerabilities, exploitation, where access is gained through vulnerabilities discovered while performing enumeration, post-exploitation where there is an effort in order to maintain the access previously gained through new users or backdoors and elevate the current privileges and reporting, where all of the findings, risk ratings and relevant remediations are added to a final report. Afterwards a cleanup is necessary to remove any new user accounts, backdoors or exploits

What types of penetration testing assessments are there?	
Some of the most common types of penetration tests are external, which is usually done off-site against an external network, internal where the assessment is conducted from within the target network, web application tests which objective is to find security vulnerabilities in web-based applications through both manual and automated tests, social engineering which tries to exploit to weak link in most organization i.e. its employees, through phishing, vishing, tailgating, physical testing, media drops etc.

Difference between active and passive reconnaissance	
During active reconnaissance, the attacker will perform scans or tests that will interact with the target machine, potentially triggering alarms or creating logs, whereas during passive reconnaissance the attacker makes use of open source intelligence to gather information about the target.

How are penetration tests classified?	
There are mainly three types of penetration tests: black box, white box and grey box. In black box assessments, the tester tries to simulate a real attack, and is provided with very little to no knowledge of the target application or network. In white box assessments, the tester is given full access to things like application source code, network diagram and even authentication credentials to privileged accounts, this increases drastically the amount of tests that can be performed. In grey box assessments, the tester will have some prior knowledge and documentation of the target system, but won’t necessarily have privileged access to it.

What types of penetration testing teams are there and what are their responsibilities?
The main teams are red, blue and purple. Red teams try as best as humanly possible to simulate a real attack using tools and techniques used by cyber criminals. Blue teams are responsible for defending systems from attacks by red teams or real attackers, through various countermeasures such as firewalls, SIEM systems, honey pots etc. Purple teams use real life techniques and tools to identify vulnerabilities and apply blue team frameworks in order to protect the organization from real attacks, it is often a combination of red and blue teams, rather than a team of its own.

What are some of the types of attackers?	
Script kiddie: an unskilled individual who uses scripts or programs developed by others to attack applications, networks or devices.
Advanced persistent threat: a skilled and stealthy threat individual, typically a nation state or state-sponsored group, which manages to gain unauthorized access to a system and remains undetected for long periods of time.
Malicious insider: a malicious individual who poses a threat to an organization from within the organization, such as an employee, a former employee or a contractor, it may potentially have inside information concerning the organization’s security practices, data and computer systems.

What are the most common types of malware?	
The most common types of malware are viruses, which are self-replicating and can spread to other systems, trojan which are disguised as legitimate software, worms are like viruses but do not require a host program to spread, spyware such as keyloggers are used to sensitive information such as credentials, adware which are used to display advertisement and are usually harmless, ransomware which are designed to lock users out of their systems and demand a ransom, logic bombs which are activated at a specific time or when a specific event has occurred and rootkits which are backdoors that allow an attacker to maintain remote control over a system and are particularly hard to identify and remove

What are some of the most common vulnerability databases?	
National Vulnerability Database (NVD), Common Vulnerabilities and Exposures (CVE), Exploit Database, VulDB, Packetstorm, Microsoft Security Bulletins.

What is the Common Vulnerability Scoring System?	
The Common Vulnerability Scoring System (CVSS) is an open framework to categorize the characteristics and severity of software vulnerabilities. It consists of three metric groups: Base, Temporal, and Environmental. The Base metrics produce a score ranging from 0 to 10, which can then be modified by scoring the Temporal and Environmental metrics. 

How would you rate vulnerabilities during a penetration test?	
In order to rate a vulnerability, a risk matrix is used and a risk level is calculated based on the likelihood and consequence of a given issue.

At what point of an assessment would you start performing testing?	
Only once a clear scope of work and timeline has been defined and agreed to by all parties, and once authorization to start the testing has been received.

What are some of the most common vulnerabilities?	
Some of the most common vulnerabilities are injection, deserialization, file inclusion, weak encryption, security misconfigurations, weak password policies.

What is the principle of least privilege?	
The principle of least privilege (PoLP), requires that in a given system, application or network, a user must be able to access only the information and resources that are necessary for its legitimate purpose.


Infrastructure/Operating Systems
This section covers general questions about infrastructure, for example networking, services and protection mechanisms, and specific operating systems and their security vulnerabilities.


What is the OSI model and what are its layers?	
The Open Systems Interconnection model is used to break down what happens behind the scenes in a network system in seven layers: Physical (the cables), Data Link (network cards and switches), Network (the router), Transport (TCP/IP), Session, Presentation and Application (end-user)

What is the difference between TCP and UDP?	
TCP is a connection-oriented protocol and it uses a three-way handshake (SYN, SYN-ACK and ACK). UDP is a connectionless protocol and its speed is much faster than TCP.

What are some of the most common services and what ports do they run on?	
Some of the most common services are HTTP on port 80, HTTPS on port 443, DNS on port 53, FTp on port 21, SSH on port 22, Telnet on port 23 and+B60 SMTP on port 25.

What is DNS?	
The Domain Name System (DNS) is a service used to translate domain names to the numerical IP addresses needed for locating and identifying computer services, for example 142.250.69.196 is translated to www.google.com. It runs on port 53.

What is ARP?	
The Address Resolution Protocol (ARP) is used for discovering the MAC address associated with a given internet layer address, typically an IPv4 address.

What is RDP?	
The Remote Desktop Protocol (RDP) is a proprietary protocol developed by Microsoft which provides a user with a graphical interface to connect to another computer over a network connection. It runs on port 3389.

What is a MAC address?	
The media access control (MAC) address is a unique identifier assigned to a network interface that is required to be able to communicate with the rest of the network.

What is a firewall and how does it work?	
A firewall is a network security device that has the ability to either monitor or filter incoming or outgoing network traffic based on pre-defined rules.

What is the difference between an IDS and an IPS?	
The main difference between them is that IDS is a monitoring system, while IPS is a control system. IDS doesn’t alter the network packets in any way, whereas IPS prevents the packet from delivery based on the contents of the packet, much like how a firewall prevents traffic by IP address.

What are honeypots?	
Honeypots are hardware or software mechanisms designed to detect and potentially help to prevent attempts at unauthorized use of a given network, application or device.

What is the difference between encoding, hashing and encrypting?	
Encoding takes a clear-text string and turns it into an encoded string, which can easily be decoded, it is used to preserve the usability of the information, an example is base64. 
Hashing takes a clear-text string and turns it into a hash, which will always be the same length, regardless of the clear text string used, it is a one-way operation and therefore it cannot be reversed, it is used to validate the integrity of information or to store sensitive data, an example is MD5. 
Encryption takes a clear-text string and turns it into an encrypted string through the use of a key, it can be reverse by knowing the algorighm used and the key, it is used to secure confidential information, an example is RSA.
Name a few type of encoding, hash and encryption	Encoding: ASCII, HEX, Base64, URL. Hashing: MD5, SHA-512, NTLM. Encryption: AES, RSA, 3DES. 


What is the fastest way to crack hashes?	
The easiest way to crack hashes is through rainbow tables, which are precomputed tables of hashes that cache the output of hashing functions. The hashes stored in these tables are then compared to the target hash, in order to identify it’s corresponding clear-text value without the need of hashing a list of clear-text strings and comparing them to the hash.

Difference between symmetric and asymmetric encryption	
Symmetric encryption only uses one key for encryption as well as decryption. Asymmetric Encryption two keys, one to encrypt the information and one to decrypt it. These keys are called Public Key and Private Key.

In what format are Windows and Linux hashes stored	Windows hashes are stored using NTLM and they used to be stored with LM. Linux passwords are normally hashed using the SHA-256 or SHA-512, in older versions they are hashed with Blowfish or DES.

Where are Windows and Linux hashes stored, how can you retrieve them?	
Linux hashes are stored in /etc/shadow, they used to be stored under /etc/passwd and they can still be stored there if required. In Windows, NTLM hashes are stored in the SAM file, the boot key which is stored in the SYSTEM hive is required to obtain them. These are stored in C:\Windows\System32\config\.

What are cron jobs/scheduled tasks?	
Cron jobs or scheduled tasks give users the ability to schedule the launch of programs or scripts at pre-defined times or after specified time intervals.

Where are cron jobs stored in Windows and Linux?	Scheduled tasks in Windows are stored in %WINDIR%\System32\Tasks. Cron jobs in Linux are stored in /etc/crontab, /var/spool/cron, /var/spool/cron/crontabs/root, /etc/cron.d, /etc/cron.daily, /etc/cron.hourly etc.

What are the different package managers used in Linux and where are they used?
For Debian-based operating systems, the most common package manager is Advanced Packaging Tool (APT), which uses .deb packages. For RedHat-based operating systems, the most common package manager is Yellowdog Updater, Modified (YUM), which uses .rpn packages. For Arch-based operating systems, the most common package manager is Pacman Package Manager. For OpenSUSE-based operating systems, the most common package manager is Zypper Package Manager (ZYpp).

Describe the permission system used in Linux file systems	
Linux file systems divide their permissions in three categories: read, write and execute. 

When looking at a file or directory, the permissions are mentioned three times, the first time refers to the owner of the file, the second one to users belonging to the group of the file and the third one to everyone else.

What are SUID and sudo?	
SUID is a Unix file permission that can allow users to run a command or a script with the as the owner of the file, rather than as the user executing it. sudo is Unix feature that allows users to run scripts or commands as another user, by default the root user.

What is Kerberos and how does it perform authentication?	
Kerberos is an authentication protocol that works on the basis of tickets to allow nodes communicating over a non-secure network to prove their identity to one another in a secure manner. When authenticating, Kerberos uses symmetric encryption and a trusted third party which is called a Key Distribution Center (KDC). At the moment of the authentication, Kerberos stores a specific ticket for that session on the user’s machine and any Kerberos aware service will look for this ticket instead of prompting the user to authenticate through a password.

What is the difference between WEP, WPA and WPA2	
WEP uses the RC4 (Rivest Cipher 4) stream cipher for authentication and encryption. The standard originally specified a 40-bit, pre-shared encryption key, later on a 104-bit key became available. WPA is also based on RC4, although it introduced Temporal Key Integrity Protocol (TKIP), which uses 256-bit keys to encrypt data, along with other key features such as per-packet key mixing which make it a much better option. WPA2 replaced RC4 and TKIP with two stronger encryption and authentication mechanisms: Advanced Encryption Standard (AES) and Counter Mode with Cipher Block Chaining Message Authentication Code Protocol (CCMP), respectively. Also meant to be backward-compatible, WPA2 supports TKIP as a fallback if a device cannot support CCMP. AES comprises three symmetric block ciphers. Each encrypts and decrypts data in blocks of 128 bits using 128-, 192- and 256-bit keys.

What is WPS? Why is it insecure?	
Wi-Fi Protected Setup (WPS) is a feature supplied with many routers which is designed to make the process of connecting to a wireless network from a device easier. In order to make a connection, WPS uses a eight-digit PIN that needs to be entered on the device, which already makes this a lot easier to crack than any other encryption. Furthermore, rather than check the entire eight-digit PIN at once, the router checks the first four digits separately from the last four digits, which makes it even easier to crack as tehre are only 11,000 possible four-digit codes, and once the brute force software gets the first four digits right, the attacker can move on to the rest of the digits. Many routers come with WPS enabled by default. A way manufacturers use to mitigate this attack is to add a time out period after a number of attempts. Reaver can be used to crack WPS PINs.


Common Techniques & Attacks
The interviewer might ask questions about specific techniques or attacks that a penetration test might need to carry out as part of their day-to-day responsibilities.

Even if you don’t know how to perform some of these attacks, it is crucial that you understand how these attacks occur, what is the potential consequence and how these can potentially be remediated.


How can DNS and ARP be exploited by attackers?	
ARP spoofing or ARP cache poisoning is an attack by which an attacker sends (spoofed) Address Resolution Protocol (ARP) messages onto a local area network. Generally, the aim is to associate the attacker’s MAC address with the IP address of another host, such as the default gateway, causing any traffic meant for that IP address to be sent to the attacker instead. The attack can only be used on networks that use ARP, and requires attacker have direct access to the local network segment to be attacked. DNS spoofing, also referred to as DNS cache poisoning, is a form of of attack in which corrupt Domain Name System data is introduced into the DNS resolver’s cache, causing the name server to return an incorrect IP address, it can be exploited by attackers and allow them to receive information that was not intended for them.

What is DDoS?	
A distributed denial-of-service (DDoS) attack is a malicious attempt to disrupt the normal traffic of a targeted server, application or network by overwhelming the target with an amount of traffic that it is unable to handle. This attack targets availability rather than confidentiality or integrity.

What is buffer overflow?	
Buffer overflow is an anomaly where a program, while writing data to a buffer, overruns the buffer’s boundary and overwrites adjacent memory locations. Attackers can intentionally feed input that the buffer cannot store, and overwrite areas that hold executable code, replacing it with their own code, therefore executing arbitrary code on the target system. There are two main types of buffer overflows: stack based, more common and easier to perform and heap based, less common and harder to perform. 

What is packet inspection?	
Packet inspection is a technique that inspects in detail the data being sent over a computer network, and it is often used to detect malicious activity or to identify sensitive information.

What is privilege escalation? 
Provide a few examples	Privilege escalation allows an attacker, through the exploitation of a vulnerability or misconfiguration, to elevate their privileges and gain access to unauthorized resources on the system. An example could be through a clear-text password stored in a history file or through a vulnerable application installed on the target system.

What is the difference between brute force and dictionary attacks?	
Brute Force attacks tries a list of possible passwords that are generated during the attack based on predefined rules, whereas dictionary attack use a list of known or commonly used passwords stored in a file.

What is a golden ticket attack?	
A golden ticket attack allows an attacker to create a Kerberos authentication ticket from a compromised service account, called krbtgt. By using the NTLM hash of the compromised account an attacker can create fraudulent golden tickets. These tickets appear pre-authorized to perform whatever action the attackers want without any real authentication.

What is a common misconfiguration of FTP and SMB?	
A common misconfiguration of FTP is the anonymous login, which if enabled can allow any user to authenticate to the server without the need to enter credentials. A common misconfiguration of SMB is null session authentication , which can allow any user to authenticate to an SMB share by providing a null username and password.

Web Application Vulnerabilities & Attacks
Nowadays most applications run on web browsers and are hosted in the cloud, and due to this the need to perform tests against web applications has increased drastically.

Therefore, it is crucial for a successful penetration to be very familiar with all of the main vulnerabilities and misconfigurations that can affect web applications, the possible consequences and remediation.

What is XSS, what types of XSS are there, what are the consequences of a successful attack and how do you prevent XSS?	
Cross-site scripting is a security vulnerability that can allow attackers to inject client-side scripts or code into web pages viewed by other users. The types of XSS are: Reflected, which means the malicious code is within the current HTTP request, Stored, which means the malicious code is stored in the website’s database or in the webpage itself and DOM-based, meaning the vulnerability lies on the client-side rather then in the server-side application code. It can result in an attacker accessing sensitive data such as the user’s session or credentials, or taking full control of the target application. It can be prevented by filtering the input before the request is made, encoding the output in the HTTP response, use the Content-Type and X-Content-Type-Options headers or escaping certain special characters.

What is SQL Injection, different types and examples, how to prevent	
SQL injection is a vulnerability that allows an attacker to interfere with the queries that an application makes to its database and to inject custom queries to retrieve unintended data or perform unintended actions. There are three main types of SQL injection: In-Band, meaning the attacker uses the same platform to both perform the attack and gather its output, Blind, where the attacker perform the attack in one platform although said platform does not return any output which makes it harder to ascertain whether the vulnerability actually exists, therefore it is indispensable to rely on the response time or certain patterns of the application in order to exploit it. Out-of-band SQL injection is performed when the attacker can’t use the same platform to perform the attack and gather the output, or when a server is too slow or unstable for these actions to be performed. SQL injection can be prevented by using input validation, character whitelisting, encoding or escaping.

Secure and HTTPOnly flags	
Secure and HTTPOnly are flags that can be set against session cookies. The secure flag ensures that cookie information is only transmitted over an HTTPS channel. The HTTPOnly flag ensures that cookie information can only be accessed by the web server and not by client-side scripts, this limits the damage that XSS could to to a victim user.

What is CSRF, what does it entail and how can it be prevented?	
Cross-site request forgery (CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform by using maliciously crafted web requests. It can allow an attacker to cause a victim user to carry out an unintended action, for example changing their email address, password or transferring funds. This can result in a full compromise of the victim’s account. CSRF attacks can be prevented through the use of CSRF tokens, which ensures the request made by the end user is genuine and makes it impossible for attackers to craft a malicious HTTP request for the end user to execute. To be effective, CSRF tokens need to be unpredictable, tied to the user’s session and validated upon every user action is executed.

What is IDOR, what are its consequences and how can you prevent it?	
Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly. If present, they can allow attackers to access unintended data on the database, including sensitive information such as passwords, potentially gaining full access to the web server. It can be prevented through input validation or by using indirect references.

What are LFI and RFI and what are the consequences of these attacks? 
How can they be prevented?	
Local file inclusion and remote file inclusion occur when a web application includes a file within its code in order to use functions within it and when proper input validation is not in place. Through local file inclusion, attackers can potentially access files within the web server that were not meant to be publicly available, whereas through remote file inclusion, attackers can include remote files, and therefore potentially execute malicious scripts hosted on a web server. The easiest way to prevent LFI and RFI attacks is to simply not include files in a way that they can be manipulated by users, otherwise input sanitization can be used.

How can you secure data in transit?	
The HTTPS protocol on port 443 can be used to secure data in transite between a client and a server, through TLS or SSL encryption.

Penetration Testing Tools
Knowing the most common penetration testing tools and how to use them is a key skill for any penetration tester, as these tools will help greatly in automating attacks and enumerations, as well as performing manual testing.


What tool would you use to perform a port scan?	
The most popular tool to perform port scans is Nmap. Port scans can also be done through scripting, for example using Python.

What tools would you use to inspect network packets?	
The most common tools for packet inspection are Wireshark and Dig.

What tool would you use to bruteforce passwords, online and offline?	
Hydra and Patator are used for online cracking, where as John the Ripper and Hashcat are used for offline cracking.

What tool would you use to automate SQL injection attacks?	
SQLMap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection attacks.

What tool would you use to perform an ARP spoofing attack?	
The main tools used for ARP spoofing are Arpspoof, Ettercap and Responder.

What tools would you use to perform testing against WiFi networks	
Aircrack-ng is a complete suite of tools used to assess WiFi network security and test for various vulnerabilities.

What tool can help generate malicious executables?	
The Metasploit MSFvenom tool is a combination of Msfpayload and Msfencode, putting both of these tools into a single Framework instance. It allows to generated encoded malicious payloads.

What tools would you use to scan a network for known vulnerabilities?	
Tools like Nessus or OpenVAS can be used to scan networks for known vulnerabilities.

What tool would you use to inspect the route between a host and a destination?	
Traceroute, or tracert, is a network diagnostic tool used to identify the exact route and hops is used for a host to connect to a given destination, and to measure any packet transit delays.


Scenario-Based
The interviewer will most likely ask some scenario-based questions, which will test your critical thinking in situations where you may need to exploit a certain vulnerability or suggest a remediation but the answer may not be as straightforward. There isn’t necessarily a right or wrong answer to these, as long as you can come up with a creative way that works it will prove you have what it takes.

Try to think of other scenarios you may come across during a penetration test that may need extra thinking.


How would you remotely access a service that can only be accessed from within an internal network?	
Port forwarding is a technique used to redirect a communication request from one address and port number combination to another. For example, if port 80 is only accessible from within the internal network but port 443 is accessible remotely, a port forward rule can be created to forward all incoming traffic on port 443 to port 80.

How would you allow regular users to run bash scripts as root and which way is most secure?	
The best way would be to use cron jobs, as long as the user does not have access to modify the script that is being run, alternatively a SUDO rule can be added to allow the user to run the script as sudo.

If you were able to obtain an NTLM hash but could not decrypt it, how would you use this knowledge to obtain access to the target host?	
Pass the hash is a hacking technique that allows an attacker to authenticate to a remote server by using the NTLM or LM hash of a user’s password, instead of requiring the plaintext password.

What measures would you put in place to prevent brute forcing?	
Password bruteforcing can be prevented through the use of account lockout mechanisms, CAPTCHA, multi-factor authentication and IP-based restrictions.








https://github.com/naveen12/web-security-interview-questions 
https://danielmiessler.com/study/infosec_interview_questions/ 


















How to bypass xss filters
how to bypass SQL injection filters
how to insert log how to to exploit log injection 
how to exploit if it up contains csrf token
What is lfi and rfi





Security test cases for Login page:- 
Approach: A

1) Invalid Username/password

2) Password encryption (Encrypted Password cannot be copy-pasted in notepad)

3) Forgot Password Link

4) Valid login name/email id for forgot password or contact administrators

5) Checking cookies for username/password

6) Number of invalid attempts for username/password

7) Remember me(for password)

8) In case of financial applications (like Bank – Captha, virtual keypad etc.., for ATM – Pin etc..)

9) Authorization

10) Access Control

11) SQL Injection

12) Check the Admin rights to delete the already logged in user.

13) SSL

Approach: B  Following are some test cases that you may want to execute to check the login level security of any web application :

1- Check if the user can access the secured area of the application without proper login.To do this, you may book mark, add to favourite or copy the URL of any secured area page and then run the URL directly without login.Application should not allow the access to the secured area in this case.

2- Check if the user can work with the secured area page, that is accessed by using browser’s BACK button, after log out the application.Proper info message should be displayed in this case mentioning that user needs to be logged in the application.

3- Check if the user can work in a secured area after session time is out.

4- Check if multiple users, with the same login ID & password can access the application.

Approach: C In Security Testing you will also check for below:

1. Check data is travel in network in plain text or Encrypted form

2. Check data encryption for login id & Password is fixed encryption or random encryption

3. Check if you are using Certificated, that certificate will follow trust chain or not

4. Log File for both web page & database

5. Client side validation is required for each text field

6. Error Message does not contain malicious info so that hacker will use this information to hack web site


https://www.edureka.co/blog/interview-questions/cybersecurity-interview-questions/
https://resources.infosecinstitute.com/topic/top-30-penetration-tester-pentester-interview-questions-and-answers-for-2019/ 

