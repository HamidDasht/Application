**A Large-scale Analysis of Content Modification by
Open HTTP Proxies**

In this paper, the authors study open HTTP proxies' behavior. The purpose of the article is to find how these proxies relay the response and how this may impact clients' security. They also present a new tool to determine safe proxies among a list of open HTTP proxies.

In essence, the authors monitor a collection of open proxies over a period of 2 months and inspect their behavior. This inspection is done by comparing the response sent back by proxies to the one directly obtained from the server and checking the existence of any content modification or injection in the proxies' response.

To make the analysis easier to do, they test proxies against two honeysites that they have designed and own.
To make the results more reliable and complete, they designed these two web pages with different levels of complexity. One is purely static while the other has dynamic content, including ads.

This diversity is important because some proxies may only change particular elements (ads, for example). Also, some proxies may target only some web pages. So the authors also use real-world websites to foil proxies' attempt to make smart decisions about what requests to target.

However, distinguishing content modification for dynamic web pages is challenging because dynamic content is highly prone to change across different requests. To make this comparison possible, the dynamic honeysite generates its dynamic content predictably. As a result, any deviations from that pattern could get assigned to the proxies.

To analyze the results and to understand how these proxies work, the following steps are taken:
 - They directly fetch target web pages, and their DOMs are then analyzed to extract non-changing, static parts of the web page into a template.
 - Honeysites are fetched through the proxies regularly and then analyzed and compared to the already extracted templates to detect any modifications.
 - These modifications are then clustered in two phases to create a fine-grained set of samples that are easier to inspect.

The authors then inspect these clusters to understand how they affect users and what malicious activities are committed. They identify these generalized cases of content modification:
 - Ad injection. Some proxies have monetary intents. They change the content to replace expected ads with their arbitrary ads. Also, some ad injections are aimed at forcing the user to click and then steal data or deliver malware.
 - Script injection. To monitor injected scripts' behavior, downloaded responses through proxies are executed in a safe environment, and their behavior is monitored. Injected JavaScript code could attempt stealing private information, track user input, or track the user by injecting cookies.
 - Some content modifications are not malicious, but on the contrary, try to protect users' privacy by blocking ads and trackers.

Finally, the authors present their work as a service that can generate a list of safe proxies based on open proxy lists.

---

In this paper, the authors present a new system for the following problem: How could we look for a specific vulnerability in a program based on its source code.
This problem is important since after finding a vulnerability in a program and patching it, it is very important to find other programs that have this vulnerability.
**Vulpecker** is the system the authors implement and present to address this challenge. Vulpecker uses code similarity algorithms and checks the presence of a particular vulnerability in a particular program and its location in the source code.

Vulpecker tries to create a knowledge database about existing vulnerabilities and their corresponding patches. This is done by using NVD and CVE databases together to extract vulnerabilities and the corresponding patches. The patches are saved in *Vulnerability Patch Database (VPD)*.  Based on this information, a signature is generated for the vulnerability. Now, using a similarity algorithm, Vulpecker checks an input program's source code for that vulnerability. There are some challenges to this process, for example, finding code similarity based on a single code-similarity algorithm is not very effecitve.

This whole process consists of two phases, a learning phase, and a detection phase. During the learning phase, for each vulnerability, two outputs are generated: 

 1. *CVE-to-algorithm mapping*: As mentioned previously, VPD stores vulnerability patches. To find the best code-similarity algorithm for a particular vulnerability, the authors use VPD and another database that stores vulnerable instances called VCID. At first, diff hunks are extracted from VPD, and some features of these hunks are extracted. Candidate algorithms are executed on vulnerable codes, and the algorithm which detects that vulnerability with a minimal error rate is chosen for detecting that particular CVE-ID in target programs.

 2. *Vulnerability Signatures*: A signature is generated for each vulnerability that is used in the detection phase. This signature is generated based on diffs in VPD and the similarity algorithm assigned to the vulnerability in the previous step.

Then we have the detection phase. In the detection phase, Vulpecker first generates the signature for the program that we want to check for vulnerability. This signature is generated by using the target program and the CVE-to-algorithm mapping. Finally, Vulpecker searches vulnerability signatures in the target program by comparing the signatures and reports the vulnerability and the code fragment corresponding to the vulnerability.

---

**Many websites expose their “.git” files, please show how it could be dangerous.**

This is dangerous because .git folder contains sensitive information about the repository (commits, branches, remote repo address, etc.) and anyone is possession of this folder can interact with the repo and even pull source code.

**Imagine that we have 2\*\*48 text files. Explain how can we find which files are the same.**

We can compute each file's hash and then compare the hashes. Files with identical hashesh are the same.

**Write a hello-world C program and explain how we can dump its binary code with radare2.**

First we use *r2 hello_world* to run radare2 with our program. Now we can use *pd $s > dis.txt* to disassemble and dump the entire binary.

p = print

d = disassemble

$s = hello_world's size 

pd $s = disassemble $s bytes

This command dumps everything in the file. We could use the following steps to dump functions recursively:

- r2 hello_world
- aaa
- pdr > dis.txt

aaa = analyzes code

pdr = disassemble recursively
