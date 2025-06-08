# **Honeypot(T-Pot) with AWS**

![](https://miro.medium.com/v2/resize:fit:700/1*TOdhH14dOHF1MeRpctW7bA.png)

**“How Honeypots Work: Real Attacks, Safe Systems, and the T-Pot Advantage”**

- “Inside the Trap: Understanding Honeypots with Real-World Examples”
- “Using T-Pot to Attract and Analyze Real Cyber Attacks — A Beginner’s Guide”
- “Deploying T-Pot Honeypot Safely on Ubuntu: Real Threats in a Controlled Lab”

- **Introduction**

➤ What is a honeypot? Why is it used in cybersecurity?

- **What is T-Pot and How Does It Work?**

  ➤ Explain multi-honeypot framework and logging with ELK stack.

- **Can Hackers Really Attack My System?**

  ➤ Clarify doubts about real vs virtual attacks.

- **🎯 Real-World Analogy: Honeypot is a Fake Shop**

  ➤ Use your example here (see below 👇).

- **Running T-Pot on a Windows System Safely**

   ➤ Explain VirtualBox + Ubuntu method to isolate real machine.

- **Why Do Companies Run T-Pot 24/7?**

 ➤ SOC/Threat Intelligence/Logging/Alerting reasons.

- **Conclusion: Safe Experimentation, Real Threat Insight**

➤ Honeypots are powerful tools for both learning and real defense.

# **🎯 Real-World Analogy: Honeypot is a Fake Shop**

Imagine setting up a **fake shop inside your house**, designed to **look real from the outside**. You place attractive signs, open the door halfway, and even display fake items in the window. Outsiders walking by — especially those looking to steal — see this and try to break in.

But here’s the trick: **the fake shop leads nowhere**. It’s not connected to the rest of your home. It’s just a setup to **lure potential thieves**, monitor what they do, and collect their methods — all without putting your real home at risk.

That’s exactly how a **honeypot works in cybersecurity**. It looks like a vulnerable system to attackers, but it’s **isolated** from your real machines. While attackers believe they’re hacking something valuable, you’re actually recording their every move.

# **🚀 Launching a New Instance on ECE (Elastic Compute Environment)**

To deploy the T-Pot honeypot safely on a cloud machine, I started by launching a new virtual instance using my ECE cloud panel. Here are the steps I followed:

# **🛠️ Step-by-Step Instance Creation**

1. **Clicked on “Launch Instance”**From the ECE dashboard, I clicked on the **“Launch Instance”** button to begin creating a new virtual server.

![](https://miro.medium.com/v2/resize:fit:700/1*OHyJFSCdGtsL3oRb8kPmjg.jpeg)

**2.Selected the Operating System: Ubuntu**

In the system configuration section, I chose **Ubuntu** as the operating system since T-Pot is designed to run on Ubuntu.

![](https://miro.medium.com/v2/resize:fit:700/1*ZkCghtVznl4lUWPr47UYhQ.jpeg)

**3.Set the Storage Size to 128 GB**

I allocated **128 GB of disk space** to ensure there is enough room for the honeypot tools, logs, and dashboards (like Kibana and ELK stack data).

![](https://miro.medium.com/v2/resize:fit:700/1*p3aBcP9xj8a4Y_GizPIR_g.jpeg)

**4.Chose a IP Address**

I selected a my **IP address** for the instance so that it could be accessible over the internet — allowing real-world attackers to reach the honeypot services exposed by T-Pot.v

![](https://miro.medium.com/v2/resize:fit:700/1*25GDrRg7UtsaXeHfp_h4xQ.jpeg)

**5.Generated a New SSH Key Pair**

I created a **new key pair** to securely access the virtual machine via SSH. This private key would be downloaded and used later for login.

![](https://miro.medium.com/v2/resize:fit:700/1*aHlVZYhyvhUCtSkhN-KNnQ.jpeg)

**6.Selected the Instance Type: t3.XLarge Tier**

I picked the **t3**.**XLarge instance type** to provide sufficient CPU and memory resources for running multiple honeypots and dashboards smoothly.

**7. Reviewed the Configuration**

After verifying all the selected options (OS, tier, storage, key, and IP), I proceeded to launch the instance.

**8. Clicked “Launch Instance”**

Finally, I clicked the **“Launch Instance”** button to deploy the virtual machine. Within a few minutes, the instance was up and running, ready for SSH access and T-Pot installation.

![](https://miro.medium.com/v2/resize:fit:700/1*ZirTTudyTxcuDLKtss8B9A.jpeg)

![](https://miro.medium.com/v2/resize:fit:700/1*DWo80ZZKqJISFBYTKTpz_A.jpeg)

Then Go to the instance click on connect

![](https://miro.medium.com/v2/resize:fit:700/1*dT_kUFE_Z6zMol_-eTZKaA.jpeg)

after that go to the SSH client and copy the full command and go to the command prompt and terminal and paste it

![](https://miro.medium.com/v2/resize:fit:700/1*sFBCyKXjmRZzxC71F0xskA.jpeg)

# **🔐 SSH Login Command to Access the Instance:**

```
ssh -i "your-key.pem" ubuntu@<Public-IP>
```

![](https://miro.medium.com/v2/resize:fit:700/1*8EIoSdJ6fG3TGq4QbgYncQ.jpeg)

![](https://miro.medium.com/v2/resize:fit:700/1*ZQuybSOiqFu0caR22OXjXg.jpeg)

after that run this command;

```
sudo apt update
```

![](https://miro.medium.com/v2/resize:fit:700/1*ZIXadnMjYpx4M7oTY5-H5A.jpeg)

then;

```
sudo apt upgrade
```

![](https://miro.medium.com/v2/resize:fit:700/1*mQdeTk3TgU8ZXeU3rtHzcQ.jpeg)

Once our system is updated then go to the this website and paste the github repositry https://github.com/telekom-security/tpotce and clone it

```
https://github.com/telekom-security/tpotce.git
```

![](https://miro.medium.com/v2/resize:fit:700/1*nIJRsVtt57MnGuJtDYGl2A.jpeg)

after clone this repositry go the **tpotce** directory run this command

```
./install.sh
```

and click on **y**

![](https://miro.medium.com/v2/resize:fit:700/1*EDmopKt_MiiD8ef2aP_W6w.jpeg)

select according to the image and set username and password for tpot

![](https://miro.medium.com/v2/resize:fit:700/1*fslhxZ5PyAjP0aSGL1nozw.jpeg)

You can see here our tpot is successfully installed

ignore sudo reboot now

![](https://miro.medium.com/v2/resize:fit:700/1*YIqXH07E19-p2wDiV5C2vQ.jpeg)

# **🔐 Configuring Inbound Rules After T-Pot Installation**

Once the T-Pot honeypot was successfully installed on my Ubuntu server, the next crucial step was to configure **inbound rules** to allow external traffic to reach the services provided by T-Pot. This is done through the **Security Group** or firewall settings in the cloud panel (ECE in my case).

Here’s how I set it up: go to the ec2 instance select security and click on according to the arrow

![](https://miro.medium.com/v2/resize:fit:700/1*mz0sDpMoq7LqBEr6aqhoGg.jpeg)

# **🔐 Why I Opened Ports 64295 and 64297 in AWS Inbound Rules**

After successfully installing **T-Pot honeypot** on my Ubuntu EC2 instance, I had to configure **inbound rules** to allow traffic to specific ports used by T-Pot’s services and dashboards. Here’s why these particular ports were chosen:

# **✅ Purpose of Each Port**

- **Port 64295 (TCP)** → This port is used by the **T-Pot Web Cockpit (Admin UI)**. It provides an overview of the system status, uptime, and resource usage. It’s the main dashboard where I can monitor the honeypot’s performance and system health in real time.
- **Port 64297 (TCP)** → This port is dedicated to the **Kibana Dashboard**, which is part of the ELK stack integrated with T-Pot. It visualizes the captured logs and attack data, showing rich visual analytics about the threats interacting with the honeypots.

These ports are not standard (like port 80 or 22), which makes them less predictable and slightly more secure by default.

two times click on add rules

![](https://miro.medium.com/v2/resize:fit:700/1*brovfeVtO6UsA6cAW16gbQ.jpeg)

![](https://miro.medium.com/v2/resize:fit:700/1*4g5LQo_x7dx0eEcx0iMJNA.jpeg)

![](https://miro.medium.com/v2/resize:fit:700/1*H3bRejR_VD_G8vn4DVWlyQ.jpeg)

# **💻 Logging In After Firewall Setup**

Once the inbound rules were saved, I connected to the T-Pot server via SSH using this command:

```
ssh -i "keys2.pem" ubuntu@ec2-13-204-67-53.ap-south-1.compute.amazonaws.com -p 64295
```

# **📌 Breakdown:**

- `i "keys2.pem"` → Path to the private key file for authentication
- `ubuntu@...` → Default user and public IP/domain of my EC2 instance
- `p 64295` → Custom SSH port (T-Pot replaces the default port 22 with 64295 for added stealth)

![](https://miro.medium.com/v2/resize:fit:1000/1*ADoRvZOm3vvkSrFpk_Boxg.jpeg)

Go the ec2 instance and copy the **ipv4** address and

![](https://miro.medium.com/v2/resize:fit:700/1*NknvPMUdCw9y-G7WFiFE6g.png)

run https://13.x.x.x:64297

![](https://miro.medium.com/v2/resize:fit:700/1*C3jzdy6BQ_BNZ5ZvYGRTtQ.jpeg)

After that login with username and password you created this before when we installing tpot

![](https://miro.medium.com/v2/resize:fit:700/1*dJsBnhM3uLtWn4GM4qeQZQ.jpeg)

# **🌍 Real-Time Global Threat Monitoring via T-Pot Attack Map**

Once the honeypot was fully installed and the Kibana dashboard was accessible via port `64297`, I opened the **T-Pot Attack Map** in the browser using the URL:

```
https://<public-ip>:64297/map/
```

In my case:

```
https://13.204.67.53:64297/map/
```

> Note: You might see a security warning in the browser because T-Pot uses a self-signed certificate. You can proceed by clicking “Advanced → Proceed anyway.
> 

![](https://miro.medium.com/v2/resize:fit:1000/1*N9DXX5roGcqTC_x2HpoEEw.jpeg)

# **🎯 What You See on the Attack Map**

The T-Pot Attack Map provides a **real-time visual representation** of all the attacks targeting the honeypot. Here’s what it shows:

🌐 **Your Honeypot’s Location**

As you can see in the image, the pink pin indicates **my honeypot’s geolocation** in **India** (`13.204.67.53` hosted on `ip-172-31-5-22`).

🔥 **Top Hits by IP & Country**

The map displays **live data** about incoming attacks, including:

- Source **IP addresses**
- **Country** of origin (Germany, China, USA, Vietnam, etc.)
- Type of honeypot or service being targeted (like FTP, SSH, TELNET)
- The **total number of hits**

🕐 **Last 1 Minute / Hour / 24 Hours Stats**

At the top, you’ll notice counters showing how many attacks were observed in:

- The last 1 minute
- The last 1 hour
- The last 24 hours

![](https://miro.medium.com/v2/resize:fit:1000/1*7TROL4LHQaSCkLIIubLwwA.jpeg)

go to the dashboard click on kibana

![](https://miro.medium.com/v2/resize:fit:700/1*N9DXX5roGcqTC_x2HpoEEw.jpeg)

![](https://miro.medium.com/v2/resize:fit:700/1*zWJI0qn8CNLU8kSrRGT-Vw.jpeg)

# **📊 2. Kibana Dashboard Summary**

This dashboard is built on **Elasticsearch + Kibana** and displays visual analytics of honeypot data.

## **🔸 Total Honeypot Attacks:**

- **16 total attacks** in the last 24 hours.
- **13** from **Honeytrap**
- **3** from **Cowrie**

## **🔸 Attacks Over Time:**

- You can see histograms showing attack frequency and source IP variation.
- Attacks occurred throughout the day with spikes in the evening.

## **🔸 Dynamic Attack Map:**

- Visualizes live attack points globally.
- Most intense attacks appear in **Asia and Europe**.

# **📈 3. Attack Types and Sources**

## **🔹 Types of Attackers:**

- **Known attackers** and **mass scanners** are both present.
- Pie charts represent proportions of attacker types and honeypot services triggered.

## **🔹 Targeted Platforms:**

- Attackers are targeting:
- **Linux kernels**
- **Solaris**
- **Windows NT**

## **🔹 Top Attacking Countries:**

- **Germany**
- **United States**
- **Brazil**
- **China**
- **South Korea**

Each country is associated with specific ports (like 4103, 8080, 24625) that were scanned or attacked.

# **🛡️ 4. Suricata IDS Alerts**

T-Pot uses **Suricata** to generate alerts based on attack signatures.

## **🔹 Top Suricata Signatures:**

- `ET DROP Dshield Block Listed Source`
- `ET INFO SSH session in progress`
- `ET SCAN NMAP -sS`
- `ET INFO Inbound HTTP CONNECT Attempt on Off-Port`
- These show attempts of **Nmap scans**, **SSH brute force**, and **malicious HTTP traffic**.

## **🔹 Suricata CVEs:**

- No CVEs have been identified yet in the logs, meaning **no known vulnerabilities** have been exploited during these attacks (as of now).

# **🌐 5. Attacker Information**

## **🔹 Top Attacker ASNs:**

- **Alibaba US**, **Microsoft-C**, **Chinanet**, **Korea Telecom**, **DigitalOcean**, etc.
- These are the **hosting providers or networks** from which attacks originated.

## **🔹 Top Source IPs:**

- `8.209.96.38`
- `183.17.236.110`
- `125.136.231.2`
- These IPs repeatedly attacked your honeypot and triggered Suricata alerts.

![](https://miro.medium.com/v2/resize:fit:1000/1*iEK2Or0DcuClznJOHXtj_A.jpeg)

![](https://miro.medium.com/v2/resize:fit:1000/1*be-lhHxssS-ykUljoKUd0w.jpeg)

![](https://miro.medium.com/v2/resize:fit:700/1*x8U9F5BH9xFtCxp8e0NM8g.png)

# **🌍 Geo-Map Insights (Visual Map):**

- The white and red lines on the map represent **attack traces**.
- The animated paths (from Asia, Europe, and North America) reflect **incoming intrusion attempts**.
- The **magenta pin in India** shows your server location (where T-Pot is running).
- Arrows from **USA, China, UK, and Germany** show attackers scanning or interacting with your honeypot.

🧠 **Conclusion: Increased Attack Surface Visibility**

Compared to earlier, both the attack volume and targeted services have increased.

The Cowrie honeypot is effectively detecting SSH and TELNET-based attacks.

Attackers from multiple countries are interacting with the honeypot, which indicates that your server is publicly visible on the internet and is attracting bots and automated scanners.
The Cowrie honeypot is effectively detecting SSH and TELNET-based attacks.

![](https://miro.medium.com/v2/resize:fit:1000/1*3DnyN6jj9-jfpfWPKoEgJg.png)
