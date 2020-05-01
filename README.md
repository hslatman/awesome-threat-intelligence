# awesome-threat-intelligence
A curated list of awesome Threat Intelligence resources

A concise definition of Threat Intelligence: *evidence-based knowledge, including context, mechanisms, indicators, implications and actionable advice, about an existing or emerging menace or hazard to assets that can be used to inform decisions regarding the subject’s response to that menace or hazard*.

Feel free to [contribute](CONTRIBUTING.md).

- [Sources](#sources)
- [Formats](#formats)
- [Frameworks & Platforms](#frameworks-and-platforms)
- [Tools](#tools)
- [Research, Standards & Books](#research)


## Sources

Most of the resources listed below provide lists and/or APIs to obtain (hopefully) up-to-date information with regards to threats.
Some consider these sources as threat intelligence, opinions differ however.
A certain amount of (domain- or business-specific) analysis is necessary to create true threat intelligence.

<table>
    <tr>
        <td>
            <a href="https://www.abuseipdb.com/" target="_blank">AbuseIPDB</a>
        </td>
        <td>
            AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It's mission is to help make Web safer by providing a central blacklist for webmasters, system administrators, and other interested parties to report and find IP addresses that have been associated with malicious activity online..
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://s3.amazonaws.com/alexa-static/top-1m.csv.zip" target="_blank">Alexa Top 1 Million sites</a>
        </td>
        <td>
            The top 1 Million sites from Amazon(Alexa). <a href="http://threatglass.com/pages/about" target="_blank">Never</a> use this as a <a href="https://www.netresec.com/?page=Blog&month=2017-04&post=Domain-Whitelist-Benchmark%3a-Alexa-vs-Umbrella" target="_blank">whitelist</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://apility.io" target="_blank">Apility.io</a>
        </td>
        <td>
            Apility.io is a Minimal and Simple anti-abuse API blacklist lookup tool. It helps users to know immediately if an IP, Domain or Email is blacklisted. It automatically extracts all the information in realtime from multiple sources.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://docs.google.com/spreadsheets/u/1/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml" target="_blank">APT Groups and Operations</a>
        </td>
        <td>
            A spreadsheet containing information and intelligence about APT groups, operations and tactics.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.autoshun.org/" target="_blank">AutoShun</a>
        </td>
        <td>
            A public service offering at most 2000 malicious IPs and some more resources.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.binarydefense.com/banlist.txt" target="_blank">Binary Defense IP Banlist</a>
        </td>
        <td>
            Binary Defense Systems Artillery Threat Intelligence Feed and IP Banlist Feed.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.circl.lu/projects/bgpranking/" target="_blank">BGP Ranking</a>
        </td>
        <td>
            Ranking of ASNs having the most malicious content.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://intel.malwaretech.com/" target="_blank">Botnet Tracker</a>
        </td>
        <td>
            Tracks several active botnets.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.botvrij.eu/">BOTVRIJ.EU</a>
        </td>
        <td>
            Botvrij.eu provides different sets of open source IOCs that you can use in your security devices to detect possible malicious activity.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://danger.rulez.sk/projects/bruteforceblocker/" target="_blank">BruteForceBlocker</a>
        </td>
        <td>
            BruteForceBlocker is a perl script that monitors a server's sshd logs and identifies brute force attacks, which it then uses to automatically configure firewall blocking rules and submit those IPs back to the project site, <a href="http://danger.rulez.sk/projects/bruteforceblocker/blist.php">http://danger.rulez.sk/projects/bruteforceblocker/blist.php</a>.
        </td>
    </tr>    
    <tr>
        <td>
            <a href="http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt" target="_blank">C&amp;C Tracker</a>
        </td>
        <td>
            A feed of known, active and non-sinkholed C&amp;C IP addresses, from Bambenek Consulting.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://certstream.calidog.io/" target="_blank">CertStream</a>
        </td>
        <td>
            Real-time certificate transparency log update stream. See SSL certificates as they're issued in real time.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.ccssforum.org/malware-certificates.php" target="_blank">CCSS Forum Malware Certificates</a>
        </td>
        <td>
            The following is a list of digital certificates that have been reported by the forum as possibly being associated with malware to various certificate authorities. This information is intended to help prevent companies from using digital certificates to add legitimacy to malware and encourage prompt revocation of such certificates.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://cinsscore.com/list/ci-badguys.txt" target="_blank">CI Army List</a>
        </td>
        <td>
        A subset of the commercial <a href="http://cinsscore.com/">CINS Score</a> list, focused on poorly rated IPs that are not currently present on other threatlists.
        </td>
    </tr>    
    <tr>
        <td>
            <a href="http://s3-us-west-1.amazonaws.com/umbrella-static/index.html" target="_blank">Cisco Umbrella</a>
        </td>
        <td>
            Probable Whitelist of the top 1 million sites resolved by Cisco Umbrella (was OpenDNS).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://intel.criticalstack.com/" target="_blank">Critical Stack Intel</a>
        </td>
        <td>
            The free threat intelligence parsed and aggregated by Critical Stack is ready for use in any Bro production system. You can specify which feeds you trust and want to ingest.
        </td>
    </tr>
     <tr>
        <td>
            <a href="https://www.c1fapp.com/" target="_blank">C1fApp</a>
        </td>
        <td>
            C1fApp is a threat feed aggregation application, providing a single feed, both Open Source and private. Provides statistics dashboard, open API for search and is been running for a few years now. Searches are on historical data.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.cybercure.ai/" target="_blank">Cyber Cure free intelligence feeds</a>
        </td>
        <td>
            Cyber Cure offers free cyber threat intelligence feeds with lists of IP addresses that are currently infected and attacking on the internet. There are list of urls used by malware and list of hash files of known malware that is currently spreading. CyberCure is using sensors to collect intelligence with a very low false positive rate. Detailed <a href="https://docs.cybercure.ai" target="_blank">documentation</a> is available as well.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.cyberthreatexchange.com/" target="_blank">Cyber Threat Exchange</a>
        </td>
        <td>
            The Threat Exchange is an online marketplace platform for buying, selling and sharing cyber threat intelligence feeds.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://dataplane.org/" target="_blank">DataPlane.org</a>
        </td>
        <td>
          DataPlane.org is a community-powered Internet data, feeds, and measurement resource for operators, by operators. We provide reliable and trustworthy service at no cost.
        </td>
    </tr>
   <tr>
        <td>
            <a href="https://osint.digitalside.it/" target="_blank">DigitalSide Threat-Intel</a>
        </td>
        <td>
          Cointains sets of Open Source Cyber Threat Intellegence indicators, monstly based on malware analysis and compromised URLs, IPs and domains. The purpose of this project is to develop and test new ways to hunt, analyze, collect and share relevants IoCs to be used by SOC/CSIRT/CERT/individuals with minimun effort. Reports are shared in three ways: <a href="https://osint.digitalside.it/Threat-Intel/stix2/" target="_blank">STIX2</a>, <a href="https://osint.digitalside.it/Threat-Intel/csv/" target="_blank">CSV</a> and <a href="https://osint.digitalside.it/Threat-Intel/digitalside-misp-feed/" target="_blank">MISP Feed</a>. Reports are published also in the <a href="https://github.com/davidonzo/Threat-Intel/" target="_blank">project's Git repository</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/martenson/disposable-email-domains">Disposable Email Domains</a>
        </td>
        <td>
            A collection of anonymous or disposable email domains commonly used to spam/abuse services.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://dnstrails.com/">DNSTrails</a>
        </td>
        <td>
            Free intelligence source for current and historical DNS information, WHOIS information, finding other websites associated with certain IPs, subdomain knowledge and technologies. There is a <a href="https://securitytrails.com/">IP and domain intelligence API available</a> as well. 
        </td>
    </tr>
     <tr>
        <td>
            <a href="https://www.assetwatch.io/domainstream/" target="_blank">DomainStream</a>
        </td>
        <td>
            Live domain name feed from various Certificate Transparency Logs and Passive DNS Data that is being scanned everyday. Use this to find new subdomains of your interest when it appears on the internet or find probable phishing domains.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://rules.emergingthreats.net/fwrules/" target="_blank">Emerging Threats Firewall Rules</a>
        </td>
        <td>
            A collection of rules for several types of firewalls, including iptables, PF and PIX.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://rules.emergingthreats.net/blockrules/" target="_blank">Emerging Threats IDS Rules</a>
        </td>
        <td>
            A collection of Snort and Suricata <i>rules</i> files that can be used for alerting or blocking.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://exonerator.torproject.org/" target="_blank">ExoneraTor</a>
        </td>
        <td>
            The ExoneraTor service maintains a database of IP addresses that have been part of the Tor network.  It answers the question whether there was a Tor relay running on a given IP address on a given date.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.exploitalert.com/" target="_blank">Exploitalert</a>
        </td>
        <td>
            Listing of latest exploits released.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://intercept.sh/threatlists/" target="_blank">FastIntercept</a>
        </td>
        <td>
	    Intercept Security hosts a number of free IP Reputation lists from their global honeypot network.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://feodotracker.abuse.ch/" target="_blank">ZeuS Tracker</a>
        </td>
        <td>
            The Feodo Tracker <a href="https://www.abuse.ch/" target="_blank">abuse.ch</a> tracks the Feodo trojan.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://iplists.firehol.org/" target="_blank">FireHOL IP Lists</a>
        </td>
        <td>
            400+ publicly available IP Feeds analysed to document their evolution, geo-map, age of IPs, retention policy, overlaps. The site focuses on cyber crime (attacks, abuse, malware).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://fraudguard.io/" target="_blank">FraudGuard</a>
        </td>
        <td>
            FraudGuard is a service designed to provide an easy way to validate usage by continuously collecting and analyzing real-time internet traffic.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://greynoise.io/" target="_blank">Grey Noise</a>
        </td>
        <td>
            Grey Noise is a system that collects and analyzes data on Internet-wide scanners.It collects data on benign scanners such as Shodan.io, as well as malicious actors like SSH and telnet worms. 
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://hailataxii.com/" target="_blank">Hail a TAXII</a>
        </td>
        <td>
            Hail a TAXII.com is a repository of Open Source Cyber Threat Intelligence feeds in STIX format. They offer several feeds, including some that are listed here already in a different format, like the Emerging Threats rules and PhishTank feeds.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://riskdiscovery.com/honeydb/" target="_blank">HoneyDB</a>
        </td> 
        <td>
            HoneyDB provides real time data of honeypot activity. This data comes from honeypots deployed on the Internet using the <a href="https://github.com/foospidy/HoneyPy" target="_blank">HoneyPy</a> honeypot. In addition, HoneyDB provides API access to collected honeypot activity, which also includes aggregated data from various honeypot Twitter feeds.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/SupportIntelligence/Icewater" target="_blank">Icewater</a>
        </td>
        <td>
            12,805 Free Yara rules created by <a href="http://icewater.io/" target="_blank">http://icewater.io</a>
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://infosec.cert-pa.it" target="_blank">Infosec - CERT-PA</a>
        </td>
        <td>
            Malware samples <a href="https://infosec.cert-pa.it/analyze/submission.html" target="_blank">collection and analysis</a>, <a href="https://infosec.cert-pa.it/analyze/statistics.html" target="_blank">blocklist service, <a href="https://infosec.cert-pa.it/cve.html">vulnerabilities database</a> and more. Created and managed by <a href="https://www.cert-pa.it">CERT-PA</a>
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.iblocklist.com/lists" target="_blank">I-Blocklist</a>
        </td>
        <td>
            I-Blocklist maintains several types of lists containing IP addresses belonging to various categories. Some of these main categories include countries, ISPs and organizations. Other lists include web attacks, TOR, spyware and proxies. Many are free to use, and available in various formats.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt" target="_blank">IPsum</a>
        </td>
        <td>
            IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses. All lists are automatically retrieved and parsed on a daily (24h) basis and the final result is pushed to this repository. List is made of IP addresses together with a total number of (black)list occurrence (for each). Created and managed by <a href="https://twitter.com/stamparm">Miroslav Stampar</a>.
        </td>
    </tr>
    <tr>
    <tr>
        <td>
            <a href="https://support.kaspersky.com/datafeeds" target="_blank">Kaspersky Threat Data Feeds</a>
        </td>
        <td>
Continuously updated and inform your business or clients about risks and implications associated with cyber threats. The real-time data helps you to mitigate threats more effectively and defend against attacks even before they are launched. Demo Data Feeds contain truncated sets of IoCs (up to 1%) compared to the commercial ones
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://majestic.com/reports/majestic-million" target="_blank">Majestic Million</a>
        </td>
        <td>
            Probable Whitelist of the top 1 million web sites, as ranked by Majestic. Sites are ordered by the number of referring subnets. More about the ranking can be found on their <a href="https://blog.majestic.com/development/majestic-million-csv-daily/" target="_blank">blog</a>.
        </td>
    </tr>
    <tr>
        <td><a href="http://malc0de.com/bl/">Malc0de DNS Sinkhole</a></td>
        <td>The files in this link will be updated daily with domains that have been indentified distributing malware during the past 30 days. Collected by malc0de.</td>
    </tr>
    </tr>
    <tr>
        <td>
            <a href="https://maldatabase.com/" target="_blank">Maldatabase</a>
        </td>
        <td>
            Maldatabase is designed to help malware data science and threat intelligence feeds. Provided data contain good information about, among other fields, contacted domains, list of executed processes and dropped files by each sample. These feeds allow you to improve your monitoring and security tools. Free services are available for Security Researchers and Students. 
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://malpedia.caad.fkie.fraunhofer.de/" target="_blank">Malpedia</a>
        </td>
        <td>
The primary goal of Malpedia is to provide a resource for rapid identification and actionable context when investigating malware. Openness to curated contributions shall ensure an accountable level of quality in order to foster meaningful and reproducible research. 
        </td>
    </tr>    
    <tr>
        <td>
            <a href="http://www.malshare.com/" target="_blank">MalShare.com</a>
        </td>
        <td>
            The MalShare Project is a public malware repository that provides researchers free access to samples.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.maltiverse.com/" target="_blank">Maltiverse</a>
        </td>
        <td>
            The Maltiverse Project is a big and enriched IoC database where is possible to make complex queries, and aggregations to investigate about malware campaigns and its infrastructures. It also has a great IoC bulk query service.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.malwaredomainlist.com/" target="_blank">Malware Domain List</a>
        </td>
        <td>
            A searchable list of malicious domains that also performs reverse lookups and lists registrants, focused on phishing, trojans, and exploit kits.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://malware-traffic-analysis.net/" target="_blank">Malware-Traffic-Analysis.net</a>
        </td>
        <td>
            This blog focuses on network traffic related to malware infections. Contains traffic analysis exercises, tutorials, malware samples, pcap files of malicious network traffic, and technical blog posts with observations.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.malwaredomains.com/" target="_blank">MalwareDomains.com</a>
        </td>
        <td>
            The DNS-BH project creates and maintains a listing of domains that are known to be used to propagate malware and spyware. These can be used for detection as well as prevention (sinkholing DNS requests).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.opswat.com/developers/threat-intelligence-feed" target="_blank">MetaDefender Cloud</a>
        </td>
        <td>
            MetaDefender Cloud Threat Intelligence Feeds contains top new malware hash signatures, including MD5, SHA1, and SHA256. These new malicious hashes have been spotted by MetaDefender Cloud within the last 24 hours. The feeds are updated daily with newly detected and reported malware to provide actionable and timely threat intelligence.
        </td>
    </tr>
    <tr>
        <td><a href="http://data.netlab.360.com/">Netlab OpenData Project</a>
      </td>
      <td>
            The Netlab OpenData project was presented to the public first at ISC' 2016 on August 16, 2016. We currently provide multiple data feeds, including DGA, EK, MalCon, Mirai C2, Mirai-Scanner, Hajime-Scanner and DRDoS Reflector.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.nothink.org">NoThink!</a>
        </td>
        <td>SNMP, SSH, Telnet Blacklisted IPs from Matteo Cantoni's Honeypots</td>
    </tr>
    <tr>
        <td>
            <a href="https://services.normshield.com" target="_blank">NormShield Services</a>
        </td>
        <td>
            NormShield Services provide thousands of domain information (including whois information) that potential phishing attacks may come from. Breach and blacklist services also available. There is free sign up for public services for continuous monitoring.
        </td>
    </tr> 
    <tr>
        <td>
            <a href="https://openphish.com/phishing_feeds.html" target="_blank">OpenPhish Feeds</a>
        </td>
        <td>
            OpenPhish receives URLs from multiple streams and analyzes them using its proprietary phishing detection algorithms. There are free and commercial offerings available.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.phishtank.com/developer_info.php" target="_blank">PhishTank</a>
        </td>
        <td>
            PhishTank delivers a list of suspected phishing URLs. Their data comes from human reports, but they also ingest external feeds where possible. It's a free service, but registering for an API key is sometimes necessary.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://ransomwaretracker.abuse.ch/" target="_blank">Ransomware Tracker</a>
        </td>
        <td>
            The Ransomware Tracker by <a href="https://www.abuse.ch/" target="_blank">abuse.ch</a> tracks and monitors the status of domain names, IP addresses and URLs that are associated with Ransomware, such as Botnet C&amp;C servers, distribution sites and payment sites.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://rescure.fruxlabs.com/" target="_blank">REScure Threat Intel Feed</a>
        </td>
        <td>
            [RES]cure is an independant threat intelligence project performed by the Fruxlabs Crack Team to enhance their understanding of the underlying architecture of distributed systems, the nature of threat intelligence and how to efficiently collect, store, consume and distribute threat intelligence. Feeds are generated every 6 hours.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://report.cs.rutgers.edu/mrtg/drop/dropstat.cgi?start=-86400">Rutgers Blacklisted IPs</a>
        </td>
        <td>IP List of SSH Brute force attackers is created from a merged of locally observed IPs and 2 hours old IPs registered at badip.com and blocklist.de</td>
    </tr>
    <tr>
        <td>
            <a href="https://isc.sans.edu/suspicious_domains.html" target="_blank">SANS ICS Suspicious Domains</a>
        </td>
        <td>
            The Suspicious Domains Threat Lists by <a href="https://isc.sans.edu/suspicious_domains.html" target="_blank">SANS ICS</a> tracks suspicious domains. It offers 3 lists categorized as either <a href="https://isc.sans.edu/feeds/suspiciousdomains_High.txt" target="_blank">high</a>, <a href="https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt" target="_blank">medium</a> or <a href="https://isc.sans.edu/feeds/suspiciousdomains_Low.txt" target="_blank">low</a> sensitivity, where the high sensitivity list has fewer false positives, whereas the low sensitivity list with more false positives. There is also an <a href="https://isc.sans.edu/feeds/suspiciousdomains_whitelist_approved.txt" target="_blank">approved whitelist</a> of domains.<br/>
            Finally, there is a suggested <a href="https://isc.sans.edu/block.txt" target="_blank">IP blocklist</a> from <a href="https://dshield.org">DShield</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Neo23x0/signature-base" target="_blank">signature-base</a>
        </td>
        <td>
            A database of signatures used in other tools by Neo23x0.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.spamhaus.org/" target="_blank">The Spamhaus project</a>
        </td>
        <td>
            The Spamhaus Project contains multiple threatlists associated with spam and malware activity.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://sslbl.abuse.ch/" target="_blank">SSL Blacklist</a>
        </td>
        <td>
            SSL Blacklist (SSLBL) is a project maintained by abuse.ch. The goal is to provide a list of "bad" SSL certificates identified by abuse.ch to be associated with malware or botnet activities. SSLBL relies on SHA1 fingerprints of malicious SSL certificates and offers various blacklists
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://statvoo.com/dl/top-1million-sites.csv.zip" target="_blank">Statvoo Top 1 Million Sites</a>
        </td>
        <td>
            Probable Whitelist of the top 1 million web sites, as ranked by Statvoo.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://strongarm.io" target="_blank">Strongarm, by Percipient Networks</a>
        </td>
        <td>
            Strongarm is a DNS blackhole that takes action on indicators of compromise by blocking malware command and control. Strongarm aggregates free indicator feeds, integrates with commercial feeds, utilizes Percipient's IOC feeds, and operates DNS resolvers and APIs for you to use to protect your network and business. Strongarm is free for personal use.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://threatfeeds.io" target="_blank">threatfeeds.io</a>
        </td>
        <td>
            threatfeeds.io lists free and open-source threat intelligence feeds and sources and provides direct download links and live summaries.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://threatconnect.com/blog/ingest-technical-blogs-reports/" target="_blank">Technical Blogs and Reports, by ThreatConnect</a>
        </td>
        <td>
            This source is being populated with the content from over 90 open source, security blogs. IOCs (<a href="https://en.wikipedia.org/wiki/Indicator_of_compromise" target="_blank">Indicators of Compromise</a>) are parsed out of each blog and the content of the blog is formatted in markdown.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.threatglass.com/" target="_blank">Threatglass</a>
        </td>
        <td>
            An online tool for sharing, browsing and analyzing web-based malware. Threatglass allows users to graphically browse website infections by viewing screenshots of the stages of infection, as well as by analyzing network characteristics such as host relationships and packet captures.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.threatminer.org/" target="_blank">ThreatMiner</a>
        </td>
        <td>
            ThreatMiner has been created to free analysts from data collection and to provide them a portal on which they can carry out their tasks, from reading reports to pivoting and data enrichment.
            The emphasis of ThreatMiner isn't just about indicators of compromise (IoC) but also to provide analysts with contextual information related to the IoC they are looking at.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://raw.githubusercontent.com/WSTNPHX/scripts-n-tools/master/malware-email-addresses.txt">WSTNPHX Malware Email Addresses</a>
        </td>
        <td>Email addresses used by malware collected by VVestron Phoronix (WSTNPHX)</td>
    </tr>
    <tr>
        <td>
            <a href="https://portal.underattack.today/" target="_blank">UnderAttack.today</a>
        </td>
        <td>UnderAttack is a free intelligence platform, it shares IPs and information about suspicious events and attacks. Registration is free at <a href="https://portal.underattack.today" target="_blank">https://portal.underattack.today</a></td>
    </tr>
    <tr>
        <td>
            <a href="https://urlhaus.abuse.ch">URLhaus</a>
        </td>
        <td>URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.</td>
    </tr>
    <tr>
        <td>
            <a href="https://virusshare.com/" target="_blank">VirusShare</a>
        </td>
        <td>
            VirusShare.com is a repository of malware samples to provide security researchers, incident responders, forensic analysts, and the morbidly curious access to samples of malicious code. Access to the site is granted via invitation only.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Yara-Rules/rules" target="_blank">Yara-Rules</a>
        </td>
        <td>
            An open source repository with different Yara signatures that are compiled, classified and kept as up to date as possible.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://zeustracker.abuse.ch/" target="_blank">ZeuS Tracker</a>
        </td>
        <td>
            The ZeuS Tracker by <a href="https://www.abuse.ch/" target="_blank">abuse.ch</a> tracks ZeuS Command & Control servers (hosts) around the world and provides you a domain- and a IP-blocklist.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://IOCFeed.mrlooquer.com/" target="_blank">1st Dual Stack Threat Feed by MrLooquer</a>
        </td>
        <td>
Mrlooquer has created the first threat feed focused on systems with dual stack. Since IPv6 protocol has begun to be part of malware and fraud communications, It is necessary to detect and mitigate the threats in both protocols (IPv4 and IPv6).
        </td>
    </tr>
</table>

## Formats

Standardized formats for sharing Threat Intelligence (mostly IOCs).

<table>
    <tr>
        <td>
            <a href="https://capec.mitre.org/" target="_blank">CAPEC</a>
        </td>
        <td>
            The Common Attack Pattern Enumeration and Classification (CAPEC) is a comprehensive dictionary and classification taxonomy of known attacks that can be used by analysts, developers, testers, and educators to advance community understanding and enhance defenses.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://cyboxproject.github.io/" target="_blank">CybOX</a>
        </td>
        <td>
            The Cyber Observable eXpression (CybOX) language provides a common structure for representing cyber observables across and among the operational areas of enterprise cyber security that improves the consistency, efficiency, and interoperability of deployed tools and processes, as well as increases overall situational awareness by enabling the potential for detailed automatable sharing, mapping, detection, and analysis heuristics.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://tools.ietf.org/html/rfc5070" target="_blank">IODEF (RFC5070)</a>
        </td>
        <td>
            The Incident Object Description Exchange Format (IODEF) defines a data representation that provides a framework for sharing information commonly exchanged by Computer Security Incident Response Teams (CSIRTs) about computer security incidents.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://tools.ietf.org/html/rfc4765" target="_blank">IDMEF (RFC4765)</a>
        </td>
        <td>
            <i>Experimental</i> - The purpose of the Intrusion Detection Message Exchange Format (IDMEF) is to define data formats and exchange procedures for sharing information of interest to intrusion detection and response systems and to the management systems that may need to interact with them.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://maecproject.github.io/" target="_blank">MAEC</a>
        </td>
        <td>
            The Malware Attribute Enumeration and Characterization (MAEC) projects is aimed at creating and providing a standardized language for sharing structured information about malware based upon attributes such as behaviors, artifacts, and attack patterns.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=openc2" target="_blank">OpenC2</a>
        </td>
        <td>
            OASIS Open Command and Control (OpenC2) Technical Committee. The OpenC2 TC will base its efforts on artifacts generated by the OpenC2 Forum. Prior to the creation of this TC and specification, the OpenC2 Forum was a community of cyber-security stakeholders that was facilitated by the National Security Agency (NSA). The OpenC2 TC was chartered to draft documents, specifications, lexicons or other artifacts to fulfill the needs of cyber security command and control in a standardized manner.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://oasis-open.github.io/cti-documentation/" target="_blank">STIX 2.0</a>
        </td>
        <td>
            The Structured Threat Information eXpression (STIX) language is a standardized construct to represent cyber threat information. The STIX Language intends to convey the full range of potential cyber threat information and strives to be fully expressive, flexible, extensible, and automatable. STIX does not only allow tool-agnostic fields, but also provides so-called <i>test mechanisms</i> that provide means for embedding tool-specific elements, including OpenIOC, Yara and Snort. STIX 1.x has been archived <a href="https://stixproject.github.io/" target="_blank">here</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://taxiiproject.github.io/" target="_blank">TAXII</a>
        </td>
        <td>
            The Trusted Automated eXchange of Indicator Information (TAXII) standard defines a set of services and message exchanges that, when implemented,  enable sharing of actionable cyber threat information across organization and product/service boundaries. TAXII defines concepts, protocols, and message exchanges to exchange cyber threat information for the detection, prevention, and mitigation of cyber threats.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://veriscommunity.net/index.html" target="_blank">VERIS</a>
        </td>
        <td>
            The Vocabulary for Event Recording and Incident Sharing (VERIS) is a set of metrics designed to provide a common language for describing security incidents in a structured and repeatable manner. VERIS is a response to one of the most critical and persistent challenges in the security industry - a lack of quality information. In addition to providing a structured format, VERIS also collects data from the community to report on breaches in the Verizon Data Breach Investigations Report (<a target="_blank" href="http://www.verizonenterprise.com/verizon-insights-lab/dbir/">DBIR</a>) and publishes this database online at <a target="_blank" href="http://vcdb.org/index.html">VCDB.org</a>.
        </td>
    </tr>
</table>

## Frameworks and Platforms

Frameworks, platforms and services for collecting, analyzing, creating and sharing Threat Intelligence.

<table>
    <tr>
        <td>
            <a href="https://github.com/abusesa/abusehelper" target="_blank">AbuseHelper</a>
        </td>
        <td>
            AbuseHelper is an open-source framework for receiving and redistributing abuse feeds and threat intel.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://abuse.io/" target="_blank">AbuseIO</a>
        </td>
        <td>
            A toolkit to receive, process, correlate and notify end users about abuse reports, thereby consuming threat intelligence feeds.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.dhs.gov/ais" target="_blank">AIS</a>
        </td>
        <td>
            The Department of Homeland Security’s (DHS) free Automated Indicator Sharing (AIS) capability enables the exchange of cyber threat indicators between the Federal Government and the private sector at machine speed. Threat indicators are pieces of information like malicious IP addresses or the sender address of a phishing email (although they can also be much more complicated).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.fidelissecurity.com/resources/fidelis-barncat" target="_blank">Barncat</a>
        </td>
        <td>
            Fidelis Cybersecurity offers free access to Barncat after registration. The platform is intended to be used by CERTs, researchers, governments, ISPs and other, large organizations. The database holds various configuration settings used by attackers.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/csirtgadgets/bearded-avenger" target="_blank">Bearded Avenger</a>
        </td>
        <td>
            The fastest way to consume threat intelligence. Successor to CIF.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://community.blueliv.com/" target="_blank">Blueliv Threat Exchange Network</a>
        </td>
        <td>
            Allows participants to share threat indicators with the community.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/TheHive-Project/Cortex" target="_blank">Cortex</a>
        </td>
        <td>
            Cortex allows observables, such as IPs, email addresses, URLs, domain names, files or hashes, to be analyzed one by one or in bulk mode using a single web interface. The web interface acts as a frontend for numerous analyzers, removing the need for integrating these yourself during analysis. Analysts can also use the Cortex REST API to automate parts of their analysis.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://crits.github.io/" target="_blank">CRITS</a>
        </td>
        <td>
            CRITS is a platform that provides analysts with the means to conduct collaborative research into malware and threats. It plugs into a centralized intelligence data repository, but can also be used as a private instance.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://csirtgadgets.org/collective-intelligence-framework" target="_blank">CIF</a>
        </td>
        <td>
            The Collective Intelligence Framework (CIF) allows you to combine known malicious threat information from many sources and use that information for IR, detection and mitigation. Code available on <a href="https://github.com/csirtgadgets/massive-octo-spice" target="_blank">GitHub</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.eclecticiq.com/platform" target="_blank">EclecticIQ Platform</a>
        </td>
        <td>
            EclecticIQ Platform is a STIX/TAXII based Threat Intelligence Platform (TIP) that empowers threat analysts to perform faster, better, and deeper investigations while disseminating intelligence at machine-speed.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.enisa.europa.eu/topics/csirt-cert-services/community-projects/incident-handling-automation" target="_blank">IntelMQ</a>
        </td>
        <td>
            IntelMQ is a solution for CERTs for collecting and processing security feeds, pastebins, tweets using a message queue protocol. It's a community driven initiative called IHAP (Incident Handling Automation Project) which was conceptually designed by European CERTs during several InfoSec events. Its main goal is to give to incident responders an easy way to collect & process threat intelligence thus improving the incident handling processes of CERTs.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.intelstitch.com" target="_blank">IntelStitch</a>
        </td>
        <td>
            IntelStitch streamlines the aggregation, enforcement and sharing of cyber threat intelligence. IntelStitch can collect and process intelligence from traditional threat feeds as well as more dynamic sources including Pastebin pastes, tweets, and forums so that it can be integrated with downstream security tools.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://technet.microsoft.com/en-us/security/dn458536" target="_blank">Interflow</a>
        </td>
        <td>
            Interflow is a security and threat information exchange platform created by Microsoft for professionals working in cybersecurity.
            It uses a distributed architecture which enables sharing of security and threat information within and between communities for a collectively stronger ecosystem.
            Offering multiple configuration options, Interflow allows users to decide what communities to form, what data feeds to consume, and with whom.
            Interflow is currently in private preview.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.kaspersky.com/enterprise-security/threat-intelligence" target="_blank">Kaspersky Threat Intelligence Portal</a>
        </td>
        <td>
            A website that provides a knowledge base describing cyber threats, legitimate objects, and their relationships, brought together into a single web service. Subscribing to Kaspersky Lab’s Threat Intelligence Portal provides you with a single point of entry to four complementary services: Kaspersky Threat Data Feeds, Threat Intelligence Reporting, Kaspersky Threat Lookup and Kaspersky Research Sandbox, all available in human-readable and machine-readable formats.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/byt3smith/malstrom" target="_blank">Malstrom</a>
        </td>
        <td>
            Malstrom aims to be a repository for threat tracking and forensic artifacts, but also stores YARA rules and notes for investigation. Note: Github project has been archived (no new contributions accepted).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/stratosphereips/Manati" target="_blank">ManaTI</a>
        </td>
        <td>
            The ManaTI project assists threat analyst by employing machine learning techniques that find new relationships and inferences automatically.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://django-mantis.readthedocs.io/en/latest/" target="_blank">MANTIS</a>
        </td>
        <td>
            The Model-based Analysis of Threat Intelligence Sources (MANTIS) Cyber Threat Intelligence Management Framework supports the management of cyber threat intelligence expressed in various standard languages, like STIX and CybOX. It is *not* ready for large-scale production though.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/cert-se/megatron-java" target="_blank">Megatron</a>
        </td>
        <td>
            Megatron is a tool implemented by CERT-SE which collects and analyses bad IPs, can be used to calculate statistics, convert and analyze log files and in abuse & incident handling.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/PaloAltoNetworks/minemeld/wiki" target="_blank">MineMeld</a>
        </td>
        <td>
            An extensible Threat Intelligence processing framework created Palo Alto Networks.
            It can be used to manipulate lists of indicators and transform and/or aggregate them for consumption by third party enforcement infrastructure.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.misp-project.org/" target="_blank">MISP</a>
        </td>
        <td>
            The Malware Information Sharing Platform (MISP) is an open source software solution for collecting, storing, distributing and sharing cyber security indicators and malware analysis.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/CERT-Polska/n6" target="_blank">n6</a>
        </td>
        <td>
            n6 (Network Security Incident eXchange) is a system to collect, manage and distribute security information on a large scale. Distribution is realized through a simple REST API and a web interface that authorized users can use to receive various types of data, in particular information on threats and incidents in their networks. It is developed by <a href="https://www.cert.pl/en/" target="_blank">CERT Polska</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.opencti.io/en/" target="_blank">OpenCTI</a>
        </td>
        <td>
            OpenCTI, the Open Cyber Threat Intelligence platform, allows organizations to manage their cyber threat intelligence knowledge and observables. Its goal is to structure, store, organize and visualize technical and non-technical information about cyber threats. Data is structured around a knowledge schema based on the STIX2 standards. OpenCTI can be integrated with other tools and platforms, including MISP, TheHive, and MITRE ATT&CK, a.o.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.fireeye.com/services/freeware.html" target="_blank">OpenIOC</a>
        </td>
        <td>
            OpenIOC is an open framework for sharing threat intelligence. It is designed to exchange threat information both internally and externally in a machine-digestible format.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/EclecticIQ/OpenTAXII" target="_blank">OpenTAXII</a>
        </td>
        <td>
            OpenTAXII is a robust Python implementation of TAXII Services that delivers a rich feature set and a friendly Pythonic API built on top of a well designed application.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Ptr32Void/OSTrICa" target="_blank">OSTrICa</a>
        </td>
        <td>
            An open source plugin-oriented framework to collect and visualize Threat Intelligence information.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://otx.alienvault.com" target="_blank">OTX - Open Threat Exchange</a>
        </td>
        <td>
            AlienVault Open Threat Exchange (OTX) provides open access to a global community of threat researchers and security professionals. It delivers community-generated threat data, enables collaborative research, and automates the process of updating your security infrastructure with threat data from any source.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Lookingglass/opentpx/" target="_blank">Open Threat Partner eXchange</a>
        </td>
        <td>
            The Open Threat Partner eXchange (OpenTPX) consists of an open-source format and tools for exchanging machine-readable threat intelligence and network security operations data. It is a JSON-based format that allows sharing of data between connected systems.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://community.riskiq.com/" target="_blank">PassiveTotal</a>
        </td>
        <td>
            The PassiveTotal platform offered by RiskIQ is a threat-analysis platform which provides analysts with as much data as possible in order to prevent attacks before they happen. Several types of solutions are offered, as well as integrations (APIs) with other systems.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://pulsedive.com/" target="_blank">Pulsedive</a>
        </td>
        <td>
            Pulsedive is a free, community threat intelligence platform that is consuming open-source feeds, enriching the IOCs, and running them through a risk-scoring algorithm to improve the quality of the data. It allows users to submit, search, correlate, and update IOCs; lists "risk factors" for why IOCs are higher risk; and provides a high level view of threats and threat activity.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.recordedfuture.com/" target="_blank">Recorded Future</a>
        </td>
        <td>
            Recorded Future is a premium SaaS product that automatically unifies threat intelligence from open, closed, and technical sources into a single solution. Their technology uses natural language processing (NLP) and machine learning to deliver that threat intelligence in real time — making Recorded Future a popular choice for IT security teams.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Netflix/Scumblr" target="_blank">Scumblr</a>
        </td>
        <td>
            Scumblr is a web application that allows performing periodic syncs of data sources (such as Github repositories and URLs) and performing analysis (such as static analysis, dynamic checks, and metadata collection) on the identified results.
            Scumblr helps you streamline proactive security through an intelligent automation framework to help you identify, track, and resolve security issues faster.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.celerium.com/automate" target="_blank">Soltra</a>
        </td>
        <td>
            Soltra supports a community defense model that is highly interoperable and extensible. It is built with industry standards supported out of the box, including STIX (up to 2.1) and TAXII.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.anomali.com/platform/staxx" target="_blank">STAXX (Anomali)</a>
        </td>
        <td>
            Anomali STAXX™ gives you a free, easy way to subscribe to any STIX/TAXII feed. Simply download the STAXX client, configure your data sources, and STAXX will handle the rest.
        </td>
    </tr>    
    <tr>
        <td>
            <a href="http://stoq.punchcyber.com/" target="_blank">stoQ</a>
        </td>
        <td>
            stoQ is a framework that allows cyber analysts to organize and automate repetitive, data-driven tasks. It features plugins for many other systems to interact with.
            One use case is the extraction of IOCs from documents, an example of which is shown <a href="https://stoq-framework.blogspot.nl/2016/04/operationalizing-indicators.html" target="_blank">here</a>, but it can also be used for deobfuscationg and decoding of content and automated scanning with YARA, for example.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/tripwire/tardis" target="_blank">TARDIS</a>
        </td>
        <td>
            The Threat Analysis, Reconnaissance, and Data Intelligence System (TARDIS) is an open source framework for performing historical searches using attack signatures.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.threatconnect.com/" target="_blank">ThreatConnect</a>
        </td>
        <td>
            ThreatConnect is a platform with threat intelligence, analytics, and orchestration capabilities. It is designed to help you collect data, produce intelligence, share it with others, and take action on it.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.threatcrowd.org/" target="_blank">ThreatCrowd</a>
        </td>
        <td>
            ThreatCrowd is a system for finding and researching artefacts relating to cyber threats.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.threatpipes.com" target="_blank">ThreatPipes</a>
        </td>
        <td>
            Stay two steps ahead of your adversaries. Get a complete picture of how they will exploit you.
            <br />
            ThreatPipes is a reconnaissance tool that automatically queries 100’s of data sources to gather intelligence on IP addresses, domain names, e-mail addresses, names and more.
            <br />
            You simply specify the target you want to investigate, pick which modules to enable and then ThreatPipes will collect data to build up an understanding of all the entities and how they relate to each other.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://developers.facebook.com/docs/threat-exchange/" target="_blank">ThreatExchange</a>
        </td>
        <td>
            Facebook created ThreatExchange so that participating organizations can share threat data using a convenient, structured, and easy-to-use API that provides privacy controls to enable sharing with only desired groups. This project is still in <b>beta</b>. Reference code can be found at <a href="https://github.com/facebook/ThreatExchange" target="_blank">GitHub</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://beta.virusbay.io/" target="_blank">VirusBay</a>
        </td>
        <td>
            VirusBay is a web-based, collaboration platform that connects security operations center (SOC) professionals with relevant malware researchers.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/brianwarehime/threatnote" target="_blank">threatnote.io</a>
        </td>
        <td>
            The new and improved threatnote.io - A tool for CTI analysts and teams to manage intel requirements, reporting, and CTI processes in an all-in-one platform
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://exchange.xforce.ibmcloud.com/" target="_blank">XFE - X-Force Exchange</a>
        </td>
        <td>
            The X-Force Exchange (XFE) by IBM XFE is a free SaaS product that you can use to search for threat intelligence information, collect your findings, and share your insights with other members of the XFE community.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://yeti-platform.github.io/" target="_blank">Yeti</a>
        </td>
        <td>
            The open, distributed, machine and analyst-friendly threat intelligence repository. Made by and for incident responders.
        </td>
    </tr>
</table>



## Tools

All kinds of tools for parsing, creating and editing Threat Intelligence. Mostly IOC based.

<table>
    <tr>
        <td>
            <a href="https://actortrackr.com/" target="_blank">ActorTrackr</a>
        </td>
        <td>
            ActorTrackr is an open source web application for storing/searching/linking actor related data. The primary sources are from users and various public repositories. Source available on <a href="https://github.com/dougiep16/actortrackr" target="_blank">GitHub</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://bitbucket.org/camp0/aiengine" target="_blank">AIEngine</a>
        </td>
        <td>
            AIEngine is a next generation interactive/programmable Python/Ruby/Java/Lua packet inspection engine with capabilities of learning without any human intervention, NIDS(Network Intrusion Detection System) functionality, DNS domain classification, network collector, network forensics and many others. Source available on <a href="https://bitbucket.org/camp0/aiengine" target="_blank">Bitbucket</a>.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/1aN0rmus/TekDefense-Automater" target="_blank">Automater</a>
        </td>
        <td>
            Automater is a URL/Domain, IP Address, and Md5 Hash OSINT tool aimed at making the analysis process easier for intrusion Analysts.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://botscout.com/">BotScout</a>
        </td>
        <td>
            BotScout helps prevent automated web scripts, known as "bots", from registering on forums, polluting databases, spreading spam, and abusing forms on web sites.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/exp0se/bro-intel-generator" target="_blank">bro-intel-generator</a>
        </td>
        <td>
            Script for generating Bro intel files from pdf or html reports.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/EclecticIQ/cabby" target="_blank">cabby</a>
        </td>
        <td>
            A simple Python library for interacting with TAXII servers.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/sroberts/cacador" target="_blank">cacador</a>
        </td>
        <td>
            Cacador is a tool written in Go for extracting common indicators of compromise from a block of text.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mlsecproject/combine" target="_blank">Combine</a>
        </td>
        <td>
            Combine gathers Threat Intelligence Feeds from publicly available sources.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/CrowdStrike/CrowdFMS" target="_blank">CrowdFMS</a>
        </td>
        <td>
            CrowdFMS is a framework for automating collection and processing of samples from VirusTotal, by leveraging the Private API system.
            The framework automatically downloads recent samples, which triggered an alert on the users YARA notification feed.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/CylanceSPEAR/CyBot" target="_blank">CyBot</a>
        </td>
        <td>
            CyBot is a threat intelligence chat bot. It can perform several types of lookups offered by custom modules.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/cuckoosandbox/cuckoo" target="_blank">Cuckoo Sandbox</a>
        </td>
        <td>
            Cuckoo Sandbox is an automated dynamic malware analysis system. It's the most well-known open source malware analysis sandbox around and is frequently deployed by researchers, CERT/SOC teams, and threat intelligence teams all around the globe. For many organizations Cuckoo Sandbox provides a first insight into potential malware samples.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Neo23x0/Fenrir" target="_blank">Fenrir</a>
        </td>
        <td>
            Simple Bash IOC Scanner.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/spacepatcher/FireHOL-IP-Aggregator" target="_blank">FireHOL IP Aggregator</a>
        </td>
        <td>
            Application for keeping feeds from FireHOL <a href="https://github.com/firehol/blocklist-ipsets" target="_blank">blocklist-ipsets</a> with IP addresses appearance history. HTTP-based API service is developed for search requests.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/byt3smith/Forager" target="_blank">Forager</a>
        </td>
        <td>
            Multithreaded threat intelligence hunter-gatherer script.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/BinaryDefense/goatrider" target="_blank">GoatRider</a>
        </td>
        <td>
            GoatRider is a simple tool that will dynamically pull down Artillery Threat Intelligence Feeds, TOR, AlienVaults OTX, and the Alexa top 1 million websites and do a comparison to a hostname file or IP file.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://cse.google.com/cse/publicurl?cx=003248445720253387346:turlh5vi4xc" target="_blank">Google APT Search Engine</a>
        </td>
        <td>
            APT Groups, Operations and Malware Search Engine. The sources used for this Google Custom Search are listed on <a href="https://gist.github.com/Neo23x0/c4f40629342769ad0a8f3980942e21d3" target="_blank"this</a> GitHub gist.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ciscocsirt/gosint" target="_blank">GOSINT</a>
        </td>
        <td>
            The GOSINT framework is a free project used for collecting, processing, and exporting high quality public indicators of compromise (IOCs).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://hashdd.com/" target="_blank">hashdd</a>
        </td>
        <td>
            A tool to lookup related information from crytographic hash value
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/exp0se/harbinger" target="_blank">Harbinger Threat Intelligence</a>
        </td>
        <td>
            Python script that allows to query multiple online threat aggregators from a single interface.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/TheHive-Project/Hippocampe" target="_blank">Hippocampe</a>
        </td>
        <td>
            Hippocampe aggregates threat feeds from the Internet in an Elasticsearch cluster. It has a REST API which allows to search into its 'memory'. It is based on a Python script which fetchs URLs corresponding to feeds, parses and indexes them.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/S03D4-164/Hiryu" target="_blank">Hiryu</a>
        </td>
        <td>
            A tool to organize APT campaign information and to visualize relations between IOCs.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.fireeye.com/services/freeware/ioc-editor.html" target="_blank">IOC Editor</a>
        </td>
        <td>
            A free editor for Indicators of Compromise (IOCs).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/fhightower/ioc-finder" target="_blank">IOC Finder</a>
        </td>
        <td>
            Python library for finding indicators of compromise in text. Uses grammars rather than regexes for improved comprehensibility. As of February, 2019, it parses over 18 indicator types.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ioc-fang/ioc_fanger" target="_blank">IOC Fanger (and Defanger)</a>
        </td>
        <td>
            Python library for fanging (`hXXp://example[.]com` => `http://example.com`) and defanging (`http://example.com` => `hXXp://example[.]com`) indicators of compromise in text.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/armbues/ioc_parser" target="_blank">ioc_parser</a>
        </td>
        <td>
            Tool to extract indicators of compromise from security reports in PDF format.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mandiant/ioc_writer" target="_blank">ioc_writer</a>
        </td>
        <td>
            Provides a Python library that allows for basic creation and editing of OpenIOC objects.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/InQuest/python-iocextract" target="_blank">iocextract</a>
        </td>
        <td>
            Extracts URLs, IP addresses, MD5/SHA hashes, email addresses, and YARA rules from text corpora. Includes some encoded and “defanged” IOCs in the output, and optionally decodes/refangs them.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/stephenbrannon/IOCextractor" target="_blank">IOCextractor</a>
        </td>
        <td>
            IOC (Indicator of Compromise) Extractor is a program to help extract IOCs from text files. The general goal is to speed up the process of parsing structured data (IOCs) from unstructured or semi-structured data
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/johestephan/ibmxforceex.checker.py" target="_blank">ibmxforceex.checker.py</a>
        </td>
        <td>
            Python client for the IBM X-Force Exchange.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/sroberts/jager" target="_blank">jager</a>
        </td>
        <td>
            Jager is a tool for pulling useful IOCs (indicators of compromise) out of various input sources (PDFs for now, plain text really soon, webpages eventually) and putting them into an easy to manipulate JSON format.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://support.kaspersky.com/13850" target="_blank">Kaspersky CyberTrace</a>
        </td>
        <td>
            Threat intelligence fusion and analysis tool that integrates threat data feeds with SIEM solutions. Users can immediately leverage threat intelligence for security monitoring and incident report (IR) activities in the workflow of their existing security operations.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/KasperskyLab/klara" target="_blank">KLara</a>
        </td>
        <td>
            KLara, a distributed system written in Python, allows researchers to scan one or more Yara rules over collections with samples, getting notifications by e-mail as well as the web interface when scan results are ready.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/TAXIIProject/libtaxii" target="_blank">libtaxii</a>
        </td>
        <td>
            A Python library for handling TAXII Messages invoking TAXII Services.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Neo23x0/Loki" target="_blank">Loki</a>
        </td>
        <td>
            Simple IOC and Incident Response Scanner.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://bitbucket.org/ssanthosh243/ip-lookup-docker" target="_blank">LookUp</a>
        </td>
        <td>
            LookUp is a centralized page to get various threat information about an IP address. It can be integrated easily into context menus of tools like SIEMs and other investigative tools.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/HurricaneLabs/machinae" target="_blank">Machinae</a>
        </td>
        <td>
            Machinae is a tool for collecting intelligence from public sites/feeds about various security-related pieces of data: IP addresses, domain names, URLs, email addresses, file hashes and SSL fingerprints.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/silascutler/MalPipe" target="_blank">MalPipe</a>
        </td>
        <td>
            Amodular malware (and indicator) collection and processing framework. It is designed to pull malware, domains, URLs and IP addresses from multiple feeds, enrich the collected data and export the results.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/MISP/misp-workbench" target="_blank">MISP Workbench</a>
        </td>
        <td>
            Tools to export data out of the MISP MySQL database and use and abuse them outside of this platform.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/MISP/MISP-Taxii-Server" target="_blank">MISP-Taxii-Server</a>
        </td>
        <td>
            A set of configuration files to use with EclecticIQ's OpenTAXII implementation, along with a callback for when data is sent to the TAXII Server's inbox.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/paulpc/nyx" target="_blank">nyx</a>
        </td>
        <td>
            The goal of this project is to facilitate distribution of Threat Intelligence artifacts to defensive systems and to enhance the value derived from both open source and commercial tools.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/fhightower/onemillion" target="_blank">OneMillion</a>
        </td>
        <td>
            Python library to determine if a domain is in the Alexa or Cisco top, one million domain lists.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/STIXProject/openioc-to-stix" target="_blank">openioc-to-stix</a>
        </td>
        <td>
            Generate STIX XML from OpenIOC XML.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/InQuest/omnibus" target="_blank">Omnibus</a>
        </td>
        <td>
            Omnibus is an interactive command line application for collecting and managing IOCs/artifacts (IPs, Domains, Email Addresses, Usernames, and Bitcoin Addresses), enriching these artifacts with OSINT data from public sources, and providing the means to store and access these artifacts in a simple way.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/kx499/ostip/wiki" target="_blank">OSTIP</a>
        </td>
        <td>
            A homebrew threat data platform.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mgeide/poortego" target="_blank">poortego</a>
        </td>
        <td>
            Open-source project to handle the storage and linking of open-source intelligence (ala Maltego, but free as in beer and not tied to a specific / proprietary database). Originally developed in ruby, but new codebase completely rewritten in python.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/yahoo/PyIOCe" target="_blank">PyIOCe</a>
        </td>
        <td>
            PyIOCe is an IOC editor written in Python.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/QTek/QRadio" target="_blank">QRadio</a>
        </td>
        <td>
            QRadio is a tool/framework designed to consolidate cyber threats intelligence sources.
            The goal of the project is to establish a robust modular framework for extraction of intelligence data from vetted sources.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/aboutsecurity/rastrea2r" target="_blank">rastrea2r</a>
        </td>
        <td>
            Collecting & Hunting for Indicators of Compromise (IOC) with gusto and style!
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.fireeye.com/services/freeware/redline.html" target="_blank">Redline</a>
        </td>
        <td>
            A host investigations tool that can be used for, amongst others, IOC analysis.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ocmdev/rita" target="_blank">RITA</a>
        </td>
        <td>
            Real Intelligence Threat Analytics (RITA) is intended to help in the search for indicators of compromise in enterprise networks of varying size.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/spacepatcher/softrace" target="_blank">Softrace</a>
        </td>
        <td>
            Lightweight National Software Reference Library RDS storage.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/SecurityRiskAdvisors/sra-taxii2-server" target="_blank">SRA TAXII2 Server</a>
        </td>
        <td>
            Full TAXII 2.0 specification server implemented in Node JS with MongoDB backend.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/STIXProject/stix-viz" target="_blank">stix-viz</a>
        </td>
        <td>
            STIX Visualization Tool.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://test.taxiistand.com/" target="_blank">TAXII Test Server</a>
        </td>
        <td>
            Allows you to test your TAXII environment by connecting to the provided services and performing the different functions as written in the TAXII specifications.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/jpsenior/threataggregator" target="_blank">threataggregator</a>
        </td>
        <td>
            ThreatAggregrator aggregates security threats from a number of online sources, and outputs to various formats, including CEF, Snort and IPTables rules.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/jheise/threatcrowd_api" target="_blank">threatcrowd_api</a>
        </td>
        <td>
            Python Library for ThreatCrowd's API.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/jheise/threatcmd" target="_blank">threatcmd</a>
        </td>
        <td>
            Cli interface to ThreatCrowd.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/syphon1c/Threatelligence" target="_blank">Threatelligence</a>
        </td>
        <td>
            Threatelligence is a simple cyber threat intelligence feed collector, using Elasticsearch, Kibana and Python to automatically collect intelligence from custom or public sources. Automatically updates feeds and tries to further enhance data for dashboards. Projects seem to be no longer maintained, however.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/InQuest/ThreatIngestor" target="_blank">ThreatIngestor</a>
        </td>
        <td>
            Flexible, configuration-driven, extensible framework for consuming threat intelligence. ThreatIngestor can watch Twitter, RSS feeds, and other sources, extract meaningful information like C2 IPs/domains and YARA signatures, and send that information to other systems for analysis.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://chrome.google.com/webstore/detail/threatpinch-lookup/ljdgplocfnmnofbhpkjclbefmjoikgke" target="_blank">ThreatPinch Lookup</a>
        </td>
        <td>
            An extension for Chrome that creates hover popups on every page for IPv4, MD5, SHA2, and CVEs. It can be used for lookups during threat investigations.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/michael-yip/ThreatTracker" target="_blank">ThreatTracker</a>
        </td>
        <td>
            A Python script designed to monitor and generate alerts on given sets of  IOCs indexed by a set of Google Custom Search Engines.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Yelp/threat_intel" target="_blank">threat_intel</a>
        </td>
        <td>
            Several APIs for Threat Intelligence integrated in a single package. Included are: OpenDNS Investigate, VirusTotal and ShadowServer.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/abhinavbom/Threat-Intelligence-Hunter" target="_blank">Threat-Intelligence-Hunter</a>
        </td>
        <td>
            TIH is an intelligence tool that helps you in searching for IOCs across multiple openly available security feeds and some well known APIs. The idea behind the tool is to facilitate searching and storing of frequently added IOCs for creating your own local database of indicators.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mlsecproject/tiq-test" target="_blank">tiq-test</a>
        </td>
        <td>
            The Threat Intelligence Quotient (TIQ) Test tool provides visualization and statistical analysis of TI feeds.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/TAXIIProject/yeti" target="_blank">YETI</a>
        </td>
        <td>
            YETI is a proof-of-concept implementation of TAXII that supports the Inbox, Poll and Discovery services defined by the TAXII Services Specification.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/0x4d31/sqhunter" target="_blank">sqhunter</a>
        </td>
        <td>
            Threat hunter based on osquery, Salt Open and Cymon API. It can query open network sockets and check them against threat intelligence sources
        </td>
    </tr>
</table>



## <a name="research"></a>Research, Standards & Books

All kinds of reading material about Threat Intelligence. Includes (scientific) research and whitepapers.

<table>
    <tr>
        <td>
            <a href="https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections" target="_blank">APT & Cyber Criminal Campaign Collection</a>
        </td>
        <td>
            Extensive collection of (historic) campaigns. Entries come from various sources.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/kbandla/APTnotes" target="_blank">APTnotes</a>
        </td>
        <td>
            A great collection of sources regarding <i>Advanced Persistent Threats</i> (APTs). These reports usually include strategic and tactical knowledge or advice.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://attack.mitre.org/wiki/Main_Page" target="_blank">ATT&CK</a>
        </td>
        <td>
            Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK™) is a model and framework for describing the actions an adversary may take while operating within an enterprise network. ATT&CK is a constantly growing common reference for post-access techniques that brings greater awareness of what actions may be seen during a network intrusion. MITRE is actively working on integrating with related construct, such as CAPEC, STIX and MAEC.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.activeresponse.org/building-threat-hunting-strategy-with-the-diamond-model/" target="_blank">Building Threat Hunting Strategies with the Diamond Model</a>
        </td>
        <td>
            Blogpost by Sergio Caltagirone on how to develop intelligent threat hunting strategies by using the Diamond Model.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://car.mitre.org/wiki/Main_Page" target="_blank">Cyber Analytics Repository by MITRE</a>
        </td>
        <td>
            The Cyber Analytics Repository (CAR) is a knowledge base of analytics developed by MITRE based on the Adversary Tactics, Techniques, and Common Knowledge (ATT&CK™) threat model.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mitre/cti" target="_blank">Cyber Threat Intelligence Repository by MITRE</a>
        </td>
        <td>
            The Cyber Threat Intelligence Repository of ATT&CK and CAPEC catalogs expressed in STIX 2.0 JSON.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://cryptome.org/2015/09/cti-guide.pdf" target="_blank">Definitive Guide to Cyber Threat Intelligence</a>
        </td>
        <td>
            Describes the elements of cyber threat intelligence and discusses how it is collected, analyzed, and used by a variety of human and technology consumers. Further examines how intelligence can improve cybersecurity at tactical, operational, and strategic levels, and how it can help you stop attacks sooner, improve your defenses, and talk more productively about cybersecurity issues with executive management in typical <i>for Dummies</i> style.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://ryanstillions.blogspot.nl/2014/04/the-dml-model_21.html" target="_blank">The Detection Maturity Level (DML)</a>
        </td>
        <td>
            The DML model is a capability maturity model for referencing ones maturity in detecting cyber attacks.
            It's designed for organizations who perform intel-driven detection and response and who put an emphasis on having a mature detection program.
            The maturity of an organization is not measured by it's ability to merely obtain relevant intelligence, but rather it's capacity to apply that intelligence effectively to detection and response functions.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.threatconnect.com/wp-content/uploads/ThreatConnect-The-Diamond-Model-of-Intrusion-Analysis.pdf" target="_blank">The Diamond Model of Intrusion Analysis</a>
        </td>
        <td>
            This paper presents the Diamond Model, a cognitive framework and analytic instrument to support and improve intrusion analysis. Supporting increased measurability, testability and repeatability
            in intrusion analysis in order to attain higher effectivity, efficiency and accuracy in defeating adversaries is one of its main contributions.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.dtic.mil/dtic/tr/fulltext/u2/a547092.pdf" target="_blank">F3EAD</a>
        </td>
        <td>
            F3EAD is a military methodology for combining operations and intelligence.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://dx.doi.org/10.6028/NIST.SP.800-150" target="_blank">Guide to Cyber Threat Information Sharing by NIST</a>
        </td>
        <td>
            The Guide to Cyber Threat Information Sharing (NIST Special Publication 800-150) assists organizations in establishing computer security incident response capabilities that leverage the collective knowledge, experience, and abilities of their partners by actively sharing threat intelligence and ongoing coordination. The guide provides guidelines for coordinated incident handling, including producing and consuming data, participating in information sharing communities, and protecting incident-related data.
        </td>
    </tr>
    <tr>
        <td>
            <a href="docs/Intelligence Preparation for the Battlefield-Battlespace.pdf" target="_blank">Intelligence Preparation of the Battlefield/Battlespace</a>
        </td>
        <td>
            This publication discusses intelligence preparation of the battlespace (IPB) as a critical component of the military decision making and planning process and how IPB supports decision making, as well as integrating processes and continuing activities.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf" target="_blank">Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains</a>
        </td>
        <td>
            The intrusion kill chain as presented in this paper provides one with a structured approach to intrusion analysis, indicator extraction and performing defensive actions.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.isao.org" target="_blank">ISAO Standards Organization</a>
        </td>
        <td>
            The ISAO Standards Organization is a non-governmental organization established on October 1, 2015. Its mission is to improve the Nation’s cybersecurity posture by identifying standards and guidelines for robust and effective information sharing related to cybersecurity risks, incidents, and best practices.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.dtic.mil/doctrine/new_pubs/jp2_0.pdf" target="_blank">Joint Publication 2-0: Joint Intelligence</a>
        </td>
        <td>
            This publication by the U.S army forms the core of joint intelligence doctrine and lays the foundation to fully integrate operations, plans and intelligence into a cohesive team. The concepts presented are applicable to (Cyber) Threat Intelligence too.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://download.microsoft.com/download/8/0/1/801358EC-2A0A-4675-A2E7-96C2E7B93E73/Framework_for_Cybersecurity_Info_Sharing.pdf" target="_blank">Microsoft Research Paper</a>
        </td>
        <td>
            A framework for cybersecurity information sharing and risk reduction. A high level overview paper by Microsoft.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://tools.ietf.org/html/draft-dulaunoy-misp-core-format-00" target="_blank">MISP Core Format (draft)</a>
        </td>
        <td>
            This document describes the MISP core format used to exchange indicators and threat information between MISP (Malware Information and threat Sharing Platform) instances.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.necoma-project.eu/" target="_blank">NECOMA Project</a>
        </td>
        <td>
            The Nippon-European Cyberdefense-Oriented Multilayer threat Analysis (NECOMA) research project is aimed at improving threat data collection and analysis to develop and demonstratie new cyberdefense mechanisms.
            As part of the project several publications and software projects have been published.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://rvasec.com/slides/2014/Bianco_Pyramid%20of%20Pain.pdf" target="_blank">Pyramid of Pain</a>
        </td>
        <td>
            The Pyramid of Pain is a graphical way to express the difficulty of obtaining different levels of indicators and the amount of resources adversaries have to expend when obtained by defenders.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.amazon.com/Structured-Analytic-Techniques-Intelligence-Analysis/dp/1452241511" target="_blank">Structured Analytic Techniques For Intelligence Analysis</a>
        </td>
        <td>
            This book contains methods that represent the most current best practices in intelligence, law enforcement, homeland security, and business analysis.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.mwrinfosecurity.com/assets/Whitepapers/Threat-Intelligence-Whitepaper.pdf" target="_blank">Threat Intelligence: Collecting, Analysing, Evaluating</a>
        </td>
        <td>
            This report by MWR InfoSecurity clearly describes several different types of threat intelligence, including strategic, tactical and operational variations. It also discusses the processes of requirements elicitation, collection, analysis, production and evaluation of threat intelligence. Also included are some quick wins and a maturity model for each of the types of threat intelligence defined by MWR InfoSecurity.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://aisel.aisnet.org/wi2017/track08/paper/3/" target="_blank">Threat Intelligence Sharing Platforms: An Exploratory Study of Software Vendors and Research Perspectives</a>
        </td>
        <td>
            A systematic study of 22 Threat Intelligence Sharing Platforms (TISP) surfacing eight key findings about the current state of threat intelligence usage, its definition and TISPs.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.us-cert.gov/tlp" target="_blank">Traffic Light Protocol</a>
        </td>
        <td>
            The Traffic Light Protocol (TLP) is a set of designations used to ensure that sensitive information is shared with the correct audience. It employs four colors to indicate different degrees of sensitivity and the corresponding sharing considerations to be applied by the recipient(s).
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://pan-unit42.github.io/playbook_viewer/" target="_blank">Unit42 Playbook Viewer</a>
        </td> 
        <td>
            The goal of the Playbook is to organize the tools, techniques, and procedures that an adversary uses into a structured format, which can be shared with others, and built upon. The frameworks used to structure and share the adversary playbooks are MITRE's ATT&CK Framework and STIX 2.0
        </td>    
    </tr>
    <tr>
        <td>
            <a href="https://www.sans.org/reading-room/whitepapers/analyst/who-039-s-cyberthreat-intelligence-how-35767" target="_blank">Who's Using Cyberthreat Intelligence and How?</a>
        </td>
        <td>
            A whitepaper by the SANS Institute describing the usage of Threat Intelligence including a survey that was performed.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.wombat-project.eu/" target="_blank">WOMBAT Project</a>
        </td>
        <td>
            The WOMBAT project aims at providing new means to understand the existing and emerging threats that are targeting the Internet economy and the net citizens. To reach this goal, the proposal includes three key workpackages: (i) real time gathering of a diverse set of security related raw data, (ii) enrichment of this input by means of various analysis techniques, and (iii) root cause identification and understanding of the phenomena under scrutiny.
        </td>
    </tr>
</table>



## License

Licensed under [Apache License 2.0](LICENSE).
