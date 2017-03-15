# 威胁情报大合集

最好的威胁情报资源的精选列表

威胁情报的简明定义：基于证据的知识，包括上下文、机制、指标、影响与和可行的建议，关于现有或新出现对资产的威胁或风险，可被用来告知有关威胁响应的决定

Feel free to [contribute](CONTRIBUTING.md).

- [资源](#资源)
- [格式](#格式)
- [框架与平台](#框架与平台)
- [工具](#工具)
- [研究、标准、书籍](#research)


## 资源

下面列表中提到的大多数资源/API 都是用来获得最新的威胁情报信息。
有些人不认为这些资源可以当成威胁情报。但是对基于特定域或特定业务的真实威胁情报进行分析是很必要的。
<table>
    <tr>
        <td>
            <a href="http://s3.amazonaws.com/alexa-static/top-1m.csv.zip" target="_blank">Alexa Top 1 Million sites</a>
        </td>
        <td>
            Alexa 上前一百万站点可作为白名单
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://docs.google.com/spreadsheets/u/1/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml" target="_blank">APT Groups and Operations</a>
        </td>
        <td>
            一个包含有 APT 组织信息、行动和策略的表格
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.autoshun.org/" target="_blank">AutoShun</a>
        </td>
        <td>
            提供不到两千个恶意 IP 地址和其他一些资源的公共服务
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.circl.lu/projects/bgpranking/" target="_blank">BGP Ranking</a>
        </td>
        <td>
            提供恶意内容最多的 ASN 排名
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://intel.malwaretech.com/" target="_blank">Botnet Tracker</a>
        </td>
        <td>
            对一些活跃的僵尸网络跟踪
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://danger.rulez.sk/projects/bruteforceblocker/" target="_blank">BruteForceBlocker</a>
        </td>
        <td>
            BruteForceBlocker 是一个旨在监视服务器上 sshd 日志来阻止暴力破解攻击的 perl 脚本，可以自动配置防火墙阻止规则并且提交恶意 IP 到项目地址, <a href="http://danger.rulez.sk/projects/bruteforceblocker/blist.php">http://danger.rulez.sk/projects/bruteforceblocker/blist.php</a>.
        </td>
    </tr>    
    <tr>
        <td>
            <a href="http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt" target="_blank">C&amp;C Tracker</a>
        </td>
        <td>
            Bambenek Consulting 提供的活动 C&C 服务器的 IP 地址跟踪
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://cinsscore.com/list/ci-badguys.txt" target="_blank">CI Army List</a>
        </td>
        <td>
        商业列表 <a href="http://cinsscore.com/">CINS Score</a> 的子集，聚焦于提供那些其他情报列表重没有的恶意IP地址
        </td>
    </tr>    
    <tr>
        <td>
            <a href="http://s3-us-west-1.amazonaws.com/umbrella-static/index.html" target="_blank">Cisco Umbrella</a>
        </td>
        <td>
            Cisco Umbrella 提供的其 DNS 解析前一百万站点的白名单
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://intel.criticalstack.com/" target="_blank">Critical Stack Intel</a>
        </td>
        <td>
            Critical Stack 提供的免费威胁情报解析与聚合工具，可以应用到生产系统中。也可以指定你信任的情报来源或能提取情报的来源
        </td>
    </tr>
     <tr>
        <td>
            <a href="https://www.c1fapp.com/" target="_blank">C1fApp</a>
        </td>
        <td>
            C1fApp 是一个威胁情报订阅聚合应用，提供开源订阅与私有订阅。带有统计面板、用来搜索几年内数据的开放 API
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.cymon.io/" target="_blank">Cymon</a>
        </td>
        <td>
            Cymon 是一个多源威胁情报聚合工具，享有到多个威胁情报订阅的单独接口。也提供一个漂亮的 Web 界面使用 API 来搜索数据库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://intel.deepviz.com/recap_network.php" target="_blank">Deepviz Threat Intel</a>
        </td>
        <td>
            Deepviz 提供一个用于恶意软件分析的沙盒，并且提供从沙盒中提取威胁情报的 API
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://rules.emergingthreats.net/fwrules/" target="_blank">Emerging Threats Firewall Rules</a>
        </td>
        <td>
            不同类型防火墙的规则集，包括 iptables、PF 和 PIX
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://rules.emergingthreats.net/blockrules/" target="_blank">Emerging Threats IDS Rules</a>
        </td>
        <td>
            用于报警或拦截的 Snort 和 Suricata 规则集
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://exonerator.torproject.org/" target="_blank">ExoneraTor</a>
        </td>
        <td>
            ExoneraTor 提供 Tor 网络中一部分 IP 地址的数据库，可以响应给定的 IP 地址在给定的时间是否作为 Tor 节点运行过
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.exploitalert.com/" target="_blank">Exploitalert</a>
        </td>
        <td>
            最新的 exploits 列表
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://feodotracker.abuse.ch/" target="_blank">ZeuS Tracker</a>
        </td>
        <td>
            Feodo Tracker <a href="https://www.abuse.ch/" target="_blank">abuse.ch</a> 跟踪 Feodo 木马
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://iplists.firehol.org/" target="_blank">FireHOL IP Lists</a>
        </td>
        <td>
            超过 400 个公开可用的 IP 订阅，可以用来分析其演化、地理位置、时长、保留策略、重叠，这个网站侧重于网络犯罪（攻击、滥用、恶意软件）
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://fraudguard.io/" target="_blank">FraudGuard</a>
        </td>
        <td>
            FraudGuard 提供了一个验证不断收集、分析实时网络流量的工具的服务
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://hailataxii.com/" target="_blank">Hail a TAXII</a>
        </td>
        <td>
            Hail a TAXII.com 是一个 STIX 格式的开源网络威胁情报库，包括多种不同的格式，例如 Emerging Threats rules 与 PhishTank
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.iblocklist.com/lists" target="_blank">I-Blocklist</a>
        </td>
        <td>
            I-Blocklist 维护包括 IP 地址在内的多种类型的列表，主要有国家、ISP 和组织。其他列表包括 Web 攻击、Tor、间谍软件、代理，许多都可以免费使用，并且有多种格式
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.malshare.com/" target="_blank">MalShare.com</a>
        </td>
        <td>
            MalShare 项目为研究人员提供一个公开的样本库
        </td>
    </tr>    
    <tr>
        <td>
            <a href="http://www.malwaredomains.com/" target="_blank">MalwareDomains.com</a>
        </td>
        <td>
            DNS-BH 项目创建并维护了一个传播恶意软件以及间谍软件的域名列表，可以被用来检测 DNS 请求做预防检测
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.openbl.org/lists.html" target="_blank">OpenBL.org</a>
        </td>
        <td>
            一个关于暴力破解的 IP 地址的列表，包括 SSH、FTP、IMAP 、phpMyAdmin 以及其他 Web 应用 
        </td>
    </tr>    
    <tr>
        <td>
            <a href="https://openphish.com/phishing_feeds.html" target="_blank">OpenPhish Feeds</a>
        </td>
        <td>
            OpenPhish 接收来自多个流的 URL，然后使用其专有的网络钓鱼检测算法进行检测。有免费以及商业两个版本
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.phishtank.com/developer_info.php" target="_blank">PhishTank</a>
        </td>
        <td>
            PhishTank 提供了可疑钓鱼网站的 URL，它们的数据来自各个报告的人，它们也在外部订阅中获得数据，这是一项免费服务，但有时需要 API key
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://ransomwaretracker.abuse.ch/" target="_blank">Ransomware Tracker</a>
        </td>
        <td>
            Ransomware Tracker 由 <a href="https://www.abuse.ch/" target="_blank">abuse.ch</a> 提供对与 Ransomware 有关的域名、IP、URL 状态进行跟踪与监视
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://isc.sans.edu/suspicious_domains.html" target="_blank">SANS ICS Suspicious Domains</a>
        </td>
        <td>
            Suspicious Domains Threat 由 <a href="https://isc.sans.edu/suspicious_domains.html" target="_blank">SANS ICS</a> 提供对恶意域名的跟踪，提供三个列表分为 <a href="https://isc.sans.edu/feeds/suspiciousdomains_High.txt" target="_blank">高</a>, <a href="https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt" target="_blank">中</a> or <a href="https://isc.sans.edu/feeds/suspiciousdomains_Low.txt" target="_blank">低</a> 三个层级，高级名单的错报低，低级名单的错报高。还有一个域名的 <a href="https://isc.sans.edu/feeds/suspiciousdomains_whitelist_approved.txt" target="_blank">白名单</a><br/>
            另外，也有黑名单 <a href="https://isc.sans.edu/block.txt" target="_blank">IP blocklist</a> 由 <a href="https://dshield.org">DShield</a> 提供
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Neo23x0/signature-base" target="_blank">signature-base</a>
        </td>
        <td>
            在其他工具中使用的签名数据库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.spamhaus.org/" target="_blank">The Spamhaus project</a>
        </td>
        <td>
            Spamhaus 项目包含包括垃圾邮件以及恶意软件活动在内的多种威胁情报
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://sslbl.abuse.ch/" target="_blank">SSL Blacklist</a>
        </td>
        <td>
                SSL Blacklist (SSLBL) 是由 abuse.ch 维护的项目，旨在提供一个与恶意软件、僵尸网络活动有关的不良 SSL 证书列表。SSLBL 提供恶意 SSL 证书的 SHA1 指纹，并且提供多种黑名单
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://statvoo.com/dl/top-1million-sites.csv.zip" target="_blank">Statvoo Top 1 Million Sites</a>
        </td>
        <td>
            Statvoo 排名的前一百万站点，可作为白名单
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://strongarm.io" target="_blank">Strongarm, by Percipient Networks</a>
        </td>
        <td>
            Strongarm 是一个 DNS 黑洞，旨在提供阻止恶意软件 C&C 的 IOC 信息，其聚合了许多免费的订阅源，并与商业订阅集成，利用 Percipient 的 IOC 订阅，利用 DNS 解析与 API 来保护你的网络与企业。Strongarm 对个人使用是免费的
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.talosintelligence.com/aspis/" target="_blank">Talos Aspis</a>
        </td>
        <td>
            Aspis 是一个 Talos 和主机提供商的封闭合作项目，用来识别与阻止主要威胁。Talos 与主机提供商共享其专业知识、资源与能力，包括网络与系统取证、逆向工程与威胁情报
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.threatglass.com/" target="_blank">Threatglass</a>
        </td>
        <td>
            一个用于共享、浏览、与分析基于网络的恶意软件的在线工具，Threatglass 允许用户通过浏览器来查看恶意软件在感染阶段的屏幕截图以及网络特性的分析（包括主机关系与数据包捕获）
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.threatminer.org/" target="_blank">ThreatMiner</a>
        </td>
        <td>
            ThreatMiner 为分析师从数据收集到执行分析提供了一个门户，ThreatMiner 关注的重点不仅仅是关于 IOC，还为分析人员提供有关 IOC 的上下文信息
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://virusshare.com/" target="_blank">VirusShare</a>
        </td>
        <td>
            VirusShare.com 是一个为安全研究员、事件响应人员、取证分析人员提供恶意样本的仓库，其中也含有很多恶意样本的代码，网站只能通过邀请得到访问授权
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Yara-Rules/rules" target="_blank">Yara-Rules</a>
        </td>
        <td>
            收集不同 Yara 规则的开源库，经过分类并尽量保持时效性
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://zeustracker.abuse.ch/" target="_blank">ZeuS Tracker</a>
        </td>
        <td>
            ZeuS Tracker 由 <a href="https://www.abuse.ch/" target="_blank">abuse.ch</a> 提供对 ZeuS 的 C&C 主机的跟踪，提供给你域名与主机的黑名单
        </td>
    </tr>
</table>

## 格式

用于分享的威胁情报标准化格式

<table>
    <tr>
        <td>
            <a href="https://capec.mitre.org/" target="_blank">CAPEC</a>
        </td>
        <td>
            Common Attack Pattern Enumeration and Classification (CAPEC) 是一个综合性的术语大全以及对已知攻击的分类，可以被分析、开发、测试以及教育工作者使用，推动社会的重视并且增加网络防御能力
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
            <a href="https://stixproject.github.io/" target="_blank">STIX</a>
        </td>
        <td>
            The Structured Threat Information eXpression (STIX) language is a standardized construct to represent cyber threat information. The STIX Language intends to convey the full range of potential cyber threat information and strives to be fully expressive, flexible, extensible, and automatable. STIX does not only allow tool-agnostic fields, but also provides so-called <i>test mechanisms</i> that provide means for embedding tool-specific elements, including OpenIOC, Yara and Snort.
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
            The Vocabulary for Event Recording and Incident Sharing (VERIS) is a set of metrics designed to provide a common language for describing security incidents in a structured and repeatable manner. VERIS is a response to one of the most critical and persistent challenges in the security industry - a lack of quality information. In addition to providing a structuref format, VERIS also collects data from the community to report on breaches in the Verizon Data Breach Investigations Report (<a target="_blank" href="http://www.verizonenterprise.com/verizon-insights-lab/dbir/">DBIR</a>) and publishes this database online at <a target="_blank" href="http://vcdb.org/index.html">VCDB.org</a>.
        </td>
    </tr>
</table>

## 框架与平台

收集、分析、构建、分享威胁情报的框架、平台与服务

<table>
    <tr>
        <td>
            <a href="https://github.com/abusesa/abusehelper" target="_blank">AbuseHelper</a>
        </td>
        <td>
            AbuseHelper 是一个用来接收与重分配威胁情报订阅的开源框架
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
            CIF 的接替者，最快处理威胁情报的方式
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://community.blueliv.com/" target="_blank">Blueliv Threat Exchange Network</a>
        </td>
        <td>
            允许社区的参与者共享威胁情报信息
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
            Collective Intelligence Framework (CIF) 允许你将已知的多源恶意威胁信息联结起来，可以用于 IR、检测与缓解，代码在 <a href="https://github.com/csirtgadgets/massive-octo-spice" target="_blank">GitHub</a> 上可用
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
            <a href="https://technet.microsoft.com/en-us/security/dn750892" target="_blank">Interflow</a>
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
            <a href="https://github.com/byt3smith/malstrom" target="_blank">Malstrom</a>
        </td>
        <td>
            Malstrom 的目的是来跟踪与取证的神器，还包括 YARA 的规则库与一些调查的笔记
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
            Malware Information Sharing Platform (MISP) 是一个收集、存储、分发和分享网络安全指标和恶意软件分析信息的开源软件解决方案
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.openioc.org/" target="_blank">OpenIOC</a>
        </td>
        <td>
            OpenIOC 是一个开放的共享威胁情报的框架，它的目的是用计读的格式互通内部与外部的威胁情报信息
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/EclecticIQ/OpenTAXII" target="_blank">OpenTAXII</a>
        </td>
        <td>
            OpenTAXII 是 TAXII 的一个 Python 实现，提供了一系列丰富的功能与友好的 Python API
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Ptr32Void/OSTrICa" target="_blank">OSTrICa</a>
        </td>
        <td>
            一个开源的插件化框架来对威胁情报的收集与可视化
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.alienvault.com/open-threat-exchange" target="_blank">OTX - Open Threat Exchange</a>
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
            <a href="https://www.passivetotal.org/" target="_blank">PassiveTotal</a>
        </td>
        <td>
            The PassiveTotal platform offered by RiskIQ is a threat-analysis platform which provides analysts with as much data as possible in order to prevent attacks before they happen. Several types of solutions are offered, as well as integrations (APIs) with other systems.
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
            <a href="https://soltra.com/" target="_blank">Soltra Edge</a>
        </td>
        <td>
            Soltra Edge 的免费版本，支持扩展社区防御模型。扩展性好，操作性交互度很高，基于开箱即用的行业标准，包括 STIX 和 TAXII
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.anomali.com/product/staxx" target="_blank">STAXX (Anomali)</a>
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
            Threat Analysis, Reconnaissance, and Data Intelligence System (TARDIS) 是一个使用攻击签名执行历史搜索的开源框架
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.threatcrowd.org/" target="_blank">ThreatCrowd</a>
        </td>
        <td>
            ThreatCrowd 是一个发现和研究有关网络威胁的系统
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
            <a href="https://github.com/defpoint/threat_Note" target="_blank">Threat_Note</a>
        </td>
        <td>
            DPS 的轻量级调查笔记本
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://exchange.xforce.ibmcloud.com/" target="_blank">XFE - X-Force Exchange</a>
        </td>
        <td>
            The X-Force Exhange (XFE) by IBM XFE is a free SaaS product that you can use to search for threat intelligence information, collect your findings, and share your insights with other members of the XFE community.
        </td>
    </tr>
</table>



## 工具

用户创建、解析、编辑威胁情报的各种工具，大多数基于 IOC

<table>
    <tr>
        <td>
            <a href="http://actortrackr.com/" target="_blank">ActorTrackr</a>
        </td>
        <td>
            ActorTrackr 是一个用来存储/搜索/链接事件相关数据的开源 Web 应用程序。主要来源是用户以及各种公共资料库，也有一些来自  <a href="https://github.com/dougiep16/actortrackr" target="_blank">GitHub</a>
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://bitbucket.org/camp0/aiengine" target="_blank">AIEngine</a>
        </td>
        <td>
            AIEngine 是下一代交互式支持 Python/Ruby/Java/Lua 编程的包检测引擎，无需任何人工干预，具有 NIDS 的功能、DNS 域名分类、网络流量收集、网络取证等许多功能，源码在<a href="https://bitbucket.org/camp0/aiengine" target="_blank">Bitbucket</a>
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/1aN0rmus/TekDefense-Automater" target="_blank">Automater</a>
        </td>
        <td>
            Automater 是一个集合 URL/Domain、IP Address 和 Md5 的 OSINT 工具，旨在让入侵分析变得更轻松
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://cse.google.com/cse/publicurl?cx=003248445720253387346:turlh5vi4xc" target="_blank">Google APT Search Engine</a>
        </td>
        <td>
            APT 组织与恶意软件搜索引擎，用于此 Google 自定义搜索的来源列表在 <a href="https://gist.github.com/Neo23x0/c4f40629342769ad0a8f3980942e21d3" target="_blank"this</a> GitHub 中
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/exp0se/bro-intel-generator" target="_blank">bro-intel-generator</a>
        </td>
        <td>
            从 PDF 或 HTML 报告中提取信息生成 Bro intel 文件的脚本
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/EclecticIQ/cabby" target="_blank">cabby</a>
        </td>
        <td>
            一个用来和 TAXII 服务器进行交互的简单 Python 库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/sroberts/cacador" target="_blank">cacador</a>
        </td>
        <td>
            Cacador 是一个使用 Go 编写的工具，用来从一段文本中提取常见的威胁情报指标
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mlsecproject/combine" target="_blank">Combine</a>
        </td>
        <td>
            Combine 聚合了多个公开源的威胁情报
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/CrowdStrike/CrowdFMS" target="_blank">CrowdFMS</a>
        </td>
        <td>
            CrowdFMS 是一个利用私有 API 来自动收集与处理来自 VirusTotal 的样本的框架，该框架会自动下载最近的样本，从而触发 YARA 提醒订阅的警报
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Neo23x0/Fenrir" target="_blank">Fenrir</a>
        </td>
        <td>
            简单的 Bash IOC 扫描器
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/byt3smith/Forager" target="_blank">Forager</a>
        </td>
        <td>
            多线程威胁情报收集脚本
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/BinaryDefense/goatrider" target="_blank">GoatRider</a>
        </td>
        <td>
            GoatRider 会动态拉取 Artillery Threat Intelligence 订阅数据、TOR、AlienVaults OTX 以及 Alexa top 1 million websites 与给定的主机名或 IP 进行比较
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/exp0se/harbinger" target="_blank">Harbinger Threat Intelligence</a>
        </td>
        <td>
            从单一接口查询多个在线威胁情报聚合服务的 Python 脚本
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/S03D4-164/Hiryu" target="_blank">Hiryu</a>
        </td>
        <td>
            一个用来组织 APT 组织信息的工具，并提供 IOC 之间关系的可视化展示
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.fireeye.com/services/freeware/ioc-editor.html" target="_blank">IOC Editor</a>
        </td>
        <td>
            一个免费的 Indicators of Compromise (IOCs) 编辑器
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/armbues/ioc_parser" target="_blank">ioc_parser</a>
        </td>
        <td>
            从 PDF 格式的安全报告中提取 IOC 的工具
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mandiant/ioc_writer" target="_blank">ioc_writer</a>
        </td>
        <td>
            一个可以创建/编辑基本 OpenIOC 对象的 Python 库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/stephenbrannon/IOCextractor" target="_blank">IOCextractor</a>
        </td>
        <td>
            IOC (Indicator of Compromise) Extractor 是一个帮助从文本文件中提取 IOC 的程序，旨在加速从非结构化数据/半结构化数据中提取结构化数据的过程
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/johestephan/ibmxforceex.checker.py" target="_blank">ibmxforceex.checker.py</a>
        </td>
        <td>
            IBM X-Force Exchange 的 Python 客户端
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/sroberts/jager" target="_blank">jager</a>
        </td>
        <td>
            Jager 是一个从各种数据源（现在已支持 PDF，很快支持纯文本，最终会支持网页）提取有用的 IOC 并将其变成易于操作的 JSON 格式的工具
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/TAXIIProject/libtaxii" target="_blank">libtaxii</a>
        </td>
        <td>
            可以调用 TAXII 服务处理 TAXII 信息的 Python 库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Neo23x0/Loki" target="_blank">Loki</a>
        </td>
        <td>
            简单的 IOC 与事件响应扫描器
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://bitbucket.org/ssanthosh243/ip-lookup-docker" target="_blank">LookUp</a>
        </td>
        <td>
            LookUp 是一个有关 IP 地址的各种威胁信息的聚合页面，可以轻松的被集成到工具的上下文菜单中，如 SIEM 或其他调查工具
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/HurricaneLabs/machinae" target="_blank">Machinae</a>
        </td>
        <td>
            Machinae 是一个用于从公开站点/订阅源收集各种与安全相关数据的工具，包括 IP 地址、域名、URL、电子邮件地址、文件哈希值与 SSL 指纹
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/MISP/misp-workbench" target="_blank">MISP Workbench</a>
        </td>
        <td>
            将 MISP 的 MySQL 数据库导出，使之可以在外部应用
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/MISP/MISP-Taxii-Server" target="_blank">MISP-Taxii-Server</a>
        </td>
        <td>
            一组用于使用 EclecticIQ 的 OpenTAXII 实例的配置文件，当数据送达 TAXII 服务器的收件箱时带有回调
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/paulpc/nyx" target="_blank">nyx</a>
        </td>
        <td>
            该项目的目标是促进威胁情报分发到防御系统中，并增强从开源和商业工具中获得的价值
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/STIXProject/openioc-to-stix" target="_blank">openioc-to-stix</a>
        </td>
        <td>
            转换 STIX XML 为 OpenIOC XML
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/kx499/ostip/wiki" target="_blank">OSTIP</a>
        </td>
        <td>
            自制的威胁数据平台
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mgeide/poortego" target="_blank">poortego</a>
        </td>
        <td>
            用于处理/链接开源威胁情报的开源 Ruby 项目
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/yahoo/PyIOCe" target="_blank">PyIOCe</a>
        </td>
        <td>
            PyIOCe 是一个使用 Python 编写的 IOC 编辑器
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/QTek/QRadio" target="_blank">QRadio</a>
        </td>
        <td>
            QRadio 是一个旨在巩固网络威胁情报源的工具/框架，该项目试图建立一个强大的框架来审查提取得到的威胁情报数据
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/aboutsecurity/rastrea2r" target="_blank">rastrea2r</a>
        </td>
        <td>
            收集与整理 Indicators of Compromise (IOC)
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.fireeye.com/services/freeware/redline.html" target="_blank">Redline</a>
        </td>
        <td>
            主机调查工具，分析其可用于 ICO 分析的数据
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/ocmdev/rita" target="_blank">RITA</a>
        </td>
        <td>
            Real Intelligence Threat Analytics (RITA) 旨在帮助不同规模的企业在网络中搜索 IOC
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/STIXProject/stix-viz" target="_blank">stix-viz</a>
        </td>
        <td>
            STIX 可视化工具
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://test.taxiistand.com/" target="_blank">TAXII Test Server</a>
        </td>
        <td>
            允许你通过连接给定的服务并执行 TAXII 给定的各种功能来测试你的 TAXII 环境
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/jpsenior/threataggregator" target="_blank">threataggregator</a>
        </td>
        <td>
            ThreatAggregrator 聚合了许多在线的威胁情报源，支持输出到各种格式，包括 CEF、Snort 和 iptables 的规则
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/jheise/threatcrowd_api" target="_blank">threatcrowd_api</a>
        </td>
        <td>
            使用 ThreatCrowd API 的 Python 库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/jheise/threatcmd" target="_blank">threatcmd</a>
        </td>
        <td>
            ThreatCrowd 的命令行接口
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/syphon1c/Threatelligence" target="_blank">Threatelligence</a>
        </td>
        <td>
            Threatelligence 是一个简单的威胁情报订阅收集器，使用 Elasticsearch、Kibana 和 Python 来自动收集自定义或开源的情报，自动跟踪数据更新，但是项目似乎以及放弃更新了
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://chrome.google.com/webstore/detail/threatpinch-lookup/ljdgplocfnmnofbhpkjclbefmjoikgke" target="_blank">ThreatPinch Lookup</a>
        </td>
        <td>
            一个用于在每个页面查找 IPv4、MD5、SHA2 以及 CVEs 的 Chrome 扩展程序
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.fidelissecurity.com/resources/fidelis-threatscanner" target="_blank">ThreatScanner</a>
        </td>
        <td>
            Fidelis Cybersecurity 开发的 ThreatScanner 在本地运行一个搜索 IOC 或 YARA 规则的脚本，并自动生成可疑信息的报告
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/michael-yip/ThreatTracker" target="_blank">ThreatTracker</a>
        </td>
        <td>
            用于监控并生成一组由 Google 自定义搜索引擎得出的 IOC 数据集
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/Yelp/threat_intel" target="_blank">threat_intel</a>
        </td>
        <td>
            多个威胁情报的 API 聚合在一个包中，其中包括 OpenDNS Investigate、VirusTotal 和 ShadowServer
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/abhinavbom/Threat-Intelligence-Hunter" target="_blank">Threat-Intelligence-Hunter</a>
        </td>
        <td>
            TIH 是一个可以帮助你在多个可公开提取的安全订阅源与知名 API 中提取 IOC 的智能工具，创建这个工具的初衷就是为了方便搜索、存储 IOC，以方便你创建自己的本地数据库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/mlsecproject/tiq-test" target="_blank">tiq-test</a>
        </td>
        <td>
            Threat Intelligence Quotient (TIQ) 测试工具提供对威胁情报的可视化与统计分析
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/TAXIIProject/yeti" target="_blank">YETI</a>
        </td>
        <td>
            YETI 是一个 TAXII 的概念验证，带有收件箱、轮询和 TAXII 的特定服务支持
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/tomchop/yeti" target="_blank">yeti</a>
        </td>
        <td>
            Your Everyday Threat Intelligence (YETI) 每日威胁情报
        </td>
    </tr>
</table>



## <a name="research"></a> 研究、标准、书籍

威胁情报的各种材料，包括研究与白皮书

<table>
    <tr>
        <td>
            <a href="https://github.com/gasgas4/APT_CyberCriminal_Campaign" target="_blank">APT & Cyber Criminal Campaign Collection</a>
        </td>
        <td>
            广泛收集各种组织信息，来源多样
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://github.com/kbandla/APTnotes" target="_blank">APTnotes</a>
        </td>
        <td>
            关于 APT 的信息收集，通常包括战略、战术知识或建议
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://attack.mitre.org/index.php/Main_Page" target="_blank">ATT&CK</a>
        </td>
        <td>
            Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK™) 是用于描述攻击者在企业内网可能采取行动的一个模型与框架。ATT&CK 对于 post-access 是一个持续进步的共同参考，其可以在网络入侵中意识到什么行动最可能发生。MITRE 正在积极致力于相关信息的构建，就像 CAPEC、STIX 和 MAEC
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.activeresponse.org/building-threat-hunting-strategy-with-the-diamond-model/" target="_blank">Building Threat Hunting Strategies with the Diamond Model</a>
        </td>
        <td>
            Sergio Caltagirone 的博客：如何利用钻石模型开发威胁情报战略
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://car.mitre.org/wiki/Main_Page" target="_blank">Cyber Analytics Repository by MITRE</a>
        </td>
        <td>
            Cyber Analytics Repository (CAR) 是 MITRE 基于 ATT&CK™ 开发的知识库
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://cryptome.org/2015/09/cti-guide.pdf" target="_blank">Definitive Guide to Cyber Threat Intelligence</a>
        </td>
        <td>
            Describes the elements of cyber threat intelligence and discusses how it is collected, analyzed, and used by a variety of human and technology consumers.Fruther examines how intelligence can improve cybersecurity at tactical, operational, and strategic levels, and how it can help you stop attacks sooner, improve your defenses, and talk more productively about cybersecurity issues with executive management in typical <i>for Dummies</i> style.
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
            This paper presents the Diamond Model, a cognitive framework and analytic instrument to support and improve intrusion analysis. Supporint increased measurability, testability and repeatability
            in intrusion analysis in order to attain higher effectivity, efficiency and accuracy in defeating adversaries is one of its main contributions.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.dtic.mil/dtic/tr/fulltext/u2/a547092.pdf" target="_blank">F3EAD</a>
        </td>
        <td>
            F3EAD 是一个将行动与情报相结合的军事方法
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
            探讨了 intelligence preparation of the battlespace (IPB) 战场的情报准备，讲述了 IPB 作为军事决策与规划的一个重要组成部分是如何支持决策以及整合流程
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.lockheedmartin.com/content/dam/lockheed/data/corporate/documents/LM-White-Paper-Intel-Driven-Defense.pdf" target="_blank">Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains</a>
        </td>
        <td>
            此文提出的入侵杀伤链为入侵分析、指标提取与执行防御行动提供了一种结构化的方法
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
            网络安全信息共享与风险降低的框架，微软高级概述文档
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://tools.ietf.org/html/draft-dulaunoy-misp-core-format-00" target="_blank">MISP Core Format (draft)</a>
        </td>
        <td>
            文档主要介绍了在 MISP 实例间进行指标与威胁情报交换的核心格式
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
            这本书包含了代表威胁情报、法律执行、国土安全以及商业分析最佳实践的方法
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.ncsc.gov.uk/content/files/protected_files/guidance_files/MWR_Threat_Intelligence_whitepaper-2015.pdf" target="_blank">Threat Intelligence: Collecting, Analysing, Evaluating</a>
        </td>
        <td>
            This report by MWR InfoSecurity clearly describes several diffent types of threat intelligence, including strategic, tactical and operational variations. It also discusses the processes of requirements elicitation, collection, analysis, production and evaluation of threat intelligence. Also included are some quick wins and a maturity model for each of the types of threat intelligence defined by MWR InfoSecurity.
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.us-cert.gov/tlp" target="_blank">Traffic Light Protocol</a>
        </td>
        <td>
            Traffic Light Protocol (TLP) 是一组用来确保敏感信息可以被正确发布接收的信号组合。其使用四种颜色来标定不同程度的敏感信息和与其敏感程度相适应的接收人
        </td>
    </tr>
    <tr>
        <td>
            <a href="https://www.sans.org/reading-room/whitepapers/analyst/who-039-s-cyberthreat-intelligence-how-35767" target="_blank">Who's Using Cyberthreat Intelligence and How?</a>
        </td>
        <td>
            由 SANS 研究所出品，描述包括策略执行在内的威胁情报使用情况的白皮书
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



## 许可证

Licensed under [Apache License 2.0](LICENSE).
