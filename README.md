# awesome-threat-intelligence
A curated list of Awesome Threat Intelligence resources

- [Sources](#sources)
- [Parsers](#parsers)
- [Standards](#standards)
- [Frameworks](#frameworks)
- [Research](#research)


## Sources

## Parsers

## Standards

<table>
  <tr>
    <td><a href="https://cyboxproject.github.io/" target="_blank">CybOX</a></td>
    <td>The Cyber Observable eXpression (CybOX) language provides a common structure for representing cyber observables across and among the operational areas of enterprise cyber security that improves the consistency, efficiency, and interoperability of deployed tools and processes, as well as increases overall situational awareness by enabling the potential for detailed automatable sharing, mapping, detection, and analysis heuristics.</td> 
  </tr>
  <tr>
    <td><a href="https://stixproject.github.io/" target="_blank">STIX</a></td>
    <td>The Structured Threat Information eXpression (STIX) language is a standardized construct to represent cyber threat information. The STIX Language intends to convey the full range of potential cyber threat information and strives to be fully expressive, flexible, extensible, and automatable. </td> 
  </tr>  
  <tr>
    <td><a href="https://taxiiproject.github.io/" target="_blank">TAXII</a></td>
    <td>The Trusted Automated eXchange of Indicator Information (TAXII) standard defines a set of services and message exchanges that, when implemented,  enable sharing of actionable cyber threat information across organization and product/service boundaries. TAXII defines concepts, protocols, and message exchanges to exchange cyber threat information for the detection, prevention, and mitigation of cyber threats.</td> 
  </tr>  
  <tr>
    <td><a href="https://maecproject.github.io/" target="_blank">MAEC</a></td>
    <td>The Malware Attribute Enumeration and Characterization (MAEC) projects is aimed at creating and providing a standardized language for sharing structured information about malware based upon attributes such as behaviors, artifacts, and attack patterns.</td> 
  </tr>
</table>

## Frameworks and Platforms

<table>
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
            <a href="http://django-mantis.readthedocs.org/en/latest/" target="_blank">MANTIS</a>
        </td>
        <td>
            The Model-based Analysis of Threat Intelligence Sources (MANTIS) Cyber Threat Intelligence Management Framework supports the management of cyber threat intelligence expressed in various standard languages, like STIX and CybOX. It is *not* ready for large-scale production though.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://csirtgadgets.org/collective-intelligence-framework" target="_blank">CIF</a>
        </td>
        <td>
            The Collective Intelligence Framework (CIF) allows you to combine known malicious threat information from many sources and use that information for IR, detection and mitigation. Code available on [GitHub](https://github.com/csirtgadgets/massive-octo-spice).
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
            <a href="http://www.openioc.org/" target="_blank">OpenIOC</a>
        </td>
        <td>
            OpenIOC is an open framework for sharing threat intelligence. It is designed to exchange threat information both internally and externally in a machine-digestible format.
        </td>
    </tr>
    <tr>
        <td>
            <a href="http://www.openioc.org/" target="_blank">OTX - Open Threat Exchange</a>
        </td>
        <td>
            AlienVault Open Threat Exchange (OTX) provides open access to a global community of threat researchers and security professionals. It delivers community-generated threat data, enables collaborative research, and automates the process of updating your security infrastructure with threat data from any source.
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
            <a href="https://developers.facebook.com/docs/threat-exchange/" target="_blank">ThreatExchange</a>
        </td>
        <td>
            Facebook created ThreatExchange so that participating organizations can share threat data using a convenient, structured, and easy-to-use API that provides privacy controls to enable sharing with only desired groups. This project is still in *beta*.
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

## Research