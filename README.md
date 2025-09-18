![](https://github.com/SkippyTheMeh370/Correlate-STIG/blob/main/assets/Correlate-STIG-banner.png?raw=true)
A basic Javascript/HTML app that provides a means to correlate DISA STIG rules with NIST 800-53 security controls. 
- This tool was created to assist in easily identifying applicable DISA STIG rules based on a specified security control baseline.

## Features
- Upload multiple STIG checklists (max 20).
- Correlation results can be examined futher in color-coded tables.
  - Click a rule to expand its details.
- Create custom CKLB files for use in STIG-Viewer 3+/STIG-Manager.
  - These files will have rules determined to be **not applicable**, marked respectively.
  - A custom remark can be provided that will be applied to the finding detail for each rule marked **not applicable**.
  - A CSV containing information for multiple hosts can also be provided identifying each host to create a checklist for.  
    - **CSV header**:  
          hostname,domain,ipAddress,macAddress,targetRemarks,role,NonComputing,TechnologyArea,webDBasset,webDBsite,webDBInstance  
    - **EXAMPLE CSV**:  
          hostname,domain,ipAddress,macAddress,targetRemarks,role,NonComputing,TechnologyArea,webDBasset,webDBsite,webDBInstance
          host-01,test.net,10.1.1.1,aa:bb:cc:dd:11:22,test host number one,Workstation,Windows OS,Computing,false,,,
          server1-site1-instance1,test.net,192.168.45.6,aa:bb:cc:22:33:77,test server number one,Member Server,UNIX OS,Computing,true,site1,instance1
          host2,text.net,10.1.1.5,aa:bb:cc:44:77:22,,None,Workstation,Non-Computing,false,,,

## Instructions
- Clone the repo.
- Open the 'index.html' in a chromium-based web-browser.
- Begin by selecting the preferrable NIST 800-53 revision.
  - Currently, the app supports revisions 4 & 5.

## Required files
#### Security Controls CSV
- This file should list each security control on a seperate line  
  - **CSV header**:  
    Control  
  - **EXAMPLE CSV**:  
    Control  
    AC-1  
    CM-7(2)  
    IA-5(14)  

#### DISA CCI List
- The DISA CCI list is provided on the public DISA Cyber Exchange from the SRGs/STIGs Document Library.
- This list provides a standard identifier and description for each of the singular, actionable statements that comprise a security control or IA best practice. This identifier is what connects a STIG rule to one or more security controls, based on the revision of the NIST 800-53.

#### STIG XCCDF files
- These files are XML files that utilize the Extensible Configuration Checklist Description Format.
- STIGs are located on the public DISA Cyber Exchange either from the SRGs/STIGs -> SRG / STIG Library Compilations (bulk download) or singularly from the SRGs/STIGs Document Library.
  - Once a STIG is downloaded, the XML will need to be extracted from the **Manual_STIG** directory.

## Layout
![](https://github.com/SkippyTheMeh370/Correlate-STIG/blob/main/assets/correlate-stig.png?raw=true)
