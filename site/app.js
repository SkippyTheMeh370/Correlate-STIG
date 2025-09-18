// Written By: Chris Roberts
// Date: 17 SEP 2025

//////////////////////
// GLOBAL VARIABLES //
//////////////////////
const correlatedMasterObject = {stigs: []};
//// FILE UPLOADS ////
let logConsoleSize = 1;
//// ACAS AUDITS ////
let acasAudits = {};
//// STIG CHECKLISTS ////
const stigChecklistHostInfoObject = [];

//////////////////
// FILE UPLOADS //
//////////////////
//// EVENT LISTENERS
//// Ensure that the HTML document has completely loaded before executing any event listeners
document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('input[name="version"]').forEach(radio => {
                radio.addEventListener('change', (event) => {
                        correlatedMasterObject.selectedNistRevision = event.target.value;
                        document.getElementById('controlCsvUploadContainer').classList.add("displayFlex");
                        updateInformationElement();
                });
        });
        document.getElementById('securityControlListUpload').addEventListener('change', (event) =>  {
                document.getElementById('cciListUploadContainer').classList.add("displayFlex");
                processSingleFileUpload(event);
        });
        document.getElementById('cciListUpload').addEventListener('change', (event) =>  {
                document.getElementById('stigXccdfUploadsContainer').classList.add("displayFlex");
                processSingleFileUpload(event);
        });
        document.getElementById('stigXccdfUpload').addEventListener('change', event => {
                dataReset();
                processBulkFileUploads(event, event.target.id);
        });
        document.addEventListener('click', (event) => {
                const summary = event.target.closest('summary');
                if (summary) {
                        const detailElement = summary.closest('details');
                        const summaryContent = detailElement.querySelector('summary + *');
                        event.preventDefault();
                        if (!summary) {return};
                        if (!detailElement) {return};
                        if (!summaryContent) {return};
                        if (detailElement.open) {
                                const height = summaryContent.offsetHeight;
                                const closingAnimation = summaryContent.animate(
                                        [{height: `${height}px`, opacity: 1}, {height: '0px', opacity: 0}],
                                        {duration: 400, easing: 'ease-in'}
                                );
                                closingAnimation.onfinish = () => {detailElement.removeAttribute('open')};
                        } else {
                                detailElement.setAttribute('open', '');
                                const height = summaryContent.offsetHeight;
                                summaryContent.animate(
                                        [{height: '0px', opacity: 0 }, { height: `${height}px`, opacity: 1}],
                                        {duration: 400, easing: 'ease-out'}
                                );
                        };
                }
        });
});
function dataReset() {
        ////PROGRESS BAR
        document.getElementById("correlationProgressBar").backgroundColor = "#1f2124";
        document.getElementById("correlationProgressBarFill").style.transition = "width 0ms";
        document.getElementById("correlationProgressBarFill").style.width = "1%";
        document.getElementById("correlationProgressBarText").innerHTML = "";
        ////LOGCONSOLE
        logConsoleSize = 1;
        document.getElementById("logConsole").innerHTML = '';
        ////RESULTS TABLE
        document.getElementById("resultsTableContainer").innerHTML = '';
}
function processSingleFileUpload(event) {
        const file = event.target.files[0];
        const reader = new FileReader();
        reader.onload = function(e) {
                const content = e.target.result;
                if (event.target.id === 'cciListUpload') {
                        processCCIList(content);
                } else if (event.target.id === 'securityControlListUpload') {
                        processSecurityControlList(content);
                };
        };
        reader.readAsText(file);
};
function processBulkFileUploads(event, uploadElement) {
        const uploadData = document.getElementById(`${uploadElement}`);
        const uploadDataLength = uploadData.files.length;
        for (let i = 0; i < uploadDataLength; i++) {
                const file = uploadData.files[i];
                const fileName = file.name;
                const reader = new FileReader();
                reader.onload = function(e) {
                        const content = e.target.result;
                        if (event.target.id === 'stigXccdfUpload') {
                                processSTIGxccdf(fileName, content, uploadDataLength);
                        } else if (event.target.id === 'acasAuditsUpload') {
                                processAcasAuditUploads(content, uploadDataLength);
                        };
                };
                reader.readAsText(file);
        };
};
/////////////////////
// DATA MANAGEMENT //
/////////////////////
// Pad a sting with a character to a specified length
function padDigit(num, targetLength, padCharacter) {
        return num.replace(/\d+/g, (match) => match.padStart(targetLength, padCharacter));
};
// Filter STIG Titles
function filterStigString(stigString) {
        const titleStringFilterObject = {
                'MS': '',
                'Microsoft': '',
                '/^Win$/': 'Windows',
                'DISA STIG for': '',
                'DISA': '',
                'STIG.': '',
                'STIG ': '',
                '/^U_/': '',
                'Security Technical Implementation Guide': '',
                '-0': '',
                'Current': '',
                '.Net': 'DotNet',
                'Dot Net': 'DotNet',
                'Continuous': '',
                'IE': 'Internet Explorer',
                'Edge': 'Microsoft Edge',
                'MOZ': 'Mozilla',
                '/^.*\sDISA/': '',
                '.': '',
                '#': '',
                '  ':' ',
                'description : This audit is designed against the': '',
                '_Manual-xccdf.xml': ''
        }
        Object.entries(titleStringFilterObject).forEach(([oldValue, newValue]) => {
                stigString = stigString.includes(oldValue) ? stigString.replace(oldValue, newValue) : stigString
        });
        return stigString.trim();
};
// Split a string to an object as keys
function splitToObject(string, delimeter, value) {
        const array = string.split(delimeter);
        const newObject = {};
        array.forEach(word => {
                newObject[word] = value;
        });
        return newObject;
};
////////////////////////////
// SECURITY CONTROLS FILE //
////////////////////////////
function processSecurityControlList(content) {
        const securityControlObject = {};
        const securityControlsListCsvHeader = content.split("\n")[0];
        const validCsvHeader = "Control";
        // Verify CSV header
        if (securityControlsListCsvHeader.localeCompare(validCsvHeader) === 1) {
                // Create an array of the provide security controls.
                const securityControlsArray = content.split('\n');
                // Remove the first index of the array (the header), leaving just the controls.
                securityControlsArray.shift();
                securityControlsArray.forEach(securityControl => {
                        // Pad any digits < 9 with a zero, if necessary, to comply with NIST 800-53 r5 update on November 7, 2023
                        let updatedSecurityControl = (padDigit(securityControl, 2, "0").trim()).replace(" ","");
                        if (updatedSecurityControl[5] === "(") {
                                updatedSecurityControl = updatedSecurityControl.slice(0, 5) + " " + updatedSecurityControl.slice(5)
                        }
                        // Push the updated security control to the array
                        securityControlObject[updatedSecurityControl] = [];
                });
                // Append the array of security controls to the master object for later reference
                correlatedMasterObject.securityControls = securityControlObject;
                updateInformationElement();
        } else {
                console.log("Error processing security control list CSV file.");
                alert("Not a valid security control list csv file...");
        };
};

///////////////////
// DISA CCI LIST //
///////////////////
function processCCIList(content) {
        try {
                // Update securtiy control to only reference the control or the enhancement, but nothing else.
                function updateControl(rawControl) {
                        let paddedControl = padDigit(rawControl, 2, "0");
                        if (paddedControl.indexOf(")") > 0 && paddedControl.indexOf(")") < 10) {
                                paddedControl = paddedControl.split(")")[0] + ")"
                        } else if (paddedControl.indexOf(" ") > 0) {
                                paddedControl = paddedControl.split(" ")[0]
                        };
                        return paddedControl
                };
                // Internal collector object
                const cciObject = {};
                const selectedNistRevision = correlatedMasterObject.selectedNistRevision;
                const applicableControls = Object.keys(correlatedMasterObject.securityControls);
                // Gather data from DISA CCI list xml.
                const parser = new DOMParser();
                const xmlDoc = parser.parseFromString(content, "text/xml");
                const cciListVersion = xmlDoc.querySelector('cci_list > metadata > version').textContent;
                const cciItems = xmlDoc.querySelectorAll('cci_list > cci_items > cci_item');
                // Iterate through data and send relevant to object.
                cciItems.forEach(item => {
                        const cciId = item.getAttribute('id');
                        let refCount = 1;
                        cciObject[cciId] = {
                                applicable: false,
                                contributor: item.querySelector('contributor').textContent,
                                definition: item.querySelector('definition').textContent,
                                publish_date: item.querySelector('publishdate').textContent,
                                references: {},
                                status: item.querySelector('status').textContent,
                                type: item.querySelector('type').textContent
                        };
                        // Iterate through CCI references
                        const cciReferences = item.querySelectorAll(`references > reference`);
                        if (cciReferences.length > 0) {
                                cciReferences.forEach(reference => {
                                        const cciReferenceVersion = reference.getAttribute('version');
                                        const cciReferenceControl = updateControl(reference.getAttribute('index'));
                                        const cciReferenceCreator = reference.getAttribute('creator');
                                        // Identify only references that are created by NIST and have a version of 4 or higher.
                                        // Send relevant data to internal collector object.
                                        if (Number(cciReferenceVersion) >= 4 && cciReferenceCreator === "NIST") {
                                                cciObject[cciId].references[refCount] = {
                                                        creator: cciReferenceCreator,
                                                        index: reference.getAttribute('index'),
                                                        location: reference.getAttribute('location'),
                                                        updatedIndex: cciReferenceControl,
                                                        version: cciReferenceVersion
                                                };
                                                // Determine if the CCI contains a reference for the selected NIST 800-53 revision, and if so,
                                                // then determine if that reference identifies a security control from the provided list.
                                                if (cciReferenceVersion === selectedNistRevision) {
                                                        if (applicableControls.includes(cciReferenceControl)) {
                                                                // This CCI references the selected NIST 800-53 revision and the provided control list contains the referenced control.
                                                                const refRuling = 2;
                                                                correlatedMasterObject.securityControls[cciReferenceControl].push(cciId);
                                                                cciObject[cciId].applicable = true;
                                                                cciObject[cciId].references[refCount].ruling = refRuling;
                                                                refCount += 1;
                                                        } else if (!applicableControls.includes(cciReferenceControl)) {
                                                                // This CCI references the selected NIST 800-53 revision, however, the provided control list does not contain the referenced control.
                                                                const refRuling = 1;
                                                                cciObject[cciId].references[refCount].ruling = refRuling;
                                                                refCount += 1;
                                                        };
                                                } else {
                                                        // // This CCI does not reference the selected NIST 800-53 revision.
                                                        const refRuling = 0;
                                                        cciObject[cciId].references[refCount].ruling = refRuling;
                                                        refCount += 1;
                                                };
                                        };
                                });
                        };
                });
                // Append relevant CCI data to master object for later reference.
                correlatedMasterObject.ccis = cciObject;
                correlatedMasterObject.cciListDate = cciListVersion;
                updateInformationElement();
        } catch (error) {
                console.error('Error processing CCI list:', error)
                alert("Not a valid CCI list xml file...");
        };
};

//////////////////////
// STIG XCCDF FILES //
//////////////////////
function processSTIGxccdf(filename, content, fileCount) {
        let totalApplicableCount = 0;
        const stigGroupObject = {};
        const logConsole = document.getElementById('logConsole');
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(content, "text/xml");
        const stigId = xmlDoc.querySelector('Benchmark').getAttribute('id');
        const stigReleaseInfoString = xmlDoc.querySelector('Benchmark > plain-text[id="release-info"]').textContent;
        const stigRelease = parseInt(stigReleaseInfoString.substring(stigReleaseInfoString.indexOf(" ")));
        const stigBenchmarkDate = stigReleaseInfoString.substring(stigReleaseInfoString.indexOf("Date:") + 5).trim();
        const stigVersion = parseInt(xmlDoc.querySelector('Benchmark > version').textContent);
        const stigTitle = xmlDoc.querySelector('Benchmark > title').textContent
        const stigDisplay = filterStigString(stigTitle.replace(/\([^()]*\)/g, "").trim());
        const stigGroups = Array.from(xmlDoc.getElementsByTagName('Group'));
        const stigKeyName = stigDisplay.replace(/ /g,"_");
        stigGroups.forEach(group => {
                let stigGroupRuleCciObject = {};
                let groupRuling = false;
                const stigGroupTitle = group.querySelector('title').textContent;
                const stigGroupId = group.getAttribute('id');
                const stigGroupRule = group.querySelector('Rule');
                const stigGroupRuleSeverity = stigGroupRule.getAttribute('severity');
                const stigGroupRuleWeight = stigGroupRule.getAttribute('weight');
                const stigGroupRuleVersion = stigGroupRule.querySelector('version').textContent;
                const ansiblePlaybookTagRuleVersion = "DISA-STIG-" + stigGroupRuleVersion;
                const stigGroupRuleTitle = stigGroupRule.querySelector('title').textContent;
                const stigGroupRuleIdSrc = stigGroupRule.getAttribute('id');
                const stigGroupRuleId = stigGroupRuleIdSrc.replace("_rule","");
                const stigGroupDiscussionRaw1= stigGroupRule.querySelector('description').textContent;
                const stigGroupDiscussionRaw2 = stigGroupDiscussionRaw1.replace("<VulnDiscussion>", "");
                const stigGroupDiscussion = stigGroupDiscussionRaw2.replace("</VulnDiscussion><FalsePositives></FalsePositives><FalseNegatives></FalseNegatives><Documentable>false</Documentable><Mitigations></Mitigations><SeverityOverrideGuidance></SeverityOverrideGuidance><PotentialImpacts></PotentialImpacts><ThirdPartyTools></ThirdPartyTools><MitigationControl></MitigationControl><Responsibility></Responsibility><IAControls></IAControls>", "");
                const stigGroupCheck = stigGroupRule.querySelector('check-content').textContent;
                const stigGroupFix = stigGroupRule.querySelector('fixtext').textContent;
                const stigGroupRuleCciArray = Array.from(stigGroupRule.querySelectorAll('ident[system="http://cyber.mil/cci"]')).map(ident => ident.textContent);
                stigGroupRuleCciArray.forEach(stigCci => {
                        const correlatedCciData = correlatedMasterObject.ccis[stigCci];
                        const cciRuling = correlatedCciData.applicable;
                        if (groupRuling === false) {
                                if (cciRuling === true) {
                                        groupRuling = cciRuling;
                                        totalApplicableCount += 1;
                                };
                        };
                        const cciReferenceData = Object.values(correlatedCciData.references);
                        // Determine the security control for each STIG CCI and the highest STIG CCI reference ruling.
                        const referenceRulingObject = {};
                        if (cciReferenceData.length > 0) {
                                let count = 1;
                                cciReferenceData.forEach(ref => {
                                        referenceRulingObject[count] = [ref.version, ref.updatedIndex, ref.ruling];
                                        count += 1;
                                });
                        };
                        let cciControl;
                        let highestRuling = 0;
                        Object.values(referenceRulingObject).forEach(refArray => {
                                if (refArray[2] > highestRuling) {
                                        highestRuling = refArray[2];
                                        cciControl = refArray[1];
                                }
                        });
                        // Write lines to the log console for troubleshooting...
                        const newlogConsoleLine = document.createElement('li');
                        newlogConsoleLine.className = "logConsoleLine";
                        if (highestRuling === 0) {
                                // No NIST reference in CCI
                                const RemarksNoNistRevisionLogError = `    ===> ${stigCci} does not have a reference for NIST 800-53 revision ${correlatedMasterObject.selectedNistRevision}.`;
                                newlogConsoleLine.innerHTML = `${padDigit(String(logConsoleSize), 5, "0")}| <span class="quaternaryFontColor">${stigId}</span> - <span class="quaternaryFontColor">${stigGroupId}</span> : <span class="quaternaryFontColor">${stigCci}</span> : <span class="quaternaryFontColor">800-53r${correlatedMasterObject.selectedNistRevision}</span> = <span class="secondaryFontColor">${cciRuling}</span>\n<span class="secondaryFontColor">${RemarksNoNistRevisionLogError}</span></li>`;
                                logConsole.appendChild(newlogConsoleLine);
                                logConsoleSize += 1;
                                stigGroupRuleCciObject[stigCci] = {applicable: cciRuling, ruling: highestRuling};
                        } else if (highestRuling === 1) {
                                // Security control not in provided list
                                const RemarksNoControlMatchLogError = `    ===> The provided list of security controls does not include ${cciControl}...`;
                                newlogConsoleLine.innerHTML = `${padDigit(String(logConsoleSize), 5, "0")}| <span class="quaternaryFontColor">${stigId}</span> - <span class="quaternaryFontColor">${stigGroupId}</span> : <span class="quaternaryFontColor">${stigCci}</span> : <span class="quaternaryFontColor">800-53r${correlatedMasterObject.selectedNistRevision}</span> : <span class="quaternaryFontColor">${cciControl}</span> = <span class="secondaryFontColor">${cciRuling}</span>\n<span class="secondaryFontColor">${RemarksNoControlMatchLogError}</span></li>`;
                                logConsole.appendChild(newlogConsoleLine);
                                logConsoleSize += 1;
                                stigGroupRuleCciObject[stigCci] = {control: cciControl, ruling: highestRuling, applicable: cciRuling};
                        } else if (highestRuling === 2) {
                                // CCI Matched to applicable control
                                newlogConsoleLine.innerHTML = `${padDigit(String(logConsoleSize), 5, "0")}| <span class="primaryFontColor">${stigId}</span> - <span class="primaryFontColor">${stigGroupId}</span> : <span class="primaryFontColor">${stigCci}</span> : <span class="primaryFontColor">800-53r${correlatedMasterObject.selectedNistRevision}</span> : <span class="primaryFontColor">${cciControl}</span> = ${cciRuling}</span>`;
                                logConsole.appendChild(newlogConsoleLine);
                                logConsoleSize += 1;
                                stigGroupRuleCciObject[stigCci] = {control: cciControl, ruling: highestRuling, applicable: cciRuling};
                        } else if (stigGroupRuleCciArray.length === 0) {
                                cciRuling = false;
                                const RemarksNoCciPresent = `    ===> There are no DISA CCI's present for this STIG rule...`;
                                newlogConsoleLine.innerHTML = `${padDigit(String(logConsoleSize), 5, "0")}| <span class="quaternaryFontColor">${stigId}</span> - <span class="quaternaryFontColor">${stigGroupId}</span> : <span class="quaternaryFontColor">N/A</span> : <span class="quaternaryFontColor">N/A</span> : <span class="quaternaryFontColor">N/A</span> = ${cciRuling}</span>\n<span class="secondaryFontColor">${RemarksNoCciPresent}</span></li>`;
                                logConsole.appendChild(newlogConsoleLine);
                        }
                });
                stigGroupObject[stigGroupId] = {
                        ansible_playbook_tag: ansiblePlaybookTagRuleVersion,
                        applicable: groupRuling,
                        ccis: Object.keys(stigGroupRuleCciObject),
                        check_content: stigGroupCheck,
                        remarks: "",
                        discussion: stigGroupDiscussion,
                        fix_text: stigGroupFix,
                        finding_details: "",
                        group_id: stigGroupId,
                        group_title: stigGroupTitle,
                        id: stigGroupRuleCciObject,
                        rule_id: stigGroupRuleId,
                        rule_id_src: stigGroupRuleIdSrc,
                        rule_title: stigGroupRuleTitle,
                        rule_version: stigGroupRuleVersion,
                        severity: stigGroupRuleSeverity,
                        status: "",
                        weight: stigGroupRuleWeight
                };
        });
        if (!Object.keys(correlatedMasterObject.stigs).includes(stigKeyName)) {
                correlatedMasterObject.stigs[stigKeyName] = {
                        applicable: totalApplicableCount,
                        benchmark_date: stigBenchmarkDate,
                        display_name: stigDisplay,
                        evaluate_stig_shortname: "",
                        file_name: filename,
                        notApplicable: Object.keys(stigGroupObject).length - totalApplicableCount,
                        release_info: stigRelease,
                        rules: stigGroupObject,
                        size: Object.keys(stigGroupObject).length,
                        stig_id: stigId,
                        stig_name: stigTitle,
                        version: stigVersion
                };
        };
        updateInformationElement(fileCount);
        let filenameArray = [];
        if (!filenameArray.includes(filename)) {
                filenameArray.push(filename);
        };
};

////////////////////////////
// INFORMATION PROCESSING //
////////////////////////////
// Add STIG and Control Tags
function addTags() {
        const tagContainer = document.getElementById('tagOuterContainer');
        const stigTags = document.getElementById("stigTagsUnorderedList");
        const controlTags = document.getElementById("controlTagsUnorderedList");
        stigTags.innerHTML = "";
        controlTags.innerHTML = "";
        tagContainer.classList.add("displayFlex");
        tagContainer.style.borderLeft = "1px solid #3A3A3A"
        Object.values(correlatedMasterObject.stigs).forEach(stigData => {
                const stigTag = document.createElement('li');
                const stigId = stigData.stig_id.replace(/_/g, " ");
                stigTag.classList.add("alignItemsCenter", "animationElement", "borderRadius", "contentSpaceBetween", "fontSizeSmall", "primaryBackground", "primaryFontColor", "tag");
                stigTag.textContent = filterStigString(stigId);
                stigTag.id = stigId;
                stigTag.textContent = (stigTag.textContent.length > 32) ? `${stigTag.textContent.slice(0, 32)}... - v${stigData.version}r${stigData.release_info}` : `${stigTag.textContent} - v${stigData.version}r${stigData.release_info}`;
                const stigTagDiv = document.createElement('div');
                stigTagDiv.classList.add("alignItemsCenter", "contentSpaceBetween");
                stigTag.appendChild(stigTagDiv);
                stigTags.appendChild(stigTag);
        });
        Object.keys(correlatedMasterObject.securityControls).sort().forEach(control => {
                const controlTag = document.createElement('li');
                controlTag.classList.add("alignItemsCenter", "animationElement", "borderRadius", "contentSpaceBetween", "fontSizeSmall", "primaryBackground", "primaryFontColor", "tag");
                controlTag.textContent = control;
                controlTag.id = control.replace(" ", "_");
                const controlTagDiv = document.createElement('div');
                controlTagDiv.classList.add("alignItemsCenter", "contentSpaceBetween");
                controlTag.appendChild(controlTagDiv);
                controlTags.appendChild(controlTag);
        });
};
// Progress Bar
function updateProgressBar(timeout) {
        const totalStigs = Object.keys(correlatedMasterObject.stigs).length;
        const stigFileNames = [];
        Object.values(correlatedMasterObject.stigs).forEach(data => {
                stigFileNames.push(data.file_name);
        });
        document.getElementById('correlationProgressContainer').classList.add("displayFlex");
        const progressBar = document.getElementById('correlationProgressBar');
        const progressBarText = document.getElementById('correlationProgressBarText');
        progressBarText.innerHTML = "Please wait...";
        const progressBarFiller = document.getElementById("correlationProgressBarFill");
        let increment = 1;
        function fillProgressBar() {
                const progressBarFillIncrement = (100 / totalStigs) * increment;
                if (increment <= totalStigs) {
                        progressBarFiller.style.transition = "width 500ms";
                        progressBarFiller.style.backgroundColor = "#4CAF50";
                        progressBar.style.backgroundColor = "#1f2124";
                        progressBarFiller.style.width = progressBarFillIncrement + "%";
                        progressBarText.innerHTML = `(${increment}/${totalStigs})  Processing ${stigFileNames[increment - 1]}...`;
                        if (increment === totalStigs) {
                                increment += 2;
                        } else {
                                increment += 1;
                        }
                        setTimeout(fillProgressBar, timeout);
                } else {
                        progressBarText.innerHTML = "All STIGs correlated successfully!";
                        progressBarFiller.style.backgroundColor = "#2d3035";
                        progressBar.style.backgroundColor = "#2d3035";
                        buildContent();
                };
        };
        setTimeout(fillProgressBar, timeout);
};
// Update Information Window
function updateInformationElement(fileCount) {
        if (correlatedMasterObject.securityControls !== undefined) {
                document.getElementById('securityControlsTotalValue').textContent = `${Object.keys(correlatedMasterObject.securityControls).length}`;
        };
        if (correlatedMasterObject.cciListDate !== undefined) {
                document.getElementById('cciListVersionValue').textContent = `${correlatedMasterObject.cciListDate}`;
        };
        if (correlatedMasterObject.stigs !== undefined && Object.keys(correlatedMasterObject.stigs).length === fileCount) {
                document.getElementById('stigsUploadedValue').textContent = `${Object.keys(correlatedMasterObject.stigs).length}`;
                updateProgressBar(200);
        };
};
// Show Advanced Checkbox
document.getElementById('showAdvancedCheckbox').addEventListener('change', showAdvancedOptions);
function showAdvancedOptions() {
        const showAdvancedCheckbox = document.getElementById('showAdvancedCheckbox');
        if (showAdvancedCheckbox.checked === true) {
                document.getElementById('logConsoleCollapsible').style.display = "flex";
                //document.getElementById('dataMapCollapsible').style.display = "flex";
        } else {
                document.getElementById('logConsoleCollapsible').style.display = "none";
                //document.getElementById('dataMapCollapsible').style.display = "none";
        };
};
// Log Console filtering
document.getElementById('logConsoleFilter').addEventListener('keyup', filterLogConsole);
function filterLogConsole() {
        const logConsoleLines = document.getElementsByClassName('logConsoleLine');
        const logConsoleFilter = document.getElementById('logConsoleFilter');
        const filterValue = logConsoleFilter.value.toLowerCase();
        Object.values(logConsoleLines).forEach(logLine => {
                const lineText = logLine.textContent.toLowerCase();
                if (lineText.includes(filterValue)) {
                        logLine.style.display = "list-item";
                } else {
                        logLine.style.display = "none";
                }
        });
};
// Display additional elements
function showContent() {
        document.getElementById('showAdvancedCheckboxContainer').classList.add("displayFlex");
        document.getElementById('resultsTableCollapsible').classList.add("displayFlex");
        document.getElementById('stigChecklistCollapsible').classList.add("displayFlex");
};
// Build out elements
function buildContent() {
        addTags();
        showContent();
        resultTableControl()
        console.log(correlatedMasterObject);
}

///////////////////
// RESULTS TABLE //
///////////////////
document.getElementById('resultsTableContainer').addEventListener('click', showHiddenRow);
document.getElementById('hideFalseCheckbox').addEventListener('change', resultTableControl);
function resultTableControl() {
        const openDetails = [];
        const resultDetails = document.getElementsByClassName('resultDetails');
        // Determine which results elements are expanded and store the respective ID.
        Object.values(resultDetails).forEach(value => {
                if (value.open) {
                        openDetails.push(value.id);
                };
        });
        // Determine if tables are to be built displaying all rules, or just the applicable rules.
        const hideFalseCheckbox = document.getElementById('hideFalseCheckbox');
        if (hideFalseCheckbox.checked === true) {
                buildResultTables(1);
        } else if (hideFalseCheckbox.checked === false) {
                buildResultTables(0);
        };
        // Using the previously store ID for expanded result elements, ensure that those elements remain open.
        openDetails.forEach(details => {
                const element = document.getElementById(details);
                element.setAttribute('open', '');
        });
};
function buildResultTables(option) {
        const resultsTableContainer = document.getElementById('resultsTableContainer');
        resultsTableContainer.innerHTML = '';
        const resultTables = document.createDocumentFragment();
        Object.entries(correlatedMasterObject.stigs).sort().forEach(([stigId, stigData]) => {
                // Build result table structure
                const detailsElement = document.createElement('details');
                resultTables.appendChild(detailsElement);
                const summaryElement = document.createElement('summary');
                detailsElement.appendChild(summaryElement);
                const resultsTableMainDiv = document.createElement('div');
                detailsElement.appendChild(resultsTableMainDiv);
                const summaryLabelContainer = document.createElement('div');
                summaryElement.appendChild(summaryLabelContainer);
                const summaryLabelSpan = document.createElement('span');
                summaryLabelContainer.appendChild(summaryLabelSpan);
                const severityCountersContainer = document.createElement('div');
                summaryLabelContainer.appendChild(severityCountersContainer);
                const headContainer = document.createElement('div');
                resultsTableMainDiv.appendChild(headContainer);
                const bodyOuterContainer = document.createElement('div');
                resultsTableMainDiv.appendChild(bodyOuterContainer);
                const bodyInnerContainer = document.createElement('div');
                bodyOuterContainer.appendChild(bodyInnerContainer);
                // Element ID values
                const summaryLabelID = `${stigId}_label`;
                const summaryLabelContainerID = `${stigId}_label_container`;
                const detailsID = `${stigId}_details`;
                // Setup element classes
                detailsElement.className = 'resultDetails';
                summaryElement.className = 'alignItemsCenter boldFont cursorPointer resultsSummary';
                summaryLabelContainer.className = 'alignItemsCenter contentSpaceBetween flexRow';
                summaryLabelSpan.className = 'primaryFontColor stigTitleRow';
                severityCountersContainer.className = 'alignItemsCenter padRight10';
                resultsTableMainDiv.className = 'alignItemsCenter borderNone flexColumn overFlowHidden padAll';
                bodyOuterContainer.className = 'alignItemsCenter contentCenter maxHeight resultsTableBodyOuterContainer';
                bodyInnerContainer.className = 'maxHeight overflowYScroll';
                // Setup element ID's
                summaryLabelContainer.id = summaryLabelContainerID;
                summaryLabelSpan.id = summaryLabelID;
                detailsElement.id = detailsID;
                let severityArray = [stigData.size, stigData.applicable, 0, 0, 0];
                // Create table header
                const tableHead = document.createElement('table');
                headContainer.appendChild(tableHead);
                const header = tableHead.createTHead();
                const headerRow = header.insertRow();
                const headerArray = ['Title', 'Rule', 'Version', 'Severity', 'Applicable?'];
                headerArray.forEach(header => {
                        const th = document.createElement('th');
                        th.textContent = header;
                        th.setAttribute("colspan", "2");
                        headerRow.appendChild(th);
                });
                const ruleDataObject = {};
                Object.entries(stigData.rules).forEach(([id, data]) => {
                        const ruleApplicable = data.applicable;
                        if (option === 1) {  //0 = All rules;  1 = Only applicable
                                if (ruleApplicable === true) {
                                        ruleDataObject[id] = data;
                                };
                        } else if (option === 0) {
                                ruleDataObject[id] = data;
                        };
                });
                summaryLabelContainer.style.width = "1100px"
                summaryLabelSpan.textContent = `${stigData.display_name}  v${stigData.version}r${stigData.release_info} - Date: ${stigData.benchmark_date}`;
                // Create table body
                const tableBody = document.createElement('table');
                bodyInnerContainer.appendChild(tableBody);
                Object.entries(ruleDataObject).forEach(([ruleId, ruleData]) => {
                        const ruleApplicable = ruleData.applicable;
                        const ruleCcis = [];
                        const stigTableBody = tableBody.createTBody();
                        const ruleSeverity = ruleData.severity.charAt(0).toUpperCase() + ruleData.severity.slice(1);
                        Object.entries(ruleData.id).forEach(([cci, cciData]) => {
                                if (cciData.ruling === 0) {
                                        ruleCcis.push(`${cci}=${cciData.applicable}: No ref for 800-53v${correlatedMasterObject.selectedNistRevision}.`);
                                } else if (cciData.ruling === 1) {
                                        ruleCcis.push(`${cci}=${cciData.applicable}: ${cciData.control.replace(" (", "(")} not in list.`);
                                } else if (cciData.ruling === 2) {
                                        ruleCcis.push(`${cci}=${cciData.applicable}: ${cciData.control.replace(" (", "(")} in list.`);
                                };
                        });
                        const tableDataObject = [
                                ["ruleRow", "expandableRow", 5,
                                        [
                                                [ruleData.rule_title, 2],
                                                [ruleId, 2],
                                                [ruleData.rule_version, 2],
                                                [ruleSeverity, 2],
                                                [ruleApplicable.toString().charAt(0).toUpperCase() + ruleApplicable.toString().slice(1), 2]
                                        ]
                                ],
                                ["hiddenTitle", "hiddenTitleRow", 4,
                                        [
                                                ["Rule discussion: ", 3, "hiddenTitleCell"],
                                                ["Check steps: ", 3, "hiddenTitleCell"],
                                                ["Fix action: ", 2, "hiddenTitleCell"],
                                                ["CCI Results: ", 2, "hiddenTitleCell"]
                                        ],
                                ],
                                ["hiddenRow", "hiddenContentRow", 4,
                                        [
                                                [ruleData.discussion, 3, "hiddenCell"],
                                                [ruleData.check_content, 3, "hiddenCell"],
                                                [ruleData.fix_text, 2, "hiddenCell"],
                                                [ruleCcis.join("\n"), 2, "hiddenCell"],
                                        ],
                                ]
                        ];   // [row class, row id, cell limit, (each cell) --> [cell textContent, cell colSpan, cell class]]
                        for (i = 0; i < 3; i++) {
                                let row = stigTableBody.insertRow(i);
                                row.className = tableDataObject[i][0];
                                row.id = tableDataObject[i][1];
                                if (i === 0) {
                                        row.setAttribute("colspan", "2");
                                } else {
                                        row.classList.add("hide");
                                };
                                // cell setup
                                for (j = 0; j < tableDataObject[i][2]; j++) {
                                        let cell = row.insertCell(j);
                                        cell.textContent = tableDataObject[i][3][j][0];
                                        cell.setAttribute("colspan", tableDataObject[i][3][j][1]);
                                        if (i != 0) {
                                                cell.setAttribute("class", tableDataObject[i][3][j][2]);
                                        };
                                        if (i === 2) {
                                                cell.classList.add("fontSizeSmaller");
                                                if (j === 3) {
                                                        cell.classList.add("whiteSpacePreserve");
                                                };
                                        };
                                };
                                if (ruleApplicable) {
                                        if (ruleSeverity === "High") {
                                                if (i === 0) {
                                                        row.classList.add("highlightedRowHigh");
                                                        severityArray[2] += 1;
                                                } else if (i === 1) {
                                                        row.classList.add("highlightedRowHighHiddenTitle");
                                                } else if (i === 2) {
                                                        row.classList.add("highlightedRowHighHiddenContent");
                                                };
                                        } else if (ruleSeverity === "Medium") {
                                                if (i === 0) {
                                                        row.classList.add("highlightedRowMedium");
                                                        severityArray[3] += 1;
                                                } else if (i === 1) {
                                                        row.classList.add("highlightedRowMediumHiddenTitle");
                                                } else if (i === 2) {
                                                        row.classList.add("highlightedRowMediumHiddenContent");
                                                };
                                        } else if (ruleSeverity === "Low") {
                                                if (i === 0) {
                                                        row.classList.add("highlightedRowLow");
                                                        severityArray[4] += 1;
                                                } else if (i === 1) {
                                                        row.classList.add("highlightedRowLowHiddenTitle");
                                                } else if (i === 2) {
                                                        row.classList.add("highlightedRowLowHiddenContent");
                                                };
                                        };
                                };
                        };
                        ruleCciResults = "";

                });
                resultsTableContainer.appendChild(resultTables);
                // Build out severity counters
                const severityCounterDataObject = {
                        totalRulesCounter: "Total rules",
                        totalApplicableCounter: "Total applicable rules",
                        totalApplicableHighsCounter: "Total applicable high severity rules",
                        totalApplicableMediumsCounter: "Total applicable medium severity rules",
                        totalApplicableLowsCounter: "Total applicable low severity rules"
                };
                Object.entries(severityCounterDataObject).forEach(([id, title]) => {
                        const severityIdIndex = Object.keys(severityCounterDataObject).indexOf(id);
                        const div = document.createElement('div');
                        div.title = title;
                        div.className = `alignItemsCenter contentCenter ${id} severityCounter`;
                        div.id = `${stigId}_${id}`;
                        div.title = title;
                        div.textContent = severityArray[severityIdIndex];
                        severityCountersContainer.appendChild(div)
                })
        });
};
function showHiddenRow(event) {
        const expandableRow = event.target.closest('tr');
        if (expandableRow && expandableRow.id === "expandableRow") {
                const hiddenTitleRow = expandableRow.nextElementSibling;
                const hiddenContentRow = hiddenTitleRow ? hiddenTitleRow.nextElementSibling : null;
                if (hiddenTitleRow && hiddenContentRow) {
                        hiddenTitleRow.classList.toggle("displayTableRow");
                        hiddenContentRow.classList.toggle("displayTableRow");
                };
        };
};

/////////////////////
// STIG CHECKLISTS //
/////////////////////
//// EVENT LISTENERS
document.getElementById('stigChecklistHostCsvUpload').addEventListener('change', processStigChecklistHostCsvUpload);
document.getElementById('stigChecklistDownloadButton').addEventListener('click', processCklb);
//// HOST CSV
function processStigChecklistHostCsvUpload(event) {
        const file = event.target.files[0];
        const reader = new FileReader();
        reader.onload = function(e) {
                const content = e.target.result;
                if (event.target.id === 'stigChecklistHostCsvUpload') {
                        processStigChecklistHosts(content);
                };
        };
        reader.readAsText(file);
};
function processStigChecklistHosts(content) {
        stigHostCsvHeader = content.split("\n")[0];
        validCsvHeader = "hostname,domain,ipAddress,macAddress,targetRemarks,role,NonComputing,TechnologyArea,webDBasset,webDBsite,webDBInstance";
        if (stigHostCsvHeader.localeCompare(validCsvHeader) === 1) {
                const stigHostArray = content.split('\n');
                stigHostArray.shift();
                stigHostArray.forEach(stigHost => {
                        const csvStigHost = stigHost.trim();
                        const stigHostInfoArray = csvStigHost.split(',');
                        let hostWebDbAsset = false;
                        if (stigHostInfoArray[8] === "true") {
                                hostWebDbAsset = true;
                        }
                        if (stigHostInfoArray[0] === "" || stigHostInfoArray[2] === "") {
                                console.log('Please provide an IP address or FQDN for asset identifcation in STIG Manager');
                                alert("Each asset requires an IP address or hostname for proper identifcation in STIG MAnager.");
                        } else {
                                stigChecklistHostInfoObject.push({
                                        Hostname: stigHostInfoArray[0],
                                        Domain: stigHostInfoArray[1],
                                        IPAddress: stigHostInfoArray[2],
                                        MACAddress: stigHostInfoArray[3],
                                        FQDN: `${stigHostInfoArray[0]}.${stigHostInfoArray[1]}`,
                                        Comments: stigHostInfoArray[4],
                                        Role: stigHostInfoArray[5],
                                        TechArea: stigHostInfoArray[6],
                                        NonComputing: stigHostInfoArray[7],
                                        WebDBAsset: hostWebDbAsset,
                                        WebDBSite: stigHostInfoArray[9],
                                        WebDBInstance: stigHostInfoArray[10],
                                });
                        };
                });
        } else {
                console.log('Error host infomration CSV file.');
                alert("Not a valid host infomration csv file. Please ensure CSV header is correct.");
        };
};
//// CKLB
function processCklb() {
        Object.values(correlatedMasterObject.stigs).forEach(stigData => {
                Object.values(stigData.rules).forEach(rule => {
                        if (rule.applicable === false) {
                                rule.status = "not_applicable";
                                rule.finding_details = document.getElementById('stigChecklistsNotApplicableDetails').value;
                        } else {
                                rule.status = "not_reviewed";
                        };
                        stigData.rules = Object.values(stigData.rules)
                });
        });
        if (stigChecklistHostInfoObject.length === 0) {
                newCklb = {
                        title: "Custom_STIG_Checklist(s)",
                        target_data: {
                                web_db_instance: "",
                                web_db_site: "",
                                technology_area: "",
                                is_web_database: "",
                                role: "",
                                comments: "",
                                fqdn: "",
                                mac_address: "",
                                ip_address: "",
                                host_name: "TEMPLATE-CUSTOM_CHECKLIST",
                                target_type: "",
                        },
                        stigs: Object.values(correlatedMasterObject.stigs)
                };
                downloadCklb(newCklb);
        } else {
                stigChecklistHostInfoObject.forEach(host => {
                        newCklb = {
                                title: `${host.IPAddress}_${host.Hostname}_STIG_Checklist(s)`,
                                target_data: {
                                        web_db_instance: host.WebDBInstance,
                                        web_db_site: host.WebDBSite,
                                        technology_area: host.TechArea,
                                        is_web_database: host.WebDBAsset,
                                        role: host.Role,
                                        comments: host.Comments,
                                        fqdn: host.FQDN,
                                        mac_address: host.MACAddress,
                                        ip_address: host.IPAddress,
                                        host_name: host.Hostname,
                                        target_type: host.NonComputing,
                                },
                                stigs: Object.values(correlatedMasterObject.stigs)
                        };
                        downloadCklb(newCklb);
                });
        };
};
function downloadCklb(checklist) {
        const timestamp = Date.now()
        const date = new Date(timestamp);
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        const cklbTimestamp = `--${year}-${month}-${day}_${hours}\u2236${minutes}\u2236${seconds}`;
        const newCklbJson = JSON.stringify(checklist);
        const blob = new Blob([newCklbJson], {type: "application/json"});
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = checklist.title + cklbTimestamp + ".cklb";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

};
