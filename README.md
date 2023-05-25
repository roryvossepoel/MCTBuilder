# MCTBuilder
MCTBuilder injects drivers into boot.wim (WinPE and Windows Setup) and install.wim (Windows 11 Pro) of a USB-drive created with the Media Creation Tool.

Instructions:
1. Create a USB-drive using the Media Creation Tool
2. Construct the CSV-file with driver information
3. Generate a Windows Answer File (autounattend.xml) and copy the contents in variable $AnswerFile (optional).
4. Run Invoke-MCTBuilder.ps1 with administrative permissions

The drivers are downloaded, extracted and selected based on the contents of the CSV-File.
The Drivers-column contains drivers that will be injected. All others will be removed. All drivers will be kept of no drivers are specified in the Drivers-column.
    
 Vendors of supported driver packages:
 - Microsoft
 - HP
 - Dell
 - Lenovo
