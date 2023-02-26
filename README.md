# Project: Evasion Escaper

![](assets/Evasion-Escaper.png)

The primary objective of this project is to evade the various checks that malicious software employs to identify if it's running in a virtual environment or sandbox, and to pass all such checks with success. To accomplish this, a novel approach has been adopted that leverages a DLL to effortlessly track the DLLs loaded on the system, access their addresses, and modify them as required. As a reference and test case, "Al-Khaser by LordNoteworthy" has been utilized. The ultimate goal of this project is to overcome the controls that malicious software implements in a sandbox or virtual machine environment to conceal its malicious activities.

## Content

- [Project: Evasion Escaper](#project-evasion-escaper)
  - [Content](#content)
  - [Bypass Methods for Application Checks in Evasion Escaper](#bypass-methods-for-application-checks-in-evasion-escaper)
  - [Other Solutions \& Additional Sources](#other-solutions--additional-sources)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Risks and Limitations](#risks-and-limitations)
  - [License](#license)
  - [References](#references)

## Bypass Methods for Application Checks in Evasion Escaper

This project introduces several new bypass methods for application checks, such as:

- WMI Query requests, including ExecQuery and Get methods
- Known dynamic link libraries (DLLs)
- Known usernames, computer names, netbios hostnames, and DNS hostnames
- Known files' availability and filenamess
- CloseHandle protected handle trick using SetHandleInformation
- Device registry property access using SetupDiGetDeviceRegistryPropertyW
- Enumeration of running services using EnumServicesStatusExW
- Retrieval of disk space information using GetDiskFreeSpaceExW
- Registry value retrieval using RegQueryValueExW
- Registry key enumeration using RegEnumKeyExW
- Delay execution using NtDelayExecution
- Timers, including SetTimer, TimeSetEvent, WaitForSingleObject, SetWaitableTimer, and CreateTimerQueueTimer
- Retrieval of system firmware table information using GetSystemFirmwareTable and EnumSystemFirmwareTables
- ...

This project is open to ongoing development and contribution, with plans to add additional improvements to the current bypass methods in future commits. The code has been structured to enhance readability and maintainability. As the project progresses, documentation for the bypass methods will be continuously updated and refined. Contributions from the community are highly welcomed and appreciated.

## Other Solutions & Additional Sources

- __cpuid ([link](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/))
- Function outputs documented in assets/targeted_functions_documentation.md

## Installation

To install Evasion Escaper, follow these simple steps:

- Clone or download the project from the GitHub repository: https://github.com/vvelitkn/Evasion-Escaper
- Navigate to the Bin folder and run the install.reg, needs administrative privileges. This will make the necessary registry changes.
- Open the agent.sln file in Visual Studio 2022 and build the solution. This will generate the agent.dll file in the Bin folder.
- That's it! Evasion Escaper is now ready to use.

## Usage

- Make sure the agent.dll file located in the Bin folder to your project directory. If not repeat the Installation steps.
- Rename the target executable file to target.exe (Al-Khaser sample compiled and zipped under Bin folder, password: infected)
- Run the install.bat file with administrative privileges: right-click on the file and select "Run as administrator".
- Execute target.exe.
- When the target.exe is executed, the agent.dll file will automatically be loaded and any necessary setup will be performed.

Note: Make sure to run your project in a virtual environment. Do not test it on your actual device.

I do not assume any liability for any potential risks or legal issues associated with the use of this project, and users are solely responsible for any consequences resulting from its use. Additionally, the project is provided under the Apache License 2.0, and by using this project, users agree to comply with the terms and conditions outlined in the license agreement. Any violation of the license terms may result in legal action.

## Risks and Limitations

While Evasion Escaper is designed to bypass detection methods used by malicious software in virtual environments or sandboxes, it is important to note that no security tool is 100% foolproof. As with any security tool, there may be unknown vulnerabilities or untested scenarios that could potentially bypass the tool's evasion techniques.

Additionally, the use of Evasion Escaper to bypass security measures in unauthorized or malicious activities is strictly prohibited and could result in legal consequences.

## License

Evasion Escaper is licensed under the Apache License 2.0. This means that it is free to use, modify, and distribute, provided that proper attribution is given to the original authors and any changes made to the project are clearly documented. It is important to review the full text of the license agreement before using Evasion Escaper to ensure compliance with the terms and conditions outlined in the license.

## References

- Al-Khaser tool: https://github.com//LordNoteworthy/al-khaser.
- Pafish tool: https://github.com/a0rtega/pafish.
