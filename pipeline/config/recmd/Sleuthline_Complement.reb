Description: Sleuthline - complement to the Kroll batch
Author: Sleuthline (pipeline\config\recmd)
Version: 1.1
Id: 4b0c6d0e-7f1e-4a43-9a52-2f5d8c1e6a10
Keys:
#
# Keys missing from Kroll_Batch.reb (v1.22), checked on 2026-10-18 (grep on the installed batch).
# Run by orchestrator.py (job recmd_complement) in addition to the Kroll batch, on every hive.
# Source of truth: <repository>\pipeline\config\recmd\Sleuthline_Complement.reb (deployed with -Only Pipeline).
#
# Not repeated here, already covered by the plugins of Kroll_Batch.reb:
#   USB properties {83da6326-97a6-4088-9453-a1923f573b29}\0064 / 0066 / 0067 (first install,
#   last connection, last removal): decoded by the RECmd USB, USBSTOR and SCSI plugins
#   (FirstInstalled, LastConnected, LastRemoved columns of the recmd_kroll_*_USB/USBSTOR/SCSI.csv outputs).
#
# The definitions follow those of Eric Zimmerman's batches (SystemASEPs.reb, SoftwareASEPs.reb,
# AllRegExecutablesFoundOrRun.reb), grouped so as not to run those complete batches (noise).

# --------------------
# DEVICES
# --------------------

    -
        Description: EMDMgmt (ReadyBoost)
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows NT\CurrentVersion\EMDMgmt
        Recursive: true
        Comment: "Removable volumes seen by ReadyBoost: the name of each subkey ends with the label and the serial number of the volume (decimal), to match with LNK / Jump Lists (DriveSerialNumber, hexadecimal)"

# --------------------
# PERSISTENCE
# --------------------

    -
        Description: Active Setup Installed Components
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: Microsoft\Active Setup\Installed Components\*
        ValueName: StubPath
        Recursive: false
        Comment: "Command run at the first logon of each user (T1547.014)"
    -
        Description: Active Setup Installed Components (WOW6432Node)
        HiveType: SOFTWARE
        Category: Persistence
        KeyPath: WOW6432Node\Microsoft\Active Setup\Installed Components\*
        ValueName: StubPath
        Recursive: false
        Comment: "Command run at the first logon of each user (T1547.014), 32-bit view"
    -
        Description: Active Setup Installed Components (user)
        HiveType: NTUSER
        Category: Persistence
        KeyPath: Software\Microsoft\Active Setup\Installed Components\*
        ValueName: Version
        Recursive: false
        Comment: "Components already run for this user (a higher version on the SOFTWARE side runs StubPath again)"
    -
        Description: Print Monitors
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: ControlSet*\Control\Print\Monitors\*
        ValueName: Driver
        Recursive: false
        Comment: "DLL loaded by the spooler (SYSTEM) at startup (T1547.010)"
    -
        Description: Print Processors
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: ControlSet*\Control\Print\Environments\*\Print Processors\*
        ValueName: Driver
        Recursive: false
        Comment: "DLL loaded by the spooler (T1547.012)"
    -
        Description: Session Manager BootExecute
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: BootExecute
        Recursive: false
        Comment: "Native programs started by smss.exe before the services; normal value: autocheck autochk * (T1547.001)"
    -
        Description: Session Manager SetupExecute
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: SetupExecute
        Recursive: false
        Comment: "Native programs started by smss.exe; normally empty"
    -
        Description: Session Manager Execute
        HiveType: SYSTEM
        Category: Persistence
        KeyPath: ControlSet*\Control\Session Manager
        ValueName: Execute
        Recursive: false
        Comment: "Native programs started by smss.exe; normally empty"

# --------------------
# EXECUTION
# --------------------

    -
        Description: AppCompatFlags Compatibility Assistant Store
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
        Recursive: false
        Comment: "Program Compatibility Assistant: each value name is the path of an executable started by the user (execution clue)"
    -
        Description: AppCompatFlags Compatibility Assistant Persisted
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted
        Recursive: false
        Comment: "Program Compatibility Assistant (Windows 7/8): executables started by the user"
