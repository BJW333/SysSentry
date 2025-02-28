SysSentry
=========

SysSentry is a cross‑platform, Python‑based system monitoring and network sniffing tool.
It provides real‑time insights into CPU, memory, disk, and network usage, while scanning
running processes for suspicious activity. A built‑in packet sniffer (using Scapy)
captures network traffic and displays protocol details in a user‑friendly GUI.

Features
--------
• System Monitoring: Live updates on CPU, memory, disk, and network usage.
• Process Analysis: Detects and logs suspicious processes based on resource usage.
• Packet Sniffing: Captures and displays network packet details in real time.
• Cross‑Platform: Runs on macOS, Windows, and Linux with a unified interface.
• User‑Friendly GUI: Built with Tkinter for simplicity and ease of use.

Prerequisites
-------------
Ensure you have Python 3.x installed. Install the required packages via pip:

  pip install psutil scapy pyinstaller

(Note: Tkinter is usually included with Python. If you encounter issues, refer to your OS
documentation for installation instructions.)

Building a Standalone macOS Application (.app) with PyInstaller
-----------------------------------------------------------------
SysSentry can be bundled into a standalone application using PyInstaller.
The provided setup.py script (or build script) automates this process.

Directory Structure:
  • SysSentry.py         - The main application script.
  • radar_heartbeat_icon.icns - The icon file for the application.
  • setup.py             - The build script (see below for its contents).

How to Build:
--------------
1. Open Terminal and navigate to your project directory:
     cd /path/to/your/project/directory

2. Run the setup script:
     python setup.py

   This command will invoke PyInstaller with the following options:
     • --onefile: Packages everything into a single executable.
     • --windowed: Creates a windowed application (without a terminal window).
     • --icon: Uses the specified icon file.
     • --distpath: Specifies the output directory (in this example, a folder named "release").

3. Locate Your App:
   After the build completes, check the "release" folder for your SysSentry.app bundle.
   You can double-click it to run the application.

Troubleshooting
---------------
• Gatekeeper Warnings:
  If macOS blocks the app because it is from an unidentified developer, right-click (or
  Control-click) the .app file, choose "Open", and confirm that you wish to run it.

• Permissions:
  Some features, such as network sniffing, may require elevated privileges.
  If necessary, run the application via Terminal with "sudo" or adjust your system permissions.

• Dependencies:
  Ensure all required Python packages are installed. If you encounter missing module errors,
  verify your virtual environment or system installation.

License
-------
(MIT License.)
