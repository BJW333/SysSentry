import subprocess
import sys
import os
from pathlib import Path

script_dir = Path(__file__).parent

def main():
    #command for pyinstaller
    sys_sentry_path = str(script_dir / "SysSentry.py")
    icon_path = str(script_dir / "radar_heartbeat_icon.icns")
    
    output_dir = str(script_dir / "release")
    
    command = [
        "pyinstaller",
        "--onefile",
        "--windowed",
        f"--icon={icon_path}",
        f"--distpath={output_dir}",
        sys_sentry_path
    ]

    print("Running command:", " ".join(command))

    #run the command in the current directory
    try:
        subprocess.run(command, check=True)
        print("\nBuild complete! Check the 'dist' folder for your app/executable.")
    except subprocess.CalledProcessError as e:
        print(f"Build failed with error code {e.returncode}.", file=sys.stderr)

if __name__ == "__main__":
    main()
