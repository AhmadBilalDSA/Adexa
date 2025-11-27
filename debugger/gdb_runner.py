import subprocess
import datetime
import os

def run_gdb(binary_path, args=""):
    # Create logs folder if missing
    if not os.path.exists("../logs"):
        os.makedirs("../logs")

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"../logs/gdb_crash_{timestamp}.txt"

    # Commands that GDB will execute
    gdb_commands = [
        "run " + args,
        "info registers",
        "bt",
        "x/20x $esp",
        "quit"
    ]

    # Convert commands into GDB syntax
    gdb_cmd = ["gdb", "-q", binary_path]
    for cmd in gdb_commands:
        gdb_cmd += ["-ex", cmd]

    try:
        result = subprocess.check_output(gdb_cmd, stderr=subprocess.STDOUT)
        output = result.decode(errors="ignore")

        with open(log_file, "w") as log:
            log.write("=== GDB OUTPUT ===\n\n")
            log.write(output)

        print(f"[+] GDB crash analysis saved to: {log_file}")

        return log_file

    except subprocess.CalledProcessError as e:
        output = e.output.decode(errors="ignore")

        with open(log_file, "w") as log:
            log.write("=== GDB ERROR OUTPUT ===\n\n")
            log.write(output)

        print(f"[!] GDB encountered an error. Log saved to: {log_file}")

        return log_file
