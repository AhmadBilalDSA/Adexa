import subprocess
import datetime
import os


def run_gdb(binary_path, payload):
    print("[DEBUG] Running GDB with script...")
    print("[DEBUG] Binary:", binary_path)
    print("[DEBUG] Payload length:", len(payload))

    # Ensure logs directory exists
    log_dir = os.path.join(os.path.dirname(__file__), "../logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"gdb_crash_{timestamp}.txt")

    # Write the payload to a temp file
    payload_file = "/tmp/adexa_payload.txt"
    with open(payload_file, "w") as f:
        f.write(payload)

    # FINAL FIXED COMMAND:
    # Use GDB script + redirect payload as argv
    cmd = f"gdb -q -batch -x {os.path.dirname(__file__)}/gdb_cmd.txt --args {binary_path} $(cat {payload_file})"

    print("[DEBUG] Executing:", cmd)

    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        output = result.decode(errors="ignore")

        with open(log_file, "w") as log:
            log.write("=== GDB OUTPUT ===\n\n")
            log.write(output)

        print(f"[+] Crash log saved at: {log_file}")

    except subprocess.CalledProcessError as e:
        output = e.output.decode(errors="ignore")

        with open(log_file, "w") as log:
            log.write("=== GDB ERROR OUTPUT ===\n\n")
            log.write(output)

        print(f"[!] GDB error logged at: {log_file}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 gdb_runner.py <binary>")
        sys.exit(1)

    binary = sys.argv[1]
    payload = "A" * 200

    run_gdb(binary, payload)

