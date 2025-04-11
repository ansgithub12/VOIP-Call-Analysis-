import subprocess

def run_pkrscan(file_data):
    try:
        result = subprocess.run(
            ["pkrscan", "-"], 
            input=file_data,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running pkrscan: {e}")
        return f"Error: {e}"
    except FileNotFoundError:
        return "Error: pkrscan not found.  Make sure it's installed and in your PATH."

if __name__ == "__main__":
    # Example usage
    with open("Forensic_challenge_4.pcap", "rb") as f:
        file_data = f.read()

    # Call the function and print the result
    pkrscan_output = run_pkrscan(file_data)
    print(pkrscan_output)