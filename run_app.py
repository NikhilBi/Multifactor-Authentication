import subprocess
import webbrowser

def run_server():
    # Activate virtual environment
    subprocess.run([".\venv\Scripts\activate"], shell=True)

    # Start server using waitress-serve
    subprocess.Popen(["waitress-serve", "--port=5001", "app:app"])

    # Open web browser to localhost:5001
    webbrowser.open("http://localhost:5001/")

if __name__ == "__main__":
    run_server()
