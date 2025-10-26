
import subprocess, sys, time, os

def main():
    py = sys.executable
    # start server_single.py
    srv = subprocess.Popen([py, "server_single.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(0.6)  # small head-start
    # start GUI
    gui = subprocess.Popen([py, "socp_gui_client_pro.py"])
    print("Launched server_single.py (pid", srv.pid, ") and GUI (pid", gui.pid, "). Ctrl+C to stop.")
    try:
        gui.wait()
    except KeyboardInterrupt:
        pass
    finally:
        try: gui.terminate()
        except: pass
        try: srv.terminate()
        except: pass

if __name__ == "__main__":
    main()
