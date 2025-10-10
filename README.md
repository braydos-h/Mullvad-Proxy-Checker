# Mullvad Proxy Checker

A desktop utility for validating Mullvad SOCKS5 exit nodes. The application uses `curl` to verify reachability, captures the public IP address reported by the proxy, and checks whether the endpoint is recognised as an active Mullvad server. The graphical interface is built with Tkinter and supports batch checks with parallel workers.

## Features

- Parse a pasted list of Mullvad private IPs or load them from a text file.
- Run concurrent SOCKS5 reachability checks using `curl`.
- Detect whether the proxy is a Mullvad endpoint and record the reported public IP and server name.
- Export the results to CSV for further analysis.

## Requirements

- Python 3.9 or newer (the application uses the standard library only).
- `curl` available on the system `PATH`. Windows 10+ includes `curl.exe` by default; on other platforms install it via your package manager.

## Usage

1. Prepare a list of Mullvad internal proxy IP addresses. An up-to-date list is available in the [mullvad-socks-list repository](https://github.com/maximko/mullvad-socks-list).
2. Launch the GUI:

   ```bash
   python app.py
   ```

3. Paste the list of IP addresses into the text area or load a file via the **Load file…** button.
4. Click **Start checks** to begin scanning. Progress updates in real time.
5. Optionally export the results to CSV once the checks complete.

The default SOCKS5 port (`1080`) can be edited directly in the source if your configuration differs.

## Repository Structure

- `app.py` – Tkinter GUI application and proxy checking logic.
- `mullvadproxyips.txt` – Sample list of Mullvad private IP addresses.

## License

This project is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
