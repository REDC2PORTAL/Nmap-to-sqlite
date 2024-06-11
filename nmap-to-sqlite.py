import xml.etree.ElementTree as ET
import sqlite3
import subprocess
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from datetime import datetime, timedelta
import threading

def get_nmap_scripts(script_dir='/usr/share/nmap/scripts'):
    scripts = {'Discovery': [], 'Version': [], 'Vulnerability': [], 'Misc': []}
    if os.path.isdir(script_dir):
        for file in os.listdir(script_dir):
            if file.endswith('.nse'):
                script_name = file.replace('.nse', '')
                if 'discover' in script_name:
                    scripts['Discovery'].append(script_name)
                elif 'version' in script_name:
                    scripts['Version'].append(script_name)
                elif 'vuln' in script_name:
                    scripts['Vulnerability'].append(script_name)
                else:
                    scripts['Misc'].append(script_name)
    for category in scripts:
        scripts[category].sort()  # Sort scripts alphabetically
    return scripts

def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError as e:
        raise ValueError(f"Error parsing XML file: {e}")

    root = tree.getroot()
    scan_start_time = root.get('start')
    scan_start_timestamp = int(scan_start_time) * 1000 if scan_start_time is not None else None
    elapsed_time_elem = root.find('runstats/finished')
    elapsed_time = elapsed_time_elem.get('elapsed') if elapsed_time_elem is not None else ''

    scan = {
        'nmap_version': root.get('version', ''),
        'command_line': root.get('args', ''),
        'start_time': scan_start_timestamp,
        'elapsed_time': elapsed_time,
        'total_hosts': 0,
        'total_open_ports': 0
    }

    hosts = []
    for host in root.findall('host'):
        address_elem = host.find('address')
        ip = address_elem.get('addr', '') if address_elem is not None else ''

        hostname_elems = host.findall('hostnames/hostname')
        hostname = hostname_elems[0].get('name', '') if hostname_elems else ''
        os = 'Unknown'
        os_element = host.find('os')
        if os_element:
            os_match = os_element.find('osmatch')
            os = os_match.get('name', 'Unknown') if os_match else 'Unknown'

        ports_open = ports_closed = ports_filtered = 0
        ports = []
        ports_element = host.find('ports')
        if ports_element is not None:
            for port in ports_element.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                if state == 'open':
                    ports_open += 1
                    scan['total_open_ports'] += 1
                elif state == 'closed':
                    ports_closed += 1
                elif state == 'filtered':
                    ports_filtered += 1

                service = port.find('service')
                service_info = (service.get('product', '') + ' ' + service.get('version', '')).strip() if service else None
                http_title = ssl_common_name = ssl_issuer = None
                for script in port.findall('script'):
                    if script.get('id') == 'http-title':
                        http_title = script.get('output')
                    elif script.get('id') == 'ssl-cert':
                        for table in script.findall('table'):
                            if table.get('key') == 'subject':
                                ssl_common_name = table.find("elem[@key='commonName']").text if table.find("elem[@key='commonName']") else None
                            elif table.get('key') == 'issuer':
                                issuer_elems = {elem.get('key'): elem.text for elem in table.findall('elem')}
                                if 'commonName' in issuer_elems:
                                    ssl_issuer = f"{issuer_elems.get('commonName')} {issuer_elems.get('organizationName', '')}".strip()

                if service and service.get('ostype') and os == 'Unknown':
                    os = service.get('ostype')

                ports.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service_name': service.get('name') if service else None,
                    'service_info': service_info,
                    'http_title': http_title,
                    'ssl_common_name': ssl_common_name,
                    'ssl_issuer': ssl_issuer
                })

            extraports = ports_element.find('extraports')
            if extraports:
                extraports_count = int(extraports.get('count', '0'))
                extraports_state = extraports.get('state', '')
                if extraports_state == 'closed':
                    ports_closed += extraports_count
                elif extraports_state == 'filtered':
                    ports_filtered += extraports_count

        host_start_time = host.get('starttime')
        host_end_time = host.get('endtime')
        start_timestamp = int(host_start_time) * 1000 if host_start_time else None
        end_timestamp = int(host_end_time) * 1000 if host_end_time else None

        hosts.append({
            'ip': ip,
            'hostname': hostname,
            'os': os,
            'ports_tested': ports_open + ports_closed + ports_filtered,
            'ports_open': ports_open,
            'ports_closed': ports_closed,
            'ports_filtered': ports_filtered,
            'start_time': start_timestamp,
            'end_time': end_timestamp,
            'ports': ports
        })

    scan['total_hosts'] = len(hosts)

    return scan, hosts

def create_database(db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  nmap_version TEXT,
                  command_line TEXT,
                  start_time INTEGER,
                  elapsed_time TEXT,
                  total_hosts INTEGER,
                  total_open_ports INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS hosts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  ip TEXT,
                  hostname TEXT,
                  os TEXT,
                  ports_tested INTEGER,
                  ports_open INTEGER,
                  ports_closed INTEGER,
                  ports_filtered INTEGER,
                  start_time INTEGER,
                  end_time INTEGER,
                  FOREIGN KEY (scan_id) REFERENCES scans (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS ports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  host_id INTEGER,
                  port TEXT,
                  protocol TEXT,
                  state TEXT,
                  service_name TEXT,
                  service_info TEXT,
                  http_title TEXT,
                  ssl_common_name TEXT,
                  ssl_issuer TEXT,
                  FOREIGN KEY (scan_id) REFERENCES scans (id),
                  FOREIGN KEY (host_id) REFERENCES hosts (id))''')
    conn.commit()
    return conn

def insert_data(conn, scan, hosts):
    with conn:
        c = conn.cursor()
        c.execute("INSERT INTO scans (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_open_ports) VALUES (?, ?, ?, ?, ?, ?)",
                  (scan['nmap_version'], scan['command_line'], scan['start_time'], scan['elapsed_time'], scan['total_hosts'], scan['total_open_ports']))
        scan_id = c.lastrowid
        for host in hosts:
            c.execute("INSERT INTO hosts (scan_id, ip, hostname, os, ports_tested, ports_open, ports_closed, ports_filtered, start_time, end_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (scan_id, host['ip'], host['hostname'], host['os'], host['ports_tested'], host['ports_open'], host['ports_closed'], host['ports_filtered'], host['start_time'], host['end_time']))
            host_id = c.lastrowid
            for port in host['ports']:
                c.execute("INSERT INTO ports (scan_id, host_id, port, protocol, state, service_name, service_info, http_title, ssl_common_name, ssl_issuer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (scan_id, host_id, port['port'], port['protocol'], port['state'], port['service_name'], port['service_info'], port['http_title'], port['ssl_common_name'], port['ssl_issuer']))

def run_nmap(command, output_text):
    output_file = "nmap_output.xml"
    full_command = f"{command} -oX {output_file}" if command.startswith("nmap") or command.startswith("sudo nmap") else f"nmap {command} -oX {output_file}"
    process = subprocess.Popen(full_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output_text.insert(tk.END, "Running command: {}\n".format(full_command), "terminal")
    output_text.see(tk.END)

    while True:
        output = process.stdout.readline().decode()
        if output == '' and process.poll() is not None:
            break
        if output:
            output_text.insert(tk.END, output, "terminal")
            output_text.see(tk.END)

    rc = process.poll()
    if rc != 0:
        raise RuntimeError(f"Failed to run nmap command with exit code {rc}")
    return output_file

def start_scan(command, output_text):
    try:
        xml_file = run_nmap(command, output_text)
        scan, hosts = parse_nmap_xml(xml_file)
        db_name = 'nmap_results.db'
        with create_database(db_name) as conn:
            insert_data(conn, scan, hosts)
        messagebox.showinfo("Success", "Nmap scan completed and data inserted into the database.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def delete_old_scans(db_name, days_old):
    cutoff_date = datetime.now() - timedelta(days=days_old)
    cutoff_timestamp = int(cutoff_date.timestamp()) * 1000

    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''DELETE FROM ports WHERE host_id IN (
                    SELECT id FROM hosts WHERE scan_id IN (
                        SELECT id FROM scans WHERE start_time < ?
                    )
                )''', (cutoff_timestamp,))
    c.execute('''DELETE FROM hosts WHERE scan_id IN (
                    SELECT id FROM scans WHERE start_time < ?
                )''', (cutoff_timestamp,))
    c.execute('''DELETE FROM scans WHERE start_time < ?''', (cutoff_timestamp,))
    conn.commit()
    conn.close()

def add_script(script, listbox):
    if script and script not in listbox.get(0, tk.END):
        listbox.insert(tk.END, script)

def remove_script(listbox):
    selected_indices = listbox.curselection()
    for index in selected_indices[::-1]:
        listbox.delete(index)

def build_command(ip, selected_scripts, scan_type, timing_template, os_detection, version_detection, ping_scan, aggressive_scan, output_options):
    if ip.startswith("nmap ") or ip.startswith("sudo nmap"):
        return ip
    
    command = f"nmap {ip}"
    
    if scan_type.get() != 'None':
        command += f" {scan_type.get().split()[0]}"
    if timing_template.get() != 'None':
        command += f" -T{timing_template.get().split()[0][-1]}"
    if os_detection.get():
        command += " -O"
    if version_detection.get():
        command += " -sV"
    if ping_scan.get():
        command += " -sn"
    if aggressive_scan.get():
        command += " -A"
    if output_options.get() != 'None':
        command += f" {output_options.get().split()[0]}"
    if selected_scripts:
        command += " --script=" + ",".join(selected_scripts)
    
    return command

def paste(event):
    event.widget.event_generate('<<Paste>>')

def main():
    root = tk.Tk()
    root.title("Nmap Scanner")
    root.configure(bg='black')
    root.geometry("1200x900")

    # Add a canvas and scrollbar to the root window
    canvas = tk.Canvas(root, bg='black')
    scrollbar = tk.Scrollbar(root, orient="vertical", command=canvas.yview)
    scrollable_frame = tk.Frame(canvas, bg='black')

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")
        )
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    def on_mouse_wheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    canvas.bind_all("<MouseWheel>", on_mouse_wheel)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def on_scan():
        ip = command_entry.get()
        selected_scripts = listbox_scripts.get(0, tk.END)
        command = build_command(ip, selected_scripts, scan_type_var, timing_template_var, os_detection_var, version_detection_var, ping_scan_var, aggressive_scan_var, output_options_var)
        output_text.insert(tk.END, f"Constructed command: {command}\n", "terminal")
        if command:
            output_text.delete(1.0, tk.END)
            scan_thread = threading.Thread(target=start_scan, args=(command, output_text))
            scan_thread.start()
        else:
            messagebox.showwarning("Input Error", "Please enter an IP address or Nmap command.")

    def on_delete():
        days_old = delete_entry.get()
        if days_old.isdigit():
            delete_old_scans('nmap_results.db', int(days_old))
            messagebox.showinfo("Success", f"Deleted scans older than {days_old} days.")
        else:
            messagebox.showwarning("Input Error", "Please enter a valid number of days.")

    frame_top = tk.Frame(scrollable_frame, bg='black')
    frame_top.pack(pady=10)
    
    tk.Label(frame_top, text="Enter Nmap Command or IP Address:", bg='black', fg='green').pack(side=tk.LEFT)
    command_entry = tk.Entry(frame_top, width=70, bg='black', fg='green', insertbackground='green')
    command_entry.pack(side=tk.LEFT, padx=5)
    command_entry.bind("<Button-3>", paste)
    
    frame_scripts = tk.Frame(scrollable_frame, bg='black')
    frame_scripts.pack(pady=10)
    
    tk.Label(frame_scripts, text="Select Nmap Scripts:", bg='black', fg='green').pack()
    
    script_categories = get_nmap_scripts()
    
    script_combobox_vars = {}
    for category, scripts in script_categories.items():
        frame = tk.Frame(frame_scripts, bg='black')
        frame.pack(pady=5)
        tk.Label(frame, text=category + " Scripts:", bg='black', fg='green').pack(side=tk.LEFT, padx=5)
        combobox_var = tk.StringVar()
        script_combobox_vars[category] = combobox_var
        combobox = ttk.Combobox(frame, textvariable=combobox_var, values=scripts, width=50)
        combobox.pack(side=tk.LEFT)
    
    tk.Button(frame_scripts, text="Add Script", bg='gray', fg='green', command=lambda: add_script(
        script_combobox_vars['Discovery'].get() or script_combobox_vars['Version'].get() or 
        script_combobox_vars['Vulnerability'].get() or script_combobox_vars['Misc'].get(), 
        listbox_scripts)).pack(pady=5)
    
    tk.Label(frame_scripts, text="Selected Nmap Scripts:", bg='black', fg='green').pack()
    listbox_scripts = tk.Listbox(frame_scripts, selectmode=tk.MULTIPLE, width=60, height=5, bg="black", fg="green")
    listbox_scripts.pack(pady=5)
    
    tk.Button(frame_scripts, text="Remove Selected Script", bg='gray', fg='green', command=lambda: remove_script(listbox_scripts)).pack(pady=5)
    
    frame_buttons = tk.Frame(scrollable_frame, bg='black')
    frame_buttons.pack(pady=10)
    
    tk.Button(frame_buttons, text="Start Scan", bg='gray', fg='green', command=on_scan).pack(side=tk.LEFT, padx=10)
    tk.Label(frame_buttons, text="Delete Scans Older Than (days):", bg='black', fg='green').pack(side=tk.LEFT)
    delete_entry = tk.Entry(frame_buttons, width=10, bg='black', fg='green', insertbackground='green')
    delete_entry.pack(side=tk.LEFT, padx=5)
    delete_entry.bind("<Button-3>", paste)
    tk.Button(frame_buttons, text="Delete Old Scans", bg='gray', fg='green', command=on_delete).pack(side=tk.LEFT, padx=10)

    frame_output = tk.Frame(scrollable_frame, bg='black')
    frame_output.pack(pady=10)
    
    tk.Label(frame_output, text="Scan Output:", bg='black', fg='green').pack()
    output_text = scrolledtext.ScrolledText(frame_output, width=130, height=20, bg="black", fg="green", insertbackground="green")
    output_text.pack(pady=5)

    frame_options = tk.Frame(scrollable_frame, bg='black')
    frame_options.pack(pady=10)
    
    tk.Label(frame_options, text="Additional Nmap Options:", bg='black', fg='green').pack(pady=10)
    
    def add_scan_type_option(label_text, option_var, options):
        frame = tk.Frame(frame_options, bg='black')
        frame.pack(pady=5)
        tk.Label(frame, text=label_text, bg='black', fg='green').pack(side=tk.LEFT, padx=5)
        ttk.Combobox(frame, textvariable=option_var, values=options, width=50).pack(side=tk.LEFT)
    
    scan_type_var = tk.StringVar(value='None')
    add_scan_type_option("Scan Type:", scan_type_var, ['None', 'SYN Scan (-sS)', 'TCP Connect Scan (-sT)', 'UDP Scan (-sU)', 'FIN Scan (-sF)', 'XMAS Scan (-sX)', 'Null Scan (-sN)', 'Window Scan (-sW)', 'Maimon Scan (-sM)'])
    
    timing_template_var = tk.StringVar(value='None')
    add_scan_type_option("Timing Template:", timing_template_var, ['None', 'T0', 'T1', 'T2', 'T3', 'T4', 'T5'])
    
    os_detection_var = tk.BooleanVar()
    tk.Checkbutton(frame_options, text="OS Detection (-O)", variable=os_detection_var, onvalue=True, offvalue=False, bg='black', fg='green', selectcolor='black').pack(pady=5)
    
    version_detection_var = tk.BooleanVar()
    tk.Checkbutton(frame_options, text="Version Detection (-sV)", variable=version_detection_var, onvalue=True, offvalue=False, bg='black', fg='green', selectcolor='black').pack(pady=5)
    
    ping_scan_var = tk.BooleanVar()
    tk.Checkbutton(frame_options, text="Ping Scan (-sn)", variable=ping_scan_var, onvalue=True, offvalue=False, bg='black', fg='green', selectcolor='black').pack(pady=5)
    
    aggressive_scan_var = tk.BooleanVar()
    tk.Checkbutton(frame_options, text="Aggressive Scan (-A)", variable=aggressive_scan_var, onvalue=True, offvalue=False, bg='black', fg='green', selectcolor='black').pack(pady=5)
    
    output_options_var = tk.StringVar(value='None')
    add_scan_type_option("Output Options:", output_options_var, ['None', 'Normal output (-oN)', 'XML output (-oX)', 'Grepable output (-oG)', 'Script Kiddie (-oS)', 'All formats (-oA)'])

    root.mainloop()

if __name__ == '__main__':
    main()

