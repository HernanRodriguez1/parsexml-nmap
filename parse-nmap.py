import csv
import xml.etree.ElementTree as ET
import subprocess
from colorama import Fore, Style

print(Fore.RED + """\n
  ____                    __  ____  __ _       _   _                        
 |  _ \ __ _ _ __ ___  ___\ \/ /  \/  | |     | \ | |_ __ ___   __ _ _ __   
 | |_) / _` | '__/ __|/ _ \\  /| |\/| | |     |  \| | '_ ` _ \ / _` | '_ \  
 |  __/ (_| | |  \__ \  __//  \| |  | | |___  | |\  | | | | | | (_| | |_) | 
 |_|   \__,_|_|  |___/\___/_/\_\_|  |_|_____| |_| \_|_| |_| |_|\__,_| .__/  
                                                                    |_|     
 :)
Create By: Hernan Rodriguez | Team Offsec Peru \n""" + Style.RESET_ALL)


xml_file = input("Ingrese Archivo XML: ")
ip_ports_dict = {}

tree = ET.parse(xml_file)
root = tree.getroot()

for host in root.findall(".//host"):
    ip = host.find(".//address[@addrtype='ipv4']").attrib["addr"]
    ports = []

    for port in host.findall(".//port"):
        port_number = port.attrib["portid"]
        ports.append(port_number)

    if ip in ip_ports_dict:
        ip_ports_dict[ip].extend(ports)
    else:
        ip_ports_dict[ip] = ports

csv_file = "scan_results.csv"
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(["IP", "Puertos"])

    for ip, ports in ip_ports_dict.items():
        ports_str = ','.join(ports)
        writer.writerow([ip, ports_str])

print(f"Se han guardado los resultados en {csv_file}.")

with open(csv_file, mode='r') as file:
    reader = csv.reader(file)
    next(reader)

    for i, row in enumerate(reader, start=1):
        print(f"{i}: IP: {row[0]}, Puertos: {row[1]}")

selection = input("\nSeleccione el número de la IP que desea escanear: ")

try:
    selection = int(selection)
    if 1 <= selection <= len(ip_ports_dict):
        selected_ip = list(ip_ports_dict.keys())[selection - 1]
    else:
        selected_ip = None
except ValueError:
    selected_ip = None

if selected_ip:
    ports_str = ','.join(ip_ports_dict[selected_ip])
    nmap_args = ["nmap", "--scan-delay", "5s", "-n", "-Pn", "-sV", "-vvv"]

    nmap_args.extend([selected_ip, "-p", ports_str])

    print(Fore.RED + "\n Seleccione el tipo de escaneo y filtro:")
    print("1-) Port(SYN) Scan (-sS): Escaneo de puertos TCP utilizando paquetes SYN. Útil para descubrir servicios sin ser intrusivo.")
    print("2-) Port(TCP) Scan (-sT): Escaneo de puertos TCP utilizando conexiones completas. Útil para escaneo sigiloso, pero más lento.")
    print("3-) Port(UDP) Scan (-sU): Escaneo de puertos UDP para servicios menos comunes. Puede ser lento y menos confiable.")
    print("4-) Null scan (-sN): Escaneo nulo que no establece banderas en el paquete. Útil para evadir ciertas defensas de firewall.")
    print("5-) FIN scan (-sF): Escaneo que establece la bandera FIN en el paquete. Útil para evadir ciertas defensas de firewall.")
    print("6-) OS Analysis and Version Discovery (-O -sV): Detecta el sistema operativo y la versión del servicio. Útil para obtener información detallada.")
    print("7-) Nmap Script Engineering (default): Ejecuta los scripts de Nmap predeterminados para detectar vulnerabilidades y servicios adicionales.")
    print("8-) Firewall Bypass (--script=firewall-bypass): Ejecuta un script de Nmap para intentar eludir firewalls.")
    print("9-) Script Bypass (--script=firewall-bypass): Ejecuta un script de Nmap para intentar eludir firewalls.")
    print("10-) Data Length (--data-length <number>): Especifica la longitud de datos personalizada en paquetes. Puede confundir a IDS/IPS.")
    print("11-) Smash (-ff): Fragmenta paquetes para evadir la detección de IDS/IPS.")
    print("12-) ACK scan (-sA): Escaneo ACK que verifica si los puertos están abiertos o filtrados por un firewall.")
    print("13-) Xmas Tree scan (-sX): Escaneo Xmas Tree que establece múltiples banderas en el paquete. Útil para evadir defensas de firewall.")
    print("14-) ICMP Echo scan (-PE): Escaneo ICMP Echo Request para descubrir hosts activos.")
    print("15-) UDP scan (-sU): Escaneo de puertos UDP para servicios menos comunes. Puede ser lento y menos confiable.")
    print("16-) IP Protocol scan (-sO): Escaneo de protocolos IP utilizados en la red.")
    print("17-) RPC scan (-sR): Escaneo de RPC (Remote Procedure Call) para descubrir servicios RPC.")
    print("18-) IDLE scan (-sI): Escaneo IDLE que utiliza la técnica de un host zombie para eludir la detección.")
    print("19-) FTP Bounce scan (-b): Escaneo de rebote FTP que utiliza servidores FTP para realizar escaneos indirectos.")
    print("20-) ICMP Timestamp scan (-D): Escaneo ICMP Timestamp que utiliza paquetes ICMP para obtener información de tiempo de respuesta de los hosts y evadir algunas defensas de firewall."+ Style.RESET_ALL)	

    scan_type = input("\nIngrese el número correspondiente: ")

    if scan_type == "1":
        nmap_args.extend(["-sS"])
    elif scan_type == "2":
        nmap_args.extend(["-sT"])
    elif scan_type == "3":
        nmap_args.extend(["-sU"])
    elif scan_type == "4":
        nmap_args.extend(["-sN"])
    elif scan_type == "5":
        nmap_args.extend(["-sF"])
    elif scan_type == "6":
        nmap_args.extend(["-O", "-sV"])
    elif scan_type == "7":
        pass
    elif scan_type == "8":
        nmap_args.extend(["--script=firewall-bypass"])
    elif scan_type == "9":
        nmap_args.extend(["--script=firewall-bypass"])
    elif scan_type == "10":
        data_length = input("Ingrese la longitud de datos deseada: ")
        nmap_args.extend(["--data-length", data_length])
    elif scan_type == "11":
        nmap_args.extend(["-ff"])
    elif scan_type == "12":
        nmap_args.extend(["-sA"])
    elif scan_type == "13":
        nmap_args.extend(["-sX"])
    elif scan_type == "14":
        nmap_args.extend(["-PE"])
    elif scan_type == "15":
        nmap_args.extend(["-sU"])
    elif scan_type == "16":
        nmap_args.extend(["-sO"])
    elif scan_type == "17":
        nmap_args.extend(["-sR"])
    elif scan_type == "18":
        zombie_ip = input("Ingrese la dirección IP del host zombie: ")
        nmap_args.extend(["-sI", zombie_ip])
    elif scan_type == "19":
        nmap_args.extend(["-b"])
    elif scan_type == "20":
        nmap_args.extend(["-D"])
    else:
        print("Selección no válida.")

    print("\nEjecutando Nmap con los siguientes argumentos:")
    print(" ".join(nmap_args))
    try:
        result = subprocess.check_output(nmap_args)
        print(result.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar Nmap: {e}")
else:
    print("Selección no válida. Por favor, seleccione un número de IP válido.")
