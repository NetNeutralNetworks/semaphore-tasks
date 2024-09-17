import yaml
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-H","--host", type=str, help="hostname or ip address")
parser.add_argument("-V","--vendor", type=str, help="vendor name")
parser.add_argument("-O","--os", type=str, help="operating system")
parser.add_argument("-u","--username", type=str, help="username")
parser.add_argument("-p","--password", type=str, help="password")
parser.add_argument("-r","--replace", action="store_true")
parser.add_argument("-s","--log_servers", type=str, help="comma seperated list of log servers")
args = parser.parse_args()

if args.vendor == "hp" and args.os == "procurve":
    from nc_mis.drivers.hp.procurve import PROCURVE 
    device = PROCURVE(ip=args.host,
                        username=args.username,
                        password=args.password
                        )

    device_config = device.get_config()
    
    # prep commands
    commands = []
    if args.replace:
        existing_lines = [f"no {line}" for line in device_config.split('\n') if 'logging' in line]
        commands += [i for s in args.log_servers.split(',') for i in existing_lines if s not in i]
        
    commands += [f"logging {s}"for s in args.log_servers.split(',')]
    
    # send commands to device
    result = device.send_config(commands)

    device.write_config()
    
    print("Config changed and saved")
    
else:
    print("Vendor and OS are not specified")
    