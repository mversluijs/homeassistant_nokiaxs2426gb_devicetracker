from nokia import Nokia

host = input("Hostname or ip-address of router:\n")
user = input("Router username:\n")
password = input("Router password:\n")

nokia = Nokia(password, host, user)
for i in nokia.get_attached_devices():
    print(i)

print(nokia.get_info().json())