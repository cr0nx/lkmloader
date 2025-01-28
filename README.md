# lkmloader
A simple Linux LKM loader capable of in-memory kernel module loading from HTTP/HTTPS

Features:
- Loads kernel modules from local files using two methods (init_module and finit_module)
- Loads modules in memory from HTTP/HTTPS URLs
- Unloads modules by name or memory address
- Supports SSL/TLS for secure downloads

How to use it:
- Load module (finit_module): ./lkmloader -l <path_to_module.ko>
- Load module (init_module):  ./lkmloader -i <path_to_module.ko>
- Load module from HTTP(S):   ./lkmloader -h https://example.com/module.ko
- Unload module by name:      ./lkmloader -u <module_name>
- Unload module by address:   ./lkmloader -a 0xffffffffc0000000

This is just another attempt to use AI engines to achieve an offensive goal in a Linux environment quickly.
It's also a part of the ongoing research within the scope of the "Linux Attack, Detection, and Live Forensics" course => https://edu.defensive-security.com/linux-attack-live-forensics-at-scale and EDRmetry - Effective Linux EDR/SIEM Evaluation Testing Playbook => https://edu.defensive-security.com/edrmetry-effective-linux-edr-xdr-evaluation-testing-playbook 
