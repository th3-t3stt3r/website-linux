# IMPORTS
if __name__ == "__main__":
    import os
    import psutil
    from pyfiglet import Figlet
    from colorama import init
    from termcolor import colored
    from software.config.shared_config import GeneralConfig as gc
    from software.app.audit import Audit
    from software.app.honeypot_generator import HoneypotGenerator
    from software.app.monitor import FileMonitor
    from software.tools.logger import logger

    # SET PRIORITY
    psutil.Process(os.getpid()).nice(19)

    # DEFINE GENERAL CONFIG

    # START
    init()
    f = Figlet(font='slant')
    print(colored(f.renderText('CapyShield'), 'red'))
    print(colored('--- A Ransomware Detector by Bash Bunny Group ---\n\n', 'red'))
    logger.debug("Starting Ransomware Detector")

    # AUDIT OBJ
    Audit().setStatus("on")

    # HONEYPOT GENERATOR OBJ
    if not gc.skip_to_monitor:
        hg = HoneypotGenerator()
        hg.run()

    # FILE MONITOR OBJ
    if not gc.delete_honeypots:
        fm = FileMonitor()
        fm.run()
    else:
        quit()

    # QUIT
    logger.debug("Quitting Ransomware Detector")
    pass
else:
    pass
