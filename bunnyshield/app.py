# IMPORTS
if __name__ == "__main__":
    import os
    import psutil
    from colorama import init
    from pyfiglet import Figlet
    from termcolor import colored
    from software.app.audit import Audit
    from software.tools.logger import logger
    import software.app.monitor as FileMonitor
    import software.app.honeypot_generator as HoneypotGenerator
    from software.config.shared_config import GeneralConfig as gc

    # SET PRIORITY
    psutil.Process(gc.PID).nice(19)

    # DEFINE GENERAL CONFIG

    # START
    init()
    f = Figlet(font='slant')
    print(colored(f.renderText('BunnyShield'), 'red'))
    print(colored('--- A Ransomware Detector by Bash Bunny Group ---\n\n', 'red'))
    logger.debug("Starting BunnyShield Protection")

    # AUDIT
    Audit().setStatus("on")

    # HONEYPOT GENERATOR
    if not gc.skip_to_monitor:
        logger.debug("Starting Honeypot Generator")
        HoneypotGenerator.start()

    # FILE MONITOR
    if not gc.delete_honeypots:
        logger.debug("Starting Monitor")
        FileMonitor.start()
    else:
        quit()

    # QUIT
    logger.debug("Quitting Ransomware Detector")
    pass
else:
    pass
