from time import sleep
import time
import psutil
from os import system


#process = psutil.Process(2006287).io_counters()
#process = psutil.Process(2006287).cmdline()
#process = psutil.Process(2006180).is_running()
#process = psutil.Process(2006180).create_time()
#process = psutil.Process(2006180).nice()
#process = psutil.Process(2315363).memory_full_info()
#process = psutil.Process(2315363).ionice()
#process = psutil.Process(2463529).num_threads()
#process = psutil.Process(2611741).rlimit()
print(psutil.Process(1279175).status())
quit()
startbytes = psutil.Process(250356).io_counters()
start = time.perf_counter()
for i in range(1, 21):
    if i == 20:
        secs = psutil.Process(250356).io_counters()

    process = psutil.Process(250356).io_counters()
    print(startbytes)
    print(process)
    print(i / 2)
    sleep(0.5)
    system('clear')
end = time.perf_counter()
print(f"Took {round(end - start,3)}")
print(startbytes)
print(process)
print(secs)

# cryptocapy = 24mi bytes em 10s
