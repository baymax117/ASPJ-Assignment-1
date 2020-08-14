import datetime
import time
import os


# create a log with name, address, and status of whether login was successful
def create_log(name, address, status):
    current_time = datetime.datetime.now()
    timestamp = "{}-{:02d}-{:02d} {:02d}:{:02d}".format(current_time.day, current_time.month, current_time.year, current_time.hour, current_time.minute)
    return "{} {} {} {}\n".format(timestamp, address, name, status)


# write the log into the log file.
def write_log(log, location):
    updating = True
    while updating:
        try:
            log_file = open(location, 'a')
            log_file.write(log)
            log_file.close()
            updating = False
        except IOError:
            time.sleep(1)


# update the log
# If the date file has not been created, it will create the file
def update_log(log):
    date = log.split()[0]
    location = 'log/{}.log'.format(date)
    if os.path.exists(location):
        write_log(log, location)
    else:
        file = open(location, 'w')
        file.close()
        write_log(log, location)


# retrieve all the access logs
def get_log():
    log_list = os.listdir('log')
    logs = []
    for log in log_list:
        log = open('log/{}'.format(log))
        raw_logs = log.readlines()
        for raw_log in raw_logs:
            processed_log = raw_log.strip('\n')
            processed_log = processed_log.split()
            logs.insert(0, processed_log)
        log.close()

    return logs

get_log()