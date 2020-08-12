import datetime
import time


def create_log(name, address):
    current_time = datetime.datetime.now()
    timestamp = "{}-{}-{} {}:{}".format(current_time.day, current_time.month, current_time.year, current_time.hour, current_time.minute)
    return "{} {} {}".format(timestamp, address, name)


def update_log(log, location):
    updating = True
    while updating:
        try:
            log_file = open(location, 'a')
            log_file.write(log)
            log_file.close()
            updating = False
        except IOError:
            time.sleep(1)



