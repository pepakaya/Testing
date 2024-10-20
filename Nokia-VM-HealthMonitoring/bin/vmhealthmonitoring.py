# ==============================================================================
# Script Name: health_monitoring.py
# Purpose: Health Monitoring Script for VM - Monitors RAM, Disk, CPU, and User Password Expiry


import sys
import os
import socket
import calendar
from datetime import datetime, timezone, date
import logging
from logging.handlers import TimedRotatingFileHandler
from logging import Formatter
import configparser

# Add configuration path for the health monitoring system
sys.path.append("/opt/PC/Nokia-VM-HealthMonitoring/conf/")
config = configparser.ConfigParser()
config.read('/opt/PC/Nokia-VM-HealthMonitoring/conf/healthmonitoring_config.ini')


class HealthMonitor:
    """
    HealthMonitor class for monitoring system resources such as RAM, disk, CPU, and user expiry information.

    Attributes:
        logFile: Name of the log file.
        agent_logFile: Name of the agent log file.
    """

    def __init__(self, logFile, agent_logFile):
        self.logFile = logFile
        self.agent_logFile = agent_logFile

        # Creating log directory if it does not exist
        try:
            if not os.path.exists(config['DIRECTORIES']['LOG_DIR']):
                os.makedirs(config['DIRECTORIES']['LOG_DIR'])

            # Creating agent log directory if it does not exist
            if not os.path.exists(config['DIRECTORIES']['AGENT_LOG_DIR']):
                os.makedirs(config['DIRECTORIES']['AGENT_LOG_DIR'])
        except Exception as e:
            logging.error(f"Error creating log directories: {str(e)}")

        LOG_FORMAT = "%(asctime)s [%(levelname)s]: %(message)s in %(pathname)s:%(lineno)d"
        LOG_LEVEL = logging.INFO

        # Setting up logger for main log file
        self.logger = logging.getLogger("Rotating Log1")
        self.logger.setLevel(LOG_LEVEL)
        handler = TimedRotatingFileHandler(
            config['DIRECTORIES']['LOG_DIR'] + logFile,
            when=config['LOG ROTATION ATTRIBUTES']['when'],
            interval=int(config['LOG ROTATION ATTRIBUTES']['interval']),
            backupCount=int(config['LOG ROTATION ATTRIBUTES']['backupCount'])
        )
        handler.setLevel(LOG_LEVEL)
        handler.setFormatter(Formatter(LOG_FORMAT))
        self.logger.addHandler(handler)

        # Setting up logger for agent log file
        self.agent_logger = logging.getLogger("Rotating Log2")
        self.agent_logger.setLevel(LOG_LEVEL)
        agent_log_handler = TimedRotatingFileHandler(
            config['DIRECTORIES']['AGENT_LOG_DIR'] + agent_logFile,
            when='m', interval=1,
            backupCount=int(config['LOG ROTATION ATTRIBUTES']['backupCount'])
        )
        self.agent_logger.addHandler(agent_log_handler)

    def ram_info(self):
        """Fetches virtual memory/RAM statistics and returns a dictionary."""
        try:
            self.mem_info_cmd = config['LINUX COMMANDS']['RAM_Info_cmd']
            mem_info_cmd_output = os.popen(self.mem_info_cmd).readlines()
            ram_stats = {'type': 'RAM Statistics', 'time_stamp': datetime.now().ctime()}
            for att, val in zip(mem_info_cmd_output[0].split(), mem_info_cmd_output[1].split()[1:]):
                ram_stats[att] = int(val)

            # Calculate percentage of RAM used
            ram_stats['Use%'] = int(
                round(((ram_stats['total'] - ram_stats['available']) / ram_stats['total']) * 100, 2))

            return ram_stats
        except Exception as e:
            self.logger.error(f"Error fetching RAM info: {str(e)}")
            return None

    def disk_info(self, path):
        """Fetches disk usage statistics and returns a dictionary."""
        try:
            self.disk_info_cmd = config['LINUX COMMANDS']['Disk_Info_cmd'] + ' %s' % (path)
            disk_info_cmd_output = os.popen(self.disk_info_cmd).readlines()
            disk_stats = {'type': 'Disk Statistics', 'time_stamp': datetime.now().ctime()}
            for att, val in zip(disk_info_cmd_output[0].split()[:-1], disk_info_cmd_output[1].split()):
                disk_stats[att] = val

            return disk_stats
        except Exception as e:
            self.logger.error(f"Error fetching disk info for path {path}: {str(e)}")
            return None

    def cpu_info(self):
        """Fetches CPU usage statistics and returns a dictionary."""
        try:
            self.cpu_info_cmd = config['LINUX COMMANDS']['CPU_Info_cmd']
            cpu_info_cmd_output = os.popen(self.cpu_info_cmd).readlines()
            cpu_stats = {'type': 'CPU Statistics', 'time_stamp': datetime.now().ctime()}
            for att, val in zip(cpu_info_cmd_output[2].split()[3:], cpu_info_cmd_output[3].split()[3:]):
                cpu_stats[att] = float(val)

            # Calculate CPU usage percentage
            cpu_stats['Use%'] = round((100 - cpu_stats['%idle']), 2)

            return cpu_stats
        except Exception as e:
            self.logger.error(f"Error fetching CPU info: {str(e)}")
            return None

    def user_password_expiry_info(self):
        """Calculates number of days remaining for password expiry for each user in the VM and returns a dictionary."""
        month_map = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5,
            'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9,
            'Oct': 10, 'Nov': 11, 'Dec': 12
        }  # Dictionary to map month names into numbers
        self.expiring_info = {}

        try:
            all_users = os.popen(config['LINUX COMMANDS']['Users_list_cmd']).read().split('\n')[
                        :-1]  # Listing all available users

            # Calculating expiry time for each user
            for user in all_users:
                chage_cmd_output = os.popen('chage -l %s' % (user)).read().split('\n')[1].split(':')[1].strip().replace(
                    ',', '').split(' ')
                if chage_cmd_output[0] == 'never':
                    self.expiring_info[user] = 9999  # Password never expires
                else:
                    expiry_date = date(int(chage_cmd_output[2]), month_map[chage_cmd_output[0]],
                                       int(chage_cmd_output[1]))
                    today = date.today()
                    expiring_in = str(expiry_date - today).split(',')[0].split(' ')[0]
                    self.expiring_info[user] = expiring_in

            return self.expiring_info
        except Exception as e:
            self.logger.error(f"Error fetching user expiry info: {str(e)}")
            return None

    def generate_alarms(self, alarm_type, percentage, time_stamp, additional_text):
        """Generates a warning alarm message (based on severity) for a given alarm type and writes the message into the log file."""
        hostname = socket.gethostname()
        if percentage > int(config['THRESHOLDS']['critical_threshold']):
            severity = 'CRITICAL'
            alarm_num = config[alarm_type]['CRITICAL']
            log_text = f"{time_stamp} {hostname}$ {alarm_type} - {severity} - {alarm_type} Threshold is > 90%$ {alarm_num} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text)

            log_text1 = f"{time_stamp} {hostname}$ {alarm_type} - MAJOR - {alarm_type} Threshold is optimal$ {config[alarm_type]['MAJOR']} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text1)

        elif percentage <= int(config['THRESHOLDS']['critical_threshold']) and percentage > int(
                config['THRESHOLDS']['major_threshold']):
            severity = 'MAJOR'
            alarm_num = config[alarm_type]['MAJOR']
            log_text = f"{time_stamp} {hostname}$ {alarm_type} - {severity} - {alarm_type} Threshold is > 80%$ {alarm_num} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text)

            log_text1 = f"{time_stamp} {hostname}$ {alarm_type} - CRITICAL - {alarm_type} Threshold is optimal$ {config[alarm_type]['CRITICAL']} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text1)

            log_text2 = f"{time_stamp} {hostname}$ {alarm_type} - MINOR - {alarm_type} Threshold is optimal$ {config[alarm_type]['MINOR']} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text2)

        elif percentage <= int(config['THRESHOLDS']['major_threshold']) and percentage > int(
                config['THRESHOLDS']['minor_threshold']):
            severity = 'MINOR'
            alarm_num = config[alarm_type]['MINOR']
            log_text = f"{time_stamp} {hostname}$ {alarm_type} - {severity} - {alarm_type} Threshold is > 70%$ {alarm_num} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text)

            log_text1 = f"{time_stamp} {hostname}$ {alarm_type} - MAJOR - {alarm_type} Threshold is optimal$ {config[alarm_type]['MAJOR']} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text1)

            log_text2 = f"{time_stamp} {hostname}$ {alarm_type} - CRITICAL - {alarm_type} Threshold is optimal$ {config[alarm_type]['CRITICAL']} $ {alarm_type} Current Percentage is {percentage} {additional_text}"
            self.agent_logger.info(log_text2)

    def generate_user_password_expiry_alarm(self, alarm_type, username, expiring_in, additional_text):
        """Generates a user password expiry warning alarm message based on the severity level."""
        time_stamp = datetime.now().ctime()

        if expiring_in <= int(config['THRESHOLDS']['password_expiry_critical_threshold']):
            severity = 'CRITICAL'
            alarm_num = config[alarm_type]['CRITICAL']
            log_text = f"{time_stamp} {hostname}$ {alarm_type} - {severity} - User Password is set to expire in the next {config['THRESHOLDS']['password_expiry_critical_threshold']} days$ {alarm_num} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text)

            log_text1 = f"{time_stamp} {hostname}$ {alarm_type} - MAJOR - User Password is expiring time is optimal$ {config[alarm_type]['MAJOR']} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text1)

            log_text2 = f"{time_stamp} {hostname}$ {alarm_type} - MINOR - User Password is expiring time is optimal$ {config[alarm_type]['MINOR']} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text2)

        elif expiring_in <= int(config['THRESHOLDS']['password_expiry_major_threshold']):
            severity = 'MAJOR'
            alarm_num = config[alarm_type]['MAJOR']
            log_text = f"{time_stamp} {hostname}$ {alarm_type} - {severity} - User Password is set to expire in the next {config['THRESHOLDS']['password_expiry_major_threshold']} days$ {alarm_num} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text)

            log_text1 = f"{time_stamp} {hostname}$ {alarm_type} - CRITICAL - User Password is expiring time is optimal$ {config[alarm_type]['CRITICAL']} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text1)

            log_text2 = f"{time_stamp} {hostname}$ {alarm_type} - MINOR - User Password is expiring time is optimal$ {config[alarm_type]['MINOR']} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text2)

        elif expiring_in <= int(config['THRESHOLDS']['password_expiry_minor_threshold']):
            severity = 'MINOR'
            alarm_num = config[alarm_type]['MINOR']
            log_text = f"{time_stamp} {hostname}$ {alarm_type} - {severity} - User Password is set to expire in the next {config['THRESHOLDS']['password_expiry_minor_threshold']} days$ {alarm_num} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text)

            log_text1 = f"{time_stamp} {hostname}$ {alarm_type} - MAJOR - User Password is expiring time is optimal$ {config[alarm_type]['MAJOR']} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text1)

            log_text2 = f"{time_stamp} {hostname}$ {alarm_type} - CRITICAL - User Password is expiring time is optimal$ {config[alarm_type]['CRITICAL']} $ {username} Password is set to expire in the next {expiring_in} days {additional_text}"
            self.agent_logger.info(log_text2)

    def monitor(self):
        """Main method to monitor health metrics and log alarms."""
        self.logger.info("Health Monitoring Scripts execution Started")
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        additional_text = f' for the VM - {hostname}:{ip_address}'

        try:
            ram_stats = self.ram_info()
            if ram_stats:
                self.generate_alarms('RAM Usage', ram_stats['Use%'], ram_stats['time_stamp'], additional_text)

            for volume_path in config['DISK USAGE PATHS']['disk_usage_paths'].split(','):
                disk_stats = self.disk_info(volume_path)
                if disk_stats:
                    self.generate_alarms('DISK Usage', int(disk_stats['Use%'][:-1]), disk_stats['time_stamp'],
                                         f" for {volume_path}. {additional_text}")

            cpu_stats = self.cpu_info()
            if cpu_stats:
                self.generate_alarms('CPU Usage', cpu_stats['Use%'], cpu_stats['time_stamp'], additional_text)

            password_expiry_info = self.user_password_expiry_info()
            if password_expiry_info:
                for user, expiring_in in password_expiry_info.items():
                    self.generate_user_password_expiry_alarm('User Password Expiry', user, int(expiring_in),
                                                             additional_text)

        except Exception as e:
            self.logger.error(f"Monitoring error: {str(e)}")

        else:
            self.logger.info("Finished. Check Agent log for more info : %s" % (
                        config['DIRECTORIES']['AGENT_LOG_DIR'] + self.agent_logFile))


# Instantiate and run the HealthMonitor
health_monitor =  HealthMonitor('VMHealthMonitoring.log', 'VMHealthMonitoring-alarmLog')
health_monitor.monitor()
