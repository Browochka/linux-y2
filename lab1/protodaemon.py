import os
import shutil
import datetime as dt
import configparser
import logging
import time
import signal
import daemon

# Функция для чтения конфигурации
def read_config():
    config = configparser.ConfigParser()
    config.read('/home/vboxuser/homework/daemon1/CONFIG.ini')
    settings = config['Settings']
    return settings

# Функция для резервного копирования файлов
def reserving_files(source, reserve):
    current_time = dt.datetime.now().strftime('%d.%m.%Y_%H:%M:%S')
    backup_name = f'backup_{current_time}'
    route = os.path.join(reserve, backup_name)
    
    try:
        shutil.copytree(source, route, symlinks=True)
        logging.info('Files copied successfully')
    except Exception as e:  # Исправление: использование Exception
        logging.error(f'MISTAKE: {e}')
        
        
# Функция для записи PID в файл
def write_pidfile(pidfile):
    with open(pidfile, 'w') as f:
        f.write(str(os.getpid()))
        
        
# Функция для запуска демона
def run_daemon(config):
    logging.basicConfig(level=logging.INFO, 
                        filename=config['log'], 
                        format='(%(asctime)s): %(message)s', 
                        datefmt='%d.%m.%Y_%H:%M:%S')
    logging.info('Daemon is running')
    
    while True:
        reserving_files(config['source'], config['reserve'])
        time.sleep(int(config['delay']))
        


def create_daemon():
    
    config = read_config()
    
    with daemon.DaemonContext(
        pidfile=open(config['pidfile'], 'w+'),
        detach_process=True
    ):
        write_pidfile(config['pidfile'])  
        run_daemon(config)
        
        
def kill_daemon():
    config = read_config()
    logging.basicConfig(level=logging.INFO, 
                        filename=config['log'], 
                        format='(%(asctime)s): %(message)s', 
                        datefmt='%d.%m.%Y_%H:%M:%S')
    
    
    pidfile = config['pidfile']
    if os.path.exists(pidfile):
        with open(pidfile, 'r') as p:
            pid = int(p.read().strip())
            os.kill(pid, signal.SIGTERM)
        os.remove(pidfile)
        logging.info('Daemon is complete')
    else:
        print("PID file does not exist. Daemon is not running.")


        



