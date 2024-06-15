import os
import time
import shutil
import hashlib
import logging
import argparse


class DirectorySynchronizer:
    def __init__(self, source, replica, interval, log_file):
        self.source = source
        self.replica = replica
        self.interval = int(interval)
        self.log_file = log_file
        self.log_file_exists()
        self.setup_logger()
        self.validate_paths()

    def setup_logger(self):
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[logging.FileHandler(self.log_file),
                                      logging.StreamHandler()])

    def log_file_exists(self):
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        if not os.path.exists(self.log_file):
            open(self.log_file, 'w').close()

    def validate_paths(self):
        def check_permissions(path):
            if not os.path.exists(path):
                raise ValueError(f"Path does not exist: {path}")
            if not os.access(path, os.R_OK):
                raise PermissionError(f"Permission denied: Cannot read from path: {path}")

        def log_permission_issues(path):
            try:
                check_permissions(path)
            except (PermissionError, ValueError) as error:
                logging.error(str(error))

        try:
            check_permissions(self.source)
            check_permissions(self.replica)
            if not os.access(self.replica, os.W_OK):
                raise PermissionError(f"Permission denied: Cannot write to replica path: {self.replica}")

            for root, dirs, files in os.walk(self.source):
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    log_permission_issues(dir_path)
                for file in files:
                    file_path = os.path.join(root, file)
                    log_permission_issues(file_path)

        except (ValueError, PermissionError, OSError) as e:
            logging.error(str(e))
            raise

    @staticmethod
    def md5(file_path):
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
        except IOError as e:
            logging.error(f"Cannot read file {file_path}. Error: {e}")
            return None
        return hash_md5.hexdigest()

    def synchronize_directories(self):
        source_items = set()
        replica_items = set()

        try:
            for root, dirs, files in os.walk(self.source):
                for directory in dirs:
                    dir_path = os.path.join(root, directory)
                    try:
                        os.listdir(dir_path)
                    except PermissionError as e:
                        logging.error(f"Cannot read directory {dir_path}. Error: {e}")
                        dirs.remove(directory)

                for item in dirs + files:
                    source_item_path = os.path.join(root, item)
                    replica_item_path = source_item_path.replace(self.source, self.replica, 1)
                    source_items.add(source_item_path)

                    if os.path.isdir(source_item_path):
                        try:
                            if not os.path.exists(replica_item_path):
                                os.makedirs(replica_item_path)
                                logging.info(f"Created directory: {replica_item_path}")
                        except (PermissionError, OSError) as e:
                            logging.error(f"Cannot create directory {replica_item_path}. Error: {e}")
                    else:
                        try:
                            if os.path.exists(replica_item_path):
                                if self.md5(source_item_path) != self.md5(replica_item_path):
                                    shutil.copy2(source_item_path, replica_item_path)
                                    logging.info(f"Updated file: {replica_item_path}")
                            else:
                                shutil.copy2(source_item_path, replica_item_path)
                                logging.info(f"Copied file: {replica_item_path}")
                        except (IOError, OSError) as e:
                            logging.error(f"Cannot copy file {source_item_path} to {replica_item_path}. Error: {e}")

            for root, dirs, files in os.walk(self.replica):
                for item in dirs + files:
                    replica_item_path = os.path.join(root, item)
                    source_item_path = replica_item_path.replace(self.replica, self.source, 1)
                    replica_items.add(replica_item_path)

                    if source_item_path not in source_items:
                        try:
                            if os.path.isdir(replica_item_path):
                                shutil.rmtree(replica_item_path)
                                logging.info(f"Deleted directory: {replica_item_path}")
                            else:
                                os.remove(replica_item_path)
                                logging.info(f"Deleted file: {replica_item_path}")
                        except (IOError, OSError) as e:
                            logging.error(f"Cannot delete item {replica_item_path}. Error: {e}")

        except Exception as e:
            logging.error(f"Error while synchronizing folders. Error: {e}")

    def run(self):
        logging.info("Starting folder synchronization")
        while True:
            try:
                self.synchronize_directories()
                logging.info(f"Synchro completed. Waiting for {self.interval} seconds before next run.")
                time.sleep(self.interval)
            except (ValueError, PermissionError, OSError) as e:
                logging.error(f"Error occurred during synchro: {e}")
                logging.info("Waiting for retry...")
                time.sleep(self.interval)


def main():
    parser = argparse.ArgumentParser(description='One-way directory synchronization script')
    parser.add_argument('--source', type=str, help='Path to the source directory')
    parser.add_argument('--replica', type=str, help='Path to the replica directory')
    parser.add_argument('--interval', type=int, help='Synchronization interval in sec')
    parser.add_argument('--log_file', type=str, help='Path to the log file')

    args = parser.parse_args()

    default_source = r"C:\Users\juand\PycharmProjects\veeam_synchro\Source"
    default_replica = r"C:\Users\juand\PycharmProjects\veeam_synchro\Replica"
    default_interval = 10
    default_log_file = r"C:\Users\juand\PycharmProjects\veeam_synchro\logfile.log"

    source = args.source or (
        default_source if os.path.exists(default_source) else input(r"Enter the path to the source folder: "))
    replica = args.replica or (
        default_replica if os.path.exists(default_replica) else input(r"Enter the path to the replica folder: "))
    interval = args.interval or (
        default_interval if default_interval else input("Enter the synchronization interval in seconds: "))
    log_file = args.log_file or (default_log_file if os.path.exists(os.path.dirname(default_log_file)) else input(
        r"Enter the path to the log file: "))

    try:
        synchronizer = DirectorySynchronizer(source, replica, interval, log_file)
        synchronizer.run()
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()
