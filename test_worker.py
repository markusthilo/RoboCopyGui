from pathlib import Path
from lib.config import Config
from lib.worker import Copy

#BASE_PATH = Path('C:/Users/THI/Documents/')
BASE_PATH = Path('C:/Users/user/Documents/')
#APP_PATH =  Path('C:/Users/THI/Documents/GitHub/RoboCopyGui')
APP_PATH = Path('P:/RoboCopyGui')

if __name__ == "__main__":
    worker = Copy(
        [BASE_PATH / 'test_dir', BASE_PATH / 'test2_200M'],
        #Path('D:/'),
        Path('F:/'),
        APP_PATH,
        Config(APP_PATH / 'labels.json'),
		tsv_path = BASE_PATH / 'test_tsv.txt',
        log_path = BASE_PATH / 'test_log.txt',
        hashes = ['md5', 'sha256'],
        verify = 'md5',
        #simulate = True
    )
    print('worker.Copy returned:', worker.run())