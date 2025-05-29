from pathlib import Path
from lib.config import Config
from lib.worker import Copy

if __name__ == "__main__":
    worker = Copy(
        [Path('P:/')],
        Path('F:/'),
        Path('P:/RoboCopyGui'),
        Config(Path('P:/RobocopyGui/labels.json')),
		tsv_path = Path('C:/Users/user/Documents/test_tsv.txt'),
        log_path = Path('C:/Users/user/Documents/test_log.txt'),
        hashes = None,
        verify = None, 
        #simulate = True
    )
    print('worker.Copy returned:', worker.run())