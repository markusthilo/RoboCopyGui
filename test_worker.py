from pathlib import Path
from lib.config import Config
from lib.worker import Copy

if __name__ == "__main__":
    worker = Copy(
        [Path('C:/Users/THI/Documents/IPED-4.2.0')],
        Path('D:/'),
        Path('C:/Users/THI/Documents/GitHub/RoboCopyGui'),
        Config(Path('C:/Users/THI/Documents/GitHub/RobocopyGui/labels.json')),
		tsv_path = Path('C:/Users/THI/Documents/test_tsv.txt'),
        log_path = Path('C:/Users/THI/Documents/test_log.txt'),
        hashes = None,
        verify = None, 
        simulate = True
    )
    print('worker.Copy returned:', worker.run())