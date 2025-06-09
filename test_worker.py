from pathlib import Path
from classes_robo import Config
from worker import Copy

#BASE_PATH = Path('C:/Users/THI/Documents/')
BASE_PATH = Path('P:/')
#APP_PATH =  Path('C:/Users/THI/Documents/GitHub/RoboCopyGui'

if __name__ == "__main__":
    worker = Copy(
        [BASE_PATH / 'test_dir', BASE_PATH / 'test1'],
        Path('F:/'),
        simulate = False
    )
    print('worker.Copy returned:', worker.run())
    