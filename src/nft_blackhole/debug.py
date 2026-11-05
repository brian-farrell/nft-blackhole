
from datetime import datetime
from pathlib import Path

from .logger import logger

def save_debug_file(file_name: str | Path, file_data: str):
	dt = datetime.now()
	mod_path = Path(__file__).resolve()
	file_path = Path(
	    f"{mod_path}/../../debug/{dt.strftime('%Y-%m-%d_%H%M%S')}_{file_name}"
	).resolve()
	_ = logger.debug(f'Saving DEBUG file to: {file_path}')  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType, reportAttributeAccessIssue]

	with open(file_path, 'w') as file_handle:
	    _ = file_handle.write(file_data)
