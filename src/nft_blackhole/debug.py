
from datetime import datetime
from pathlib import Path

def save_resolved_ips(ip_list: list[str]):
	dt = datetime.now()
	mod_path = Path(__file__).resolve()
	print(f'\n\nMOD PATH:{mod_path}\n\n')
	file_path = Path(f'{mod_path}/../../debug/{dt.strftime('%Y-%m-%d_%H%M%S_resolved_ips.text')}').resolve()
	
	with open(file_path, 'w') as file_handle:
		for ip_address in ip_list:
			_ = file_handle.write(f'{ip_address}\n')
