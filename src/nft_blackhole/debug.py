
from datetime import datetime
from pathlib import Path

from nft_blackhole import Absent
from nft_blackhole.config import Config

def save_resolved_ips(config: Config | Absent):
	dt = datetime.now()
	mod_path = Path(__file__).resolve()
	print(f'\n\nMOD PATH:{mod_path}\n\n')

	for address_list in config.active_address_lists:
		list_type = address_list.list_type
		for ip_version in config.active_ip_versions:
			file_path = Path(
				f"{mod_path}/../../debug/{dt.strftime('%Y-%m-%d_%H%M%S')}_{list_type}_nft_set_{ip_version}.text"
			).resolve()

			_data = address_list.nft_sets.get(ip_version)
			
			if _data:
				with open(file_path, 'w') as file_handle:
					for ip_address in _data:
						_ = file_handle.write(f'{ip_address}\n')
