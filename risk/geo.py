"""Optional offline MaxMind lookup. No network, no automatic database download."""
import re


class OfflineGeo:
    def __init__(self, path):
        import maxminddb
        self.reader = maxminddb.open_database(str(path))

    def __call__(self, address):
        data = self.reader.get(address) or {}
        country = (data.get('country') or {}).get('iso_code', '')
        subdivisions = data.get('subdivisions') or []
        if country == 'CN' and subdivisions:
            province = subdivisions[0].get('iso_code', '')
            if re.fullmatch(r'[A-Z0-9]{2}', province):
                return 'CN-' + province
        return country if re.fullmatch(r'[A-Z]{2}', country) else 'UNKNOWN'

    def close(self):
        self.reader.close()
