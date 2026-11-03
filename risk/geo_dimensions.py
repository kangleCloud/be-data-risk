"""Wire shape validation only; geographic verification remains Java-owned."""
import re
import unicodedata


def valid_geo_name(value):
    return (isinstance(value, str) and len(value) <= 512
            and unicodedata.normalize('NFC', value) == value
            and not any(unicodedata.category(c) in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp'} for c in value))


def valid_geo_dimensions(dimensions):
    country, province, city = (dimensions[k] for k in ('countryCode', 'provinceCode', 'cityCode'))
    province_name, city_name = (dimensions[k] for k in ('provinceName', 'cityName'))
    if not all(isinstance(v, str) for v in (country, province, city, province_name, city_name)):
        return False
    if not re.fullmatch(r'(?:[A-Z]{2})?', country) or not re.fullmatch(r'(?:[A-Z]{2}-[A-Z0-9-]{1,16})?', province) or not re.fullmatch(r'(?:[0-9]{6})?', city):
        return False
    if province and not province.startswith(country + '-'):
        return False
    if bool(city) != bool(city_name):
        return False
    if city and (country != 'CN' or not re.fullmatch(r'CN-[0-9]{2}', province)):
        return False
    if dimensions['locationLevel'] == 'CITY' and not city:
        return False
    if country != 'CN' and (city or city_name):
        return False
    return valid_geo_name(province_name) and valid_geo_name(city_name)
