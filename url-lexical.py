from whois import whois
from waybackpy import Cdx
from socket import gethostbyname
from shodan import Shodan
from requests import get
from urllib.parse import urlparse
from datetime import datetime
from re import compile
from json import dump, loads
from time import sleep

cache = []

with open('data/output/hostfeatures.json', 'r+') as ff:
    data = [loads(i) for i in ff.readlines()]
    seen = [i['host'] for i in data]
    for i in seen:
        print('Caching {}'.format(i))
        cache.append(i)

class HostFeatures:
    def __init__(self, url):
        self.url = url
        self.urlparse = urlparse(self.url)
        self.host = self.__get_ip()
        self.now = datetime.now()
        self.init_sub_params = self.initialise_sub_parameters()

    def initialise_sub_parameters(self):
        if self.host not in cache:
            self.whois = self.__get__whois_dict()
            self.shodan = self.__get_shodan_dict()
            self.snapshots = self.__get_site_snapshots()
            return True
        else:
            return False

    def __get_ip(self):
        try:
            ip = self.urlparse.netloc if self.url_host_is_ip() else gethostbyname(self.urlparse.netloc)
            return ip
        except:
            return None

    def __get__whois_dict(self):
        try:
            whois_dict = whois(self.host)
            return whois_dict
        except:
            return {}

    def __get_shodan_dict(self):
        api = Shodan('W6cy1PGcje0jJwKDBTgrqWSZioRpRmzg')
        try:
            host = api.host(self.host)
            return host
        except:
            return {}

    def __parse__before__date(self, date_string):
        month_year = date_string.split()[-1]
        d = '01-{}'.format(month_year)
        d = datetime.strptime(d, '%d-%b-%Y')
        return d

    def __parse_whois_date(self, date_key):
        cdate = self.whois.get(date_key, None)
        if cdate:
            if isinstance(cdate, str) and 'before' in cdate:
                d = self.__parse__before__date(cdate)
            elif isinstance(cdate, list):
                d = cdate[0]
            else:
                d = cdate
        return d if cdate else cdate

    def __get_site_snapshots(self):
        try:
            snapshots = Cdx(self.urlparse.netloc).snapshots()
            snapshots = [snapshot.datetime_timestamp for snapshot in snapshots]
            return snapshots
        except:
            return []

    def url_host_is_ip(self):
        host = self.urlparse.netloc
        pattern = compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        match = pattern.match(host)
        return match is not None

    def number_of_subdomains(self):
        ln1 = self.whois.get('nets', None)
        ln2 = self.shodan.get('domains', None)
        ln = ln1 or ln2
        return len(ln) if ln else None

    def url_creation_date(self):
        d = self.__parse_whois_date('creation_date')
        return d

    def url_expiration_date(self):
        d = self.__parse_whois_date('expiration_date')
        return d

    def url_last_updated(self):
        d = self.__parse_whois_date('updated_date')
        return d

    def url_age(self):
        try:
            days = (self.now - self.url_creation_date()).days
        except:
            days = None
        return days

    def url_intended_life_span(self):
        try:
            lifespan = (self.url_expiration_date() - self.url_creation_date()).days
        except:
            lifespan = None
        return lifespan

    def url_life_remaining(self):
        try:
            rem = (self.url_expiration_date() - self.now).days
        except:
            rem = None
        return rem

    def url_registrar(self):
        return self.whois.get('registrar', None)

    def url_registration_country(self):
        c = self.whois.get('country', None)
        return c

    def url_host_country(self):
        c = self.shodan.get('country_name', None)
        return c

    def url_open_ports(self):
        ports = self.shodan.get('ports', '')
        return ports if ports != '' else None

    def url_num_open_ports(self):
        ports = self.url_open_ports()
        lp = len(ports) if ports else 0
        return lp

    def url_is_live(self):
        url = '{}://{}'.format(self.urlparse.scheme, self.urlparse.netloc)
        try:
            return get(url).status_code == 200
        except:
            return False

    def url_isp(self):
        return self.shodan.get('isp', '')

    def url_connection_speed(self):
        url = '{}://{}'.format(self.urlparse.scheme, self.urlparse.netloc)
        if self.url_is_live():
            return get(url).elapsed.total_seconds()
        else:
            return None

    def first_seen(self):
        try:
            fs = self.snapshots[0]
            return fs
        except:
            return datetime.now()

    def get_os(self):
        oss = self.shodan.get('os', None)
        return oss

    def last_seen(self):
        try:
            ls = self.snapshots[-1]
            return ls
        except:
            return datetime.now()

    def days_since_last_seen(self):
        dsls = (self.now - self.last_seen()).days
        return dsls

    def days_since_first_seen(self):
        dsfs = (self.now - self.first_seen()).days
        return dsfs

    def average_update_frequency(self):
        snapshots = self.snapshots
        diffs = [(t-s).days for s, t in zip(snapshots, snapshots[1:])]
        l = len(diffs)
        if l > 0:
            return sum(diffs)/l
        else:
            return 0

    def number_of_updates(self):
        return len(self.snapshots)

    def ttl_from_registration(self):
        earliest_date_seen = self.first_seen()
        try:
            ttl_from_reg = (earliest_date_seen - self.url_creation_date()).days
        except:
            ttl_from_reg = None
        return ttl_from_reg

    def run(self):
        if self.init_sub_params:
            try:
                fv = {
                    "host": self.host,
                    "num_subdomains": self.number_of_subdomains(),
                    "registration_date": str(self.url_creation_date()),
                    "expiration_date": str(self.url_expiration_date()),
                    "last_updates_dates": str(self.url_last_updated()),
                    "age": self.url_age(),
                    "intended_life_span": self.url_intended_life_span(),
                    "life_remaining": self.url_life_remaining(),
                    "registrar": self.url_registrar(),
                    "reg_country": self.url_registration_country(),
                    "host_country": self.url_host_country(),
                    "open_ports": self.url_open_ports(),
                    "num_open_ports": self.url_num_open_ports(),
                    "is_live": self.url_is_live(),
                    "isp": self.url_isp(),
                    "connection_speed": self.url_connection_speed(),
                    "first_seen": str(self.first_seen()),
                    "last_seen": str(self.last_seen()),
                    "days_since_last_seen": self.days_since_last_seen(),
                    "days_since_first_seen": self.days_since_first_seen(),
                    "avg_update_days": self.average_update_frequency(),
                    "total_updates": self.number_of_updates(),
                    "ttl": self.ttl_from_registration()
                }
                cache.append(self.host)
                return fv
            except:
                print('OOPS')
                pass
        else:
            print('Seen Host')
            return None


if __name__ == '__main__':
    # files = os.listdir('data')
    files = ['benign.csv', 'malware.csv']
    for file in files:
        tag, file = file.split('.')[0], 'data/raw/{}'.format(file)
        with open(file, 'r+') as ff:
            lines = [i.strip() for i in ff.readlines()][::-1]
            for line in lines:
                ft = HostFeatures(line).run()
                if ft is not None:
                    ft['tag'] = tag
                    with open('data/output/hostfeatures.json', 'a') as jj:
                        dump(ft, jj)
                        jj.write('\n')
                        print(ft)

                else:
                    pass

