import logging
import os
import sys
import argparse
from argparse import RawTextHelpFormatter
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper
import subprocess

class RandomPortGenerator(object):
    """
        g = RandomPortGenerator().get()
        g.next()
    """
    def __init__(self):
        pass

    def get(self):
        b = 30000
        i = 0
        while(True):
            i += 1
            yield(b+i)       

class WalkDir(object):
    logger = logging.getLogger(__name__)

    def __init__(self):
        pass

    def get_files(self, base_dir, include_filenames=None, exlude_dirs=None):
        """
            Params:
                base_path(str): base path of directory
                include_filenames (array): array of filenames, 
                    None if include everything
                exlude_dirs (array): array of dir namaes to exlude
                    None if exclude nothing
            
            Returns:
            ========
                iterator of pairs (root_dir_path, name)
        """
        exlude_dirs = exlude_dirs or set()
        include_filenames = include_filenames or set()

        for root, dirs, files in os.walk(base_dir):
            [dirs.remove(d) for d in list(dirs) if d in exlude_dirs]
            included = set(files)
            if include_filenames:
                [included.remove(f) for f in list(files) if f not in include_filenames]
            for f in included:
                yield((root, f))

    def get_dirs(self, base_dir, include_filenames=None, exlude_dirs=None):
        """
            Params:
                base_path(str): base path of directory
                include_filenames (array): array of filenames, 
                    None if include everything
                exlude_dirs (array): array of dir namaes to exlude
                    None if exclude nothing
            
            Returns:
            ========
                iterator of pairs (root_dir_path, name)
        """
        exlude_dirs = exlude_dirs or set()
        include_filenames = include_filenames or set()

        for root, dirs, files in os.walk(base_dir):
            [dirs.remove(d) for d in list(dirs) if d in exlude_dirs]
            included = set(files)
            if include_filenames:
                [included.remove(f) for f in list(files) if f not in include_filenames]
            self.logger.debug("%s %s %s", root, dirs, files)
            # print(root, dirs, files, included)
            if(included):
                yield(root)


class DkrCompose(object):
    logger = logging.getLogger(__name__)

    def __init__(self):
        """
            Params:
            =======
                port_generator(iterator): generate sequence of ports
        """
        self.dir_walker = WalkDir()
    
    def randomize_ports(self, base_dir, port_generator):
        """

            g = RandomPortGenerator().get()
            dkc = DkrCompose()
            service_map = dkc.randomize_ports(".", port_generator=g)

            {'activemq/CVE-2015-5254': {'activemq': {'ports': {'61616': 30003,
                '8161': 30004}}},
                'activemq/CVE-2016-3088': {'activemq': {'ports': {'61616': 30001,
                    '8161': 30002}}},
                'appweb/CVE-2018-8715': {'aria2': {'ports': {'8080': 30076}}},
                'aria2/rce': {'aria2': {'ports': {'6800': 30042}}},
                'bash/shellshock': {'web': {'ports': {'80': 30055}}},
                'cgi/httpoxy': {'nginx': {'ports': {'443': 30072, '80': 30071}},
                'php': {'ports': {}}},
                'coldfusion/CVE-2010-2861': {'coldfusion': {'ports': {'8500': 30108}}},
                'coldfusion/CVE-2017-3066': {'coldfusion': {'ports': {'8500': 30107}}},
                'confluence/CVE-2019-3396': {'db': {'ports': {}},
                'web': {'ports': {'8090': 30095}}}
            }

        """
        include_filenames = ["docker-compose.yml"]
        exlude_dirs = ["base"]
        service_map = {}
        for root, fname in self.dir_walker.get_files(base_dir, \
                            include_filenames=include_filenames, \
                            exlude_dirs=exlude_dirs):
            fpath = os.path.join(root, fname)
            self.logger.debug("Updating file %s", fpath)
            ports_map = self._update_ports(fpath, port_generator )
            name_path = root.replace(os.path.join(base_dir, "/"), "")
            service_map[root] = ports_map
        return service_map

    def list_services(self, base_dir, keywords=None):
        """
            Params:
            =======
                keywords: array of str: keywords to filter in dir or filename
            
            Returns:
            ========
                array of str
        """
        exlude_dirs = ["base"]
        include_filenames = ["docker-compose.yml"]
        keywords = keywords or [""]
        services = set()
        for root in self.dir_walker.get_dirs(base_dir, \
                            include_filenames=include_filenames,
                            exlude_dirs=exlude_dirs):
            # dir_path = os.path.join(root, dir_name)
            # name_path = self._get_base_name(root, base_dir)
            self.logger.info("Received service path %s %s", base_dir, root)
            for k in keywords:
                if k in root:
                    services.add(root)
        return list(services)

    def _subprocess_cmd(self, command):
        process = subprocess.Popen(command,stdout=subprocess.PIPE, shell=True)
        proc_stdout = process.communicate()[0].strip()
        return proc_stdout

    def create(self, base_dir, keywords=None):
        services = self.list_services(base_dir=base_dir, 
                                      keywords=keywords)
        for service in services:
            cmd = "cd %s; docker-compose up -d; " % service
            proc_stdout = self._subprocess_cmd(cmd)
            self.logger.info(proc_stdout)
        return services
    
    def delete(self, services=None, base_dir=None, keywords=None):
        """
            Params:
            =======
                services: array of str: str is path of the service
                          if services is none search by base_dir and keywords
                base_dir: 
                keywords:
        """
        if not services:
            if not base_dir:
                self.logger.warn("Services or Base dir not provided")
                return
            services = self.list_services(base_dir=base_dir, 
                                      keywords=keywords)
        
        for service in services:
            cmd = "cd %s; docker-compose down -v; " % service
            proc_stdout = self._subprocess_cmd(cmd)
            self.logger.info(proc_stdout)

    def _get_base_name(self, root, base_dir):
        return root.replace(os.path.join(base_dir, "/"), "")

    def _update_ports(self, dkr_cmp_fpath, port_generator):
        # self.logger.debug("updating file %s" % dkr_cmp_fpath)
        updated = False
        updated_ports_map = {}
        with open(dkr_cmp_fpath) as f:
            data = load(f, Loader=Loader)
            for service, value in data.get('services', {}).items():
                updated_ports_map[service] = {}
                ports = value.get("ports", [])
                updated_ports_map[service]["ports"]  = {}
                updated_ports = []
                for port in ports:
                    p1, p2 = port.split(":")
                    p11 = port_generator.__next__()
                    port2 = "%s:%s" % (p11, p2)
                    updated_ports_map[service]["ports"][p2] = p11
                    updated_ports.append(port2)
                if updated_ports:
                    value["ports"] = updated_ports
                    updated = True
        if(updated):
            with open(dkr_cmp_fpath, "w") as f:
                dump(data, stream=f, Dumper=Dumper)
        return updated_ports_map


    # def find_dkr_cmp(self, base_path, process_func, exlude_dirs=None):
    #     exlude_dirs = exlude_dirs or ["base"]
    #     for root, dirs, files in os.walk(base_path):
    #         [dirs.remove(d) for d in list(dirs) if d in exlude_dirs]
    #         # print(root)
    #         # print(dirs)
    #         # print(files)
    #         if "docker-compose.yml" in files:
    #             fpath = os.path.join(root, "docker-compose.yml")
    #             print(fpath)
    #             process_func(fpath)



def _handle_log_level(options):
    log_level = options.log_level
    log_level_no = logging.INFO
    if(log_level):
        level = logging.getLevelName(log_level)
        if type(level) == int:
            log_level_no = level
    logging.basicConfig(level=logging.DEBUG, 
                        format="%(asctime)s - %(name)s (%(lineno)s) - \
                             %(levelname)s: %(message)s", 
                        datefmt='%Y.%m.%d %H:%M:%S')

def handle_env_commands(options):
    command = options.command
    logging.debug("Running command %s", command)
    base_dir = options.base_dir
    keywords = options.keywords.split(",")
    # print(keywords)
    drp = DkrCompose()
    if(command == "randomize_ports"):
        rpg = RandomPortGenerator().get()
        drp.randomize_ports(base_dir, port_generator=rpg)
    elif(command == "list"):
        services = drp.list_services(base_dir, keywords)
        for s in services:
            print(s)
    elif(command == "create"):
        services = drp.create(base_dir=base_dir, keywords=keywords)
    elif(command == "delete"):
        drp.delete(base_dir=base_dir, keywords=keywords)       
    else:
        print("Unknown Command %s" % command)
    

def main(options):
    _handle_log_level(options)
    if(options.category == "vulnhub"):
        handle_env_commands(options)
    else:
        print("Unknown Command %s", options.category)

def match_any_element(source_arr, target_arr):
    for e in source_arr:
        if e in target_arr:
            return True
    return False

def start():
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description="""Vulnhun Management
        Examples:-
            TBD

                """)
    import textwrap

    env_help = textwrap.dedent("""\
        Commands

    """)

    subparsers = parser.add_subparsers(help='commands', dest="category")
    env_parser = subparsers.add_parser('vulnhub', help='Vuln Hub Env Mgmt Commands')
    env_parser.add_argument("command",  choices=(['randomize_ports', 'create', 'list', 'delete']), help=env_help)
    env_parser.add_argument("-base_dir", type=str, required=True, default="vulnhub/", help="Base Directory to scan")
    env_parser.add_argument("-keywords",  default="", help="comma (,) seperated keywords to filter")
    # scan_parser.add_argument("-keys_file", help="Keys File for modules that requires API keys")
    # scan_parser.add_argument("-keys_file", help="Keys File for modules that requires API keys")
    # scan_parser.add_argument('-entity_from_file', action='store_true', default=False)
    # scan_parser.add_argument("-entity_type", help="Type of Entity such as ip_address, domain_name, internet_name etc.")
    # scan_parser.add_argument("-entities",  required=match_any_element(['create'], sys.argv), help="Entities such as IP address or domain mame seperated by spaces")
    # scan_parser.add_argument("-depth", type=int,  default=sys.maxint, help="Number of events to handle. Useful when you want to limit the numodulembe of execution.")
    # scan_parser.add_argument("-modules", type=str, required=False, default="", help="List of Modules seprated by spaces")
    # scan_parser.add_argument("-checkpoint_frequency",  type=int, required=False, default=0, help="How often checkpointing should be done. 0 for never")
    # scan_parser.add_argument("-checkpoint_file", required=match_any_element(['restore'], sys.argv), default="checkpoint.pickle", help="File Location or Name to Pickle resulted Knowledge Graph (kg). ")
    # scan_parser.add_argument("-search_from_time", required=False, default="all_time", help="Possible Values: past_24hrs, past_week, all_time, all_time")
    # scan_parser.add_argument("-blacklisted_modules", type=str, required=False, default="", help="List of Modules that need to blacklisted. It can even contain tags in the format tags:tagname1,tagname2")
    # scan_parser.add_argument("-local_cache_create", action='store_true', default=False, help="Create Local Cache on Startup if does not exist")
    env_parser.add_argument("-log_level",  default="INFO", help="DEBUG INFO WARN ERROR")
    # scan_parser.add_argument("-artifact_bucket_name", type=str, help="Bucket (Remote) OR Directory Path (local) to store module artifacts such as reports etc.")
    # scan_parser.add_argument("-artifact_bucket_location", type=str, help="local|remote")


    options = parser.parse_args()
    logging.debug(options)
    main(options)

if __name__ == '__main__':
    start()