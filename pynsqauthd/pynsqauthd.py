import tornado.web
import tornado.httpserver
import tornado.httpclient
import tornado.ioloop
import tornado.options
import logging
import csv
import os
import urllib
try:
    import json
except ImportError:
    import simplejson as json # pyflakes.ignore
from collections import defaultdict

import netaddr

class DB(object):
    def __init__(self, filename):
        
        assert os.path.exists(filename)
        self.data = []
        for i, row in enumerate(csv.DictReader(open(filename, 'r'))):
            assert all([key in row for key in ['login', 'ip', 'tls_required', 'topic', 'channel', 'subscribe', 'publish']]), "invalid row:%d %r" % (i, row)
            if row['ip']:
                row['ip'] = netaddr.IPSet([row['ip']])
            else:
                row['ip'] = None
            if row['tls_required'] and row['tls_required'] not in ['true', 'false', 'True', 'False']:
                logging.error('tls_required value %r invalid. must be true/false (row:%d %r)', row['tls_required'], i, row)
                raise TypeError()
            row['tls_required'] = row['tls_required'].lower() in ['1', 'true', 'tls']
            permissions = []
            if row['subscribe'].lower() == 'subscribe':
                permissions.append('subscribe')
            if row['publish'].lower() == 'publish':
                permissions.append('publish')
            del row['subscribe']
            del row['publish']
            row['permissions'] = permissions
            logging.info('loading permission %r', row)
            self.data.append(row)
        logging.info('loaded %d data records from %s', len(self.data), filename)
    
    def match(self, login, remote_ip, tls_enabled):
        remote_ip = netaddr.IPAddress(remote_ip)
        def n():
            return defaultdict(list)
        matches = defaultdict(n)
        for row in self.data:
            if row['login'] and row['login'] != login:
                continue
            if row['ip'] and remote_ip not in row['ip']:
                continue
            if row['tls_required'] and not tls_enabled:
                continue
            matches[row['topic']][','.join(row['permissions'])].append(row['channel'])
        
        for topic, data in matches.items():
            for permissions, channels in data.items():
                yield dict(topic=topic, channels=channels, permissions=permissions.split(','))
            

class PingHandler(tornado.web.RequestHandler):
    def get(self):
        self.finish('OK')

class Auth(tornado.web.RequestHandler):
    def get_bool_argument(self, name, *args, **kwargs):
        """get a request argument that evaluates to a boolean value
        valid values are value.lower() == 'true' || 'false'
        takes an optional default=default_value which is not restricted to bool,
        and may also be None type
        """
        value = self.get_argument(name, *args, **kwargs)
        if not isinstance(value, (str, unicode)):
            return value
        if value.lower() not in ['true', 'false']:
            raise tornado.web.HTTPError(500, "Invalid argument %s. must be true|false" % name)
        return value.lower() == 'true'
    
    @tornado.web.asynchronous
    def get(self):
        secret = self.get_argument("secret")
        
        if tornado.options.options.oauth2_echo_endpoint:
            params = urllib.urlencode(dict(access_token=secret))
            url = tornado.options.options.oauth2_echo_endpoint + "?" + params
            client = tornado.httpclient.AsyncHTTPClient()
            client.fetch(url, callback=self.finish_oauth_get, validate_cert=tornado.options.options.validate_cert)
            return
        else:
            self.start_match(login=secret, skip_identity=True)
    
    def start_match(self, login, skip_identity=False):
        remote_ip = self.get_argument("remote_ip")
        tls_enabled = self.get_bool_argument("tls")
        # returns a list of topics/channels this client has access to
        # in the format {ttl:..., authorizations=[{topic:..., channels:[".*", ...], permissions:[publish,subscribe]}]}
        matches = list(self.settings['db'].match(login, remote_ip, tls_enabled))
        
        if not matches and not login:
            self.set_status(403)
            self.finish(dict(message="NOT_AUTHORIZED"))
        else:
            data = dict(ttl=tornado.options.options.ttl, authorizations=matches, identity=login if not skip_identity else '')
            self.finish(data)
    
    def finish_oauth_get(self, response):
        logging.debug("oauth response %d %r", response.code, response.body)
        raw_data = None
        try:
            assert response.code == 200
            raw_data = json.loads(response.body)
            data = raw_data
            keys = tornado.options.options.oauth2_response_path.split('.')
            while keys:
                key = keys.pop(0)
                data = data[key]
            assert data
            self.start_match(login=data)
        except:
            logging.error('failed calling oauth %s %d %r %r', response.effective_url, response.code, response.body, response.error)
            # there could still be matches on IP that don't require a login
            self.start_match(login="")


class AuthApp(tornado.web.Application):
    def __init__(self):
        
        settings = dict(debug=tornado.options.options.debug, db=DB(tornado.options.options.data_file))
        handlers = [
            (r"/ping", PingHandler),
            (r"/auth", Auth),
        ]
        super(AuthApp, self).__init__(handlers, **settings)


if __name__ == "__main__":
    tornado.options.define("http_address", type=str, default="0.0.0.0:4181", help="<addr>:<port> to listen on for HTTP clients")
    tornado.options.define("data_file", type=str, default="", help="a csv containing columns: login,ip,tls,topic,channel,subscribe,publish")
    tornado.options.define("ttl", type=int, default=60*60, help="TTL for auth responses (in seconds)")
    tornado.options.define("oauth2_echo_endpoint", type=str, default="https://api-ssl.bitly.com/v3/user/info", 
        help="used to confirm an oauth2 access_token and to extract the login\n to use bitly oauth use https://api-ssl.bitly.com/v3/user/info")
    tornado.options.define("oauth2_response_path", type=str, default="data.login", help="path in json response to get the login field")
    tornado.options.define("debug", type=bool, default=False)
    tornado.options.define("validate_cert", type=bool, default=True)
    tornado.options.define("xheaders", type=bool, default=False)
    tornado.options.parse_command_line()
    
    assert os.path.exists(tornado.options.options.data_file), "file does not exist --data-file=%s" % tornado.options.options.data_file
    
    http_server = tornado.httpserver.HTTPServer(AuthApp(), xheaders=tornado.options.options.xheaders)
    addr, port = tornado.options.options.http_address.rsplit(':', 1)

    logging.info("listening on %s", tornado.options.options.http_address)
    http_server.listen(int(port), address=addr)
    tornado.ioloop.IOLoop.instance().start()
    