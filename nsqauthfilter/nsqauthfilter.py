import tornado.web
import tornado.httpserver
import tornado.httpclient
import tornado.ioloop
import tornado.options
import logging
import urllib
import functools
import re
try:
    import json
except ImportError:
    import simplejson as json # pyflakes.ignore

class PingHandler(tornado.web.RequestHandler):
    def get(self):
        self.finish('OK')

class AuthBase(tornado.web.RequestHandler):
    def start_auth(self, callback):
        secret = self.get_argument("secret")
        self.pending += 1
        auth_endpoint = self.auth_servers.pop()
        logging.info("GET http://%s/auth", auth_endpoint)
        auth_endpoint = "http://%s/auth?%s" % (auth_endpoint, urllib.urlencode(dict(
            remote_ip=self.request.remote_ip,
            tls='true' if self.request.protocol == 'https' else 'false',
            secret=secret
        )))
        self.http_client.fetch(auth_endpoint, callback=functools.partial(self.finish_auth, callback=callback))

    def finish_auth(self, response, callback):
        self.pending -= 1
        try:
            logging.debug("auth response %d %r", response.code, response.body)
            assert response.code == 200
            raw_data = json.loads(response.body)
            self.permissions = raw_data['authorizations']
        except:
            logging.error('got %r', response)
            if self.auth_servers:
                self.start_auth(callback=self.filter_stats)
                return
            self.set_status(500)
            self.finish(dict(status_txt="INTERNAL_ERROR"))
            return
        if self.pending == 0:
            callback()

    def is_authorized(self, topic, channel, permission):
        for auth in self.permissions:
            topic_regex = re.compile('^' + auth['topic'] + '$')
            if not topic_regex.match(topic):
                continue
            if permission == 'publish' and 'publish' in auth['permissions']:
                return True
            if permission == 'subscribe' and 'subscribe' in auth['permissions'] and not channel:
                # we are just checking if there are any potentially matching subscribe checks
                return True
            for channel_auth in auth['channels']:
                channel_regex = re.compile('^'+ channel_auth + '$')
                if not channel:
                    continue
                if not channel_regex.match(channel):
                    continue
                return True
        return False
    
    def api_response(self, data):
        if self.request.headers['Accept'] == "application/vnd.nsq; version=1.0":
            self.finish(data)
        else:
            self.finish(dict(status_code=200, status_txt="OK", data=data))
    
    def api_error(self, status_code, data):
        if self.request.headers['Accept'] == "application/vnd.nsq; version=1.0":
            self.set_stat(status_code)
            self.finish(dict(message=data))
        else:
            self.finish(dict(status_code=status_code, status_txt=data, data=None))

class StatsProxy(AuthBase):
    @tornado.web.asynchronous
    def get(self):
        self.stats = []
        self.auth_servers = list(self.settings["auth_addresses"])
        
        self.http_client = tornado.httpclient.AsyncHTTPClient()

        self.pending = 0
        self.start_auth(callback=self.filter_stats)
        assert len(self.settings["nsqd_endpoints"]) == 1
        for addr in self.settings["nsqd_endpoints"]:
            self.start_stats(addr)
        
        assert self.pending > 0
    
    def start_stats(self, addr):
        self.pending += 1
        endpoint = "http://%s/stats?format=json" % addr
        callback=functools.partial(self.finish_stats_get, addr=addr)
        logging.info("GET %s", endpoint)
        self.http_client.fetch(endpoint, headers={"Accept": "application/vnd.nsq; version=1.0"}, callback=callback)
    
    def finish_stats_get(self, response, addr):
        logging.debug("response %d %r", response.code, response.body)
        self.pending -= 1
        assert response.code == 200
        raw_data = json.loads(response.body)
        if "data" in raw_data:
            topics = raw_data["data"]["topics"]
        else:
            topics = raw_data["topics"]

        for topic in topics:
            topic["producer"] = addr
            self.stats.append(topic)
        
        if self.pending == 0:
            self.filter_stats()
    
    
    def filter_stats(self):
        output_topics = dict()
        for topic in self.stats:
            output_topic = None
            if self.is_authorized(topic['topic_name'], None, 'publish'):
                # full data visibility to topic
                output_topic = dict(
                    message_count=topic['message_count'],
                    backend_depth=topic['backend_depth'],
                    depth=topic['depth'],
                    topic_name=topic['topic_name'],
                    producers=[topic['producer']],
                    channels=[],
                )
            elif self.is_authorized(topic['topic_name'], None, 'subscribe'):
                output_topic = dict(
                    topic_name=topic['topic_name'],
                    producers=[topic['producer']],
                    channels=[],
                )
            if not output_topic:
                continue
            if topic['topic_name'] in output_topics:
                existing_topic = output_topics[topic['topic_name']]
                if 'message_count' in output_topic:
                    for key in ['message_count', 'backend_depth', 'depth']:
                        existing_topic[key] += output_topic[key]
                existing_topic['producers'].extend(output_topic['producers'])
                output_topic = existing_topic
            else:
                output_topics[topic['topic_name']] = output_topic
            
            for channel in topic['channels']:
                channel['producer'] = topic['producer']
                if self.is_authorized(topic['topic_name'], None, 'publish') or self.is_authorized(topic['topic_name'], channel['channel_name'], 'subscribe'):
                    output_topic['channels'].append(channel)
        
        if self.pending == 0:
            self.api_response(dict(topics=output_topics.values()))


class LookupProxy(AuthBase):
    @tornado.web.asynchronous
    def get(self):
        self.auth_servers = list(self.settings["auth_addresses"])
        self.http_client = tornado.httpclient.AsyncHTTPClient()
        self.pending = 0
        self.start_auth(callback=self.filter_lookupd)
        self.seen_producers = set()
        self.producers = []
        topic = self.get_argument("topic")
        assert self.settings["lookupd_endpoints"]
        for endpoint in self.settings["lookupd_endpoints"]:
            self.pending += 1
            url = endpoint + '?' + urllib.urlencode(dict(topic=topic, format="json"))
            logging.info("GET %s", url)
            self.http_client.fetch(url, headers={"Accept": "application/vnd.nsq; version=1.0"}, callback=self.finish_lookupd_get)
        assert self.pending > 0
    
    def finish_lookupd_get(self, response):
        logging.debug("response %d %r", response.code, response.body)
        # build up the list of producers we need to query
        self.pending -= 1
        
        assert response.code == 200
        raw_data = json.loads(response.body)
        if "data" in raw_data:
            producers = raw_data["data"]["producers"]
        else:
            producers = raw_data["producers"]
    
        for producer in producers:
            
            addr = "%s:%d" % (producer["broadcast_address"], producer["http_port"])
            if addr in self.seen_producers:
                continue
            self.seen_producers.add(addr)
            self.producers.append(producer)
        
        if self.pending == 0:
            self.filter_lookupd()
    
    def filter_lookupd(self):
        topic = self.get_argument("topic")
        if self.is_authorized(topic, None, 'subscribe'):
            self.api_response(dict(producers=self.producers))
        else:
            self.api_error(403, "AUTH_UNAUTHORIZED")

class TopicStatsProxy(StatsProxy):
    @tornado.web.asynchronous
    def get(self):
        self.stats = []
        self.auth_servers = list(self.settings["auth_addresses"])
        self.http_client = tornado.httpclient.AsyncHTTPClient()
        self.seen_producers = set()
        topic = self.get_argument("topic")

        self.pending = 0
        self.start_auth(callback=self.filter_stats)
        assert self.settings["lookupd_endpoints"]
        for endpoint in self.settings["lookupd_endpoints"]:
            self.pending += 1
            url = endpoint + '?' + urllib.urlencode(dict(topic=topic, format="json"))
            logging.info("GET %s", url)
            self.http_client.fetch(url, headers={"Accept": "application/vnd.nsq; version=1.0"}, callback=self.finish_lookupd_get)
        assert self.pending > 0
    
    def finish_lookupd_get(self, response):
        logging.debug("response %d %r", response.code, response.body)
        # build up the list of producers we need to query
        self.pending -= 1
        
        assert response.code == 200
        raw_data = json.loads(response.body)
        if "data" in raw_data:
            producers = raw_data["data"]["producers"]
        else:
            producers = raw_data["producers"]
    
        for producer in producers:
            addr = "%s:%d" % (producer["broadcast_address"], producer["http_port"])
            if addr in self.seen_producers:
                continue
            self.seen_producers.add(addr)
            self.start_stats(addr)
        
        if self.pending == 0:
            self.filter_stats()


class Application(tornado.web.Application):
    def __init__(self):
        
        addresses = tornado.options.options.auth_address
        assert isinstance(addresses, list)
        
        lookupd_endpoints = []
        for addr in tornado.options.options.lookupd_http_address:
            lookupd_endpoints.append("http://%s/lookup" % addr)
        
        settings = dict(
            debug=tornado.options.options.debug,
            auth_addresses=addresses,
            nsqd_endpoints=tornado.options.options.nsqd_http_address,
            lookupd_endpoints=lookupd_endpoints,
        )
        handlers = [
            (r"/ping", PingHandler),
            (r"/stats", StatsProxy),
            (r"/topic_stats", TopicStatsProxy),
            (r"/lookup", LookupProxy),
        ]
        super(Application, self).__init__(handlers, **settings)



if __name__ == "__main__":
    tornado.options.define("http_address", type=str, default="0.0.0.0:4182", help="<addr>:<port> to listen on for HTTP clients")
    tornado.options.define("auth_address", type=str, default="127.0.0.1:4181", multiple=True, help="<addr>:<port> to connect to auth server")
    tornado.options.define("lookupd_http_address", type=str, multiple=True, help="<addr>:<port> to connect to nsqlookupd (specify multiple times)")
    tornado.options.define("nsqd_http_address", type=str, multiple=True, help="<addr>:<port> of nsqd http address for stats call (skip if using lookupd; specify multiple times)")
    tornado.options.define("debug", type=bool, default=False)
    tornado.options.define("xheaders", type=bool, default=False)
    tornado.options.parse_command_line()
    
    http_server = tornado.httpserver.HTTPServer(Application(), xheaders=tornado.options.options.xheaders)
    addr, port = tornado.options.options.http_address.rsplit(':', 1)
    
    logging.info("listening on %s", tornado.options.options.http_address)
    http_server.listen(int(port), address=addr)
    tornado.ioloop.IOLoop.instance().start()
    