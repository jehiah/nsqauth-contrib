import tornado.web
import tornado.httpserver
import tornado.httpclient
import tornado.ioloop
import tornado.options
import logging
import urllib
import re
try:
    import json
except ImportError:
    import simplejson as json # pyflakes.ignore

class PingHandler(tornado.web.RequestHandler):
    def get(self):
        self.finish('OK')

class StatsProxy(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        self.auth_servers = list(self.settings["auth_addresses"])
        
        self.http_client = tornado.httpclient.AsyncHTTPClient()

        self.pending = 1
        self.start_auth()
        self.http_client.fetch(self.settings["nsqd_http_endpoint"], headers={"Accept": "vnd/nsq; version=1.0"}, callback=self.finish_stats_get)
    
    def start_auth(self):
        secret = self.get_argument("secret")
        self.pending += 1
        auth_endpoint = "http://%s/auth?%s" % (self.auth_servers.pop(), urllib.urlencode(dict(
            remote_ip=self.request.remote_ip,
            tls='true' if self.request.protocol == 'https' else 'false',
            secret=secret
        )))
        self.http_client.fetch(auth_endpoint, callback=self.finish_auth)

    def finish_auth(self, response):
        self.pending -= 1
        try:
            assert response.code == 200
            raw_data = json.loads(response.body)
            self.permissions = raw_data['authorizations']
        except:
            logging.error('got %r', response)
            if self.auth_servers:
                self.start_auth()
                return
            raise
        
        if self.pending == 0:
            self.filter_stats()
    
    def finish_stats_get(self, response):
        self.pending -= 1
        assert response.code == 200
        raw_data = json.loads(response.body)
        if "data" in raw_data:
            self.stats = raw_data["data"]["topics"]
        else:
            self.stats = raw_data["topics"]
        if self.pending == 0:
            self.filter_stats()
    
    def is_authorized(self, topic, channel, permission):
        for auth in self.permissions:
            topic_regex = re.compile(auth['topic'])
            if not topic_regex.findall(topic):
                continue
            if permission == 'publish' and 'publish' in auth['permissions']:
                return True
            if permission == 'subscribe' and 'subscribe' in auth['permissions'] and not channel:
                return True
            for channel_auth in auth['channels']:
                channel_regex = re.compile(channel_auth)
                if not channel:
                    continue
                if not channel_regex.findall(channel):
                    continue
                return True
        return False
    
    def filter_stats(self):
        
        output_topics = []
        for topic in self.stats:
            output_topic = None
            if self.is_authorized(topic['topic_name'], None, 'publish'):
                # full data visibility to topic
                output_topic = dict(
                    message_count=topic['message_count'],
                    backend_depth=topic['backend_depth'],
                    depth=topic['depth'],
                    topic_name=topic['topic_name'],
                    channels=[],
                )
            elif self.is_authorized(topic['topic_name'], None, 'subscribe'):
                output_topic = dict(
                    topic_name=topic['topic_name'],
                    channels=[],
                )
            if not output_topic:
                continue
            output_topics.append(output_topic)
            
            for channel in topic['channels']:
                if self.is_authorized(topic['topic_name'], None, 'publish') or self.is_authorized(topic['topic_name'], channel['channel_name'], 'subscribe'):
                    output_topic['channels'].append(channel)
        
        if self.request.headers['Accept'] == "vnd/nsq; version=1.0":
            self.finish(dict(topics=output_topics))
        else:
            self.finish(dict(status_code=200, status_txt="OK", data=dict(topics=output_topics)))


class Application(tornado.web.Application):
    def __init__(self):
        
        addresses = tornado.options.options.auth_address
        assert isinstance(addresses, list)
        
        settings = dict(
            debug=tornado.options.options.debug,
            auth_addresses=addresses,
            nsqd_http_endpoint="http://%s/stats?format=json" % tornado.options.options.nsqd_http_address,
        )
        handlers = [
            (r"/ping", PingHandler),
            (r"/stats", StatsProxy),
        ]
        super(Application, self).__init__(handlers, **settings)


if __name__ == "__main__":
    tornado.options.define("http_address", type=str, default="0.0.0.0:4182", help="<addr>:<port> to listen on for HTTP clients")
    tornado.options.define("auth_address", type=str, default="127.0.0.1:4181", multiple=True, help="<addr>:<port> to connect to auth server")
    tornado.options.define("nsqd_http_address", type=str, default="127.0.0.1:4151", help="<addr>:<port> of nsqd http address for stats call")
    tornado.options.define("debug", type=bool, default=False)
    tornado.options.parse_command_line()
    
    http_server = tornado.httpserver.HTTPServer(Application())
    addr, port = tornado.options.options.http_address.rsplit(':', 1)
    
    logging.info("listening on %s", tornado.options.options.http_address)
    http_server.listen(int(port), address=addr)
    tornado.ioloop.IOLoop.instance().start()
    