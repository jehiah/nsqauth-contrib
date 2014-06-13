nsqauth-contrib
===============

Useful companion apps for when using nsq with auth enabled

## nsqauthfilter

Filter a cluster of nsqd's `/stats` call to only the topics and channels you have access to.

- `/topic_stats?topic=...&secret=...`

Filter a nsqlookupd's `/lookup` call to return only topics you have access to

- `/lookup?topic=...&secret=....`

To filter a full nsqd hosts `/stats` call to only the topics and channels you have access to

- `/stats?secret=...`

Typical usage will be to run in front of a lookupd based cluster of nsqds

    python nsqauthfilter.py \
       --auth-address=127.0.0.1:4181 \
       --lookupd-http-address=127.0.0.1:4161 \
       --http-address=0.0.0.0:4182

## pynsqauthd

Implements the NSQ auth specification and authenticates a secret as an access token against an oauth2 endpoint. 
Identity validated by the oauth2 endpoint is then matched against a local permissions database.

To use validating a secret as an access token against the bitly API, use the following options:

    --oauth2-echo-endpoint=https://api-ssl.bitly.com/v3/user/info
    --oauth2-response-path=data.login

The datafile is a csv format like this.

```
login,ip,tls,topic,channel,subscribe,publish
johndoe,127.0.0.1,both,test_topic,test_channnel,subscribe,
```

Typical usage will be like this:

    python pynsqauthd.py \
      --data_file=permissions.csv \
      --http_address=0.0.0.0:4181 \
      --ttl=3600 \
      --oauth2-echo-endpoint=https://api-ssl.bitly.com/v3/user/info \
      --oauth2-response-path=data.login
      
