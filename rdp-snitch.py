from csv import DictWriter
import json
from datetime import datetime, timedelta
from urllib.parse import quote
import time

from tqdm import tqdm
import tweepy
import constants
import requests
from elasticsearch import Elasticsearch

SEARCH_SIZE = 1000
SCROLL_TIMEOUT = '2m'

class GatherRDPData(object):
    def __init__(self, es_host, es_port):
        super().__init__()

        self.es = Elasticsearch(['{}:{}'.format(es_host, es_port)])
        self.reports = {}

    def run(self):
        # Gather data
        all_data = self.run_custom_agg(['user', 'srcIp', 'srcASN'])
        self.users = all_data['user']
        self.ips = all_data['srcIp']
        self.asns = all_data['srcASN']
        self.total = all_data['__total']

        # Run reports
        self.reports['users_txt'] = self.format_txt_report(all_data['user'], ['count', 'user'])
        self.reports['ips_txt'] = self.format_txt_report(all_data['srcIp'], ['count', 'srcIp'])
        self.reports['asns_txt'] = self.format_txt_report(all_data['srcASN'], ['count', 'srcASN'])

    def agg_scroll(self, data, agg_fields):
        """
        Borrowed from https://gist.github.com/hmldd/44d12d3a61a8d8077a3091c4ff7b9307
        """
        all_data = {f: {} for f in agg_fields}

        # Get the scroll ID
        sid = data['_scroll_id']
        scroll_size = len(data.get('hits', {}).get('hits', []))
        total_docs = data.get('hits', {}).get('total', {}).get('value', 0)
        all_data['__total'] = total_docs
        pbar = tqdm(desc=f"Aggregating", total=total_docs, unit=' docs', unit_scale=True)

        while scroll_size > 0:
            "Scrolling..."

            # Before scroll, process current batch of hits
            agg_data = data.get('hits', {}).get('hits', [])
            if not agg_data:
                break

            # Count records
            for item in agg_data:
                field_data = item['_source']
                if not len(field_data):
                    continue

                for agg_field in agg_fields:
                    if not agg_field in field_data:
                        continue

                    if isinstance(field_data.get(agg_field), list):
                        for term in field_data.get(agg_field, []):
                            if term == '':
                                term = '_no_value_'
                            if term not in all_data[agg_field]:
                                all_data[agg_field][term] = 0
                            all_data[agg_field][term] += 1
                    else:
                        term = field_data.get(agg_field, '')
                        if term == '':
                            term = '_no_value_'
                        if term not in all_data[agg_field]:
                            all_data[agg_field][term] = 0
                        all_data[agg_field][term] += 1

            pbar.update(len(agg_data))

            data = self.es.scroll(scroll_id=sid, scroll=SCROLL_TIMEOUT)

            # Update the scroll ID
            sid = data['_scroll_id']

            # Get the number of results that returned in the last scroll
            scroll_size = len(agg_data)

        pbar.close()

        return all_data

    def run_custom_agg(self, agg_fields):
        res = self.es.search(index="sessions2*", size=SEARCH_SIZE, scroll=SCROLL_TIMEOUT,
            _source_includes=agg_fields,
            body={
                "query":{
                     "range": {"timestamp": {"from": "now-1d", "to": "now"}}
                }
            }
        )
        agg_data = self.agg_scroll(res, agg_fields)

        sorted_data = {'__total': agg_data['__total']}
        for field in agg_fields:

            data_list = [{field: k, 'count': v} for k, v in agg_data[field].items()]
            sorted_data[field] = sorted(data_list, key=lambda x: x['count'], reverse=True)

        return sorted_data

    def format_txt_report(self, dataset, header):
        report = f"{header[0]} {header[1]}\n"

        for item in dataset:
            report += "{} {}\n".format(item[header[0]], item[header[1]])
        return report

def post_pastebin(data, title, data_fmt):

    sess_res = requests.post('https://pastebin.com/api/api_login.php', {
        'api_user_password': constants.PASTEBIN_PASS,
        'api_user_name': constants.PASTEBIN_USER,
        'api_dev_key': constants.PASTEBIN_API_KEY
    })
    if 'Bad' in sess_res.text:
        print(sess_res.text)
        return sess_res

    url = 'https://pastebin.com/api/api_post.php'

    res = requests.post(url, {
        # Required
        'api_dev_key': constants.PASTEBIN_API_KEY,
        'api_user_key': sess_res.text,
        'api_paste_code': data,
        'api_option': 'paste',
        # Optional
        'api_paste_format': data_fmt,
        'api_paste_name': quote(title),
        'api_paste_private': 0 # Public
    })
    if 'Bad' in res.text:
        print("Error posting to pastebin")
        print(res.text)
    else:
        print(res.text)

    return res


if __name__ == "__main__":
    # Gather data
    gather = GatherRDPData(constants.ELASTICSEARCH_HOST, constants.ELASTICSEARCH_PORT)
    gather.run()

    # Write to Pastebin
    now = datetime.now().strftime('%Y-%m-%d')
    title_fmt = "{}_".format(now)
    pastebin_sleep = 60

    users_txt_res = post_pastebin(gather.reports['users_txt'], title_fmt+'users.txt', 'text')

    time.sleep(pastebin_sleep)

    ips_txt_res = post_pastebin(gather.reports['ips_txt'], title_fmt+'ips.txt', 'text')

    time.sleep(pastebin_sleep)

    asns_txt_res = post_pastebin(gather.reports['asns_txt'], title_fmt+'asns.txt', 'text')

    top_ips = '\n'.join([x['srcIp'] for x in gather.ips[:3]])
    top_users = '\n'.join([x['user'] for x in gather.users[:3]])
    top_asns = '\n'.join([x['srcASN'][:27] for x in gather.asns[:3]]) # Limit ASN Length

    summary = f"{datetime.now().strftime('%Y-%m-%d')} RDP #Honeypot IOCs - {gather.total:,} scans\n\nTop IPs:\n{top_ips}\n\nTop Users:\n{top_users}\n\nTop ASNs:\n{top_asns}\n\nLinks below with details. #DFIR #InfoSec"

    pastebin_summary = f"Pastebin links with full 24-hr RDP #Honeypot IOC Lists:\nUsers: {users_txt_res.text}\nIPs: {ips_txt_res.text}\nASNs: {asns_txt_res.text}\n\n#DFIR #InfoSec #CyberSec #SOC #Hunt #Blueteam #SecurityOperations #SecOps #Security"

    print("==== Tweet 1 ({} chars):".format(len(summary)))
    print(summary)
    print("\n\n==== Tweet 2 ({} chars):".format(len(pastebin_summary)))
    print(pastebin_summary)

    print("Pausing for {}s".format(pastebin_sleep))
    time.sleep(pastebin_sleep)

    auth = tweepy.OAuthHandler(constants.TWITTER_API_KEY, constants.TWITTER_SECRET)
    auth.set_access_token(constants.TWITTER_ACCESS_TOKEN, constants.TWITTER_ACCESS_SECRET)

    tw_api = tweepy.API(auth)

    resp1 = tw_api.update_status(summary)
    resp2 = tw_api.update_status(pastebin_summary, in_reply_to_status_id=resp1.id)

