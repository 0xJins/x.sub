import os
import re
from subprocess import getoutput
from threading import RLock
from time import sleep
from urllib.parse import urlsplit

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from utils import list_file_paths, parallel_map

GITHUB_REPOSITORY = os.getenv('GITHUB_REPOSITORY')
GITHUB_REF_NAME = os.getenv('GITHUB_REF_NAME')
GITHUB_SHA = getoutput('git rev-parse HEAD')
DDAL_EMAIL = os.getenv('DDAL_EMAIL')
DDAL_PASSWORD = os.getenv('DDAL_PASSWORD')

GH_RAW_URL_PREFIX = f'https://raw.kgithub.com/{GITHUB_REPOSITORY}/{GITHUB_REF_NAME}'
GH_RAW_URL_PREFIX_SHA = f'https://cdn.jsdelivr.net/gh/{GITHUB_REPOSITORY}@{GITHUB_SHA}'

re_ddal_alias = re.compile(r'[\da-z]+(?:-[\da-z]+)*', re.I)


def get_short_url(path: str):
    if DDAL_EMAIL and DDAL_PASSWORD:
        name = os.path.splitext(os.path.basename(path))[0]
        return f"https://dd.al/{get_alias(name)}"
    else:
        return f'{GH_RAW_URL_PREFIX}/{path}'


def get_alias(name: str):
    if GITHUB_REPOSITORY == 'zsokami/sub':
        if name == 'clash-hardcode':
            return 'trial'
        if name == 'clash-proxy-providers':
            return 'trial-pp'
        return f"trial-{'-'.join(re_ddal_alias.findall(name))}"
    else:
        repo = '-'.join(re_ddal_alias.findall(GITHUB_REPOSITORY))
        if name == 'clash-hardcode':
            return f"gh-{repo}-trial"
        if name == 'clash-proxy-providers':
            return f"gh-{repo}-trial-pp"
        return f"gh-{repo}-trial-{'-'.join(re_ddal_alias.findall(name))}"


class DDAL:
    def __init__(self):
        self.__session = requests.Session()
        self.__session.mount('https://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.1)))
        self.__session.mount('http://', HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.1)))
        self.__session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
        self.__token_lock = RLock()

    @staticmethod
    def raise_for_alias(alias):
        if not re_ddal_alias.fullmatch(alias):
            raise Exception(f'非法 alias: {alias}')

    def login(self, email, password):
        for _ in range(10):
            with self.__token_lock:
                bs = BeautifulSoup(self.__session.get('https://dd.al/user/login').text, 'html.parser')
                token = bs.find('input', {'name': 'token'})
                if not token:
                    raise Exception('未找到 token (https://dd.al/user/login)')
                token = token['value']
                r = self.__session.post('https://dd.al/user/login', data={
                    'email': email,
                    'password': password,
                    'token': token
                }, allow_redirects=False)
            loc = r.headers.get('Location')
            if loc and urlsplit(loc).path == '/user':
                break
            sleep(9)
        else:
            raise Exception(f'尝试 10 次登录均失败 (loc = {repr(loc)})')

    def search(self, q) -> list[dict]:
        html = self.__session.post('https://dd.al/user/search', data={
            'q': q,
            'token': 'd2172161243aedc5da47e41227f37add'
        }).text
        bs = BeautifulSoup(html, 'html.parser')
        return [{
            'id': item['data-id'],
            'short': item.select_one('.short-url>a')['href'],
            'original': item.select_one('.title>a')['href']
        } for item in bs.find_all(class_='url-list')]

    def insert(self, alias, url) -> str:
        self.raise_for_alias(alias)
        r = self.__session.post('https://dd.al/shorten', data={
            'url': url,
            'custom': alias
        }).json()
        if r['error']:
            raise Exception(f"{r['msg']} (alias = {repr(alias)}, url = {repr(url)})")
        return r['short']

    def update(self, id, alias, url) -> str:
        for _ in range(10):
            with self.__token_lock:
                bs = BeautifulSoup(self.__session.get(f'https://dd.al/user/edit/{id}').text, 'html.parser')
                token = bs.find('input', {'name': 'token'})
                if not token:
                    raise Exception(f'未找到 token (https://dd.al/user/edit/{id})')
                token = token['value']
                r = self.__session.post(f'https://dd.al/user/edit/{id}', data={
                    'url': url,
                    'token': token
                }, allow_redirects=False)
            loc = r.headers.get('Location')
            if not (loc and urlsplit(loc).path != '/user'):
                raise Exception(f'loc = {repr(loc)}')
            item = next((item for item in self.search(alias) if item['id'] == id), None)
            if item and item['original'] == url:
                break
        else:
            raise Exception(f'尝试 10 次更新 url 均失败 (id = {repr(id)}, url = {repr(url)})')
        return item['short']

    def upsert(self, alias, url) -> str:
        self.raise_for_alias(alias)
        id = next((item['id'] for item in self.search(alias) if urlsplit(item['short']).path[1:] == alias), None)
        if id:
            return self.update(id, alias, url)
        else:
            return self.insert(alias, url)


if __name__ == '__main__':
    names_and_paths = [
        ('base64', 'trial'),
        ('clash-hardcode', 'trial.yaml'),
        ('clash-proxy-providers', 'trial_pp.yaml')
    ]

    descriptions = [
        'base64 版',
        'clash 硬编码版',
        'clash 提供器版'
    ]

    for path in list_file_paths('trials_providers'):
        name = os.path.splitext(os.path.basename(path))[0]
        names_and_paths.append((name, path))
        descriptions.append(name)

    if DDAL_EMAIL and DDAL_PASSWORD:
        ddal = DDAL()
        ddal.login(DDAL_EMAIL, DDAL_PASSWORD)
        aliases_and_urls = ((get_alias(name), f'{GH_RAW_URL_PREFIX_SHA}/{path}') for name, path in names_and_paths)

        def upsert(alias, url):
            try:
                return ddal.upsert(alias, url)
            except Exception as e:
                return f'{type(e)}: {e}'

        for short, description in zip(parallel_map(upsert, *zip(*aliases_and_urls)), descriptions):
            print(f'{description}: {short}')
    else:
        for (name, path), description in zip(names_and_paths, descriptions):
            print(f'{description}: {GH_RAW_URL_PREFIX}/{path}')
