#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

# 此版本未完全解决反爬虫机制，可供参考

# 导入所需的库
from pyspider.libs.base_handler import *
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from lxml import etree
import ast
import time
import random
import requests
import sys

# 设置默认编码为utf8
reload(sys)
sys.setdefaultencoding('utf8')

class Handler(BaseHandler):
    crawl_config = {}

    def __init__(self):
        # 设置请求头信息
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.16 Safari/537.36"
        }
        # 起始URL
        self.start_url = "http://www.cnvd.org.cn/flaw/list.htm"
        self.count = 0
        self.cookies = self.get_cookies()

    # 获取cookies
    def get_cookies(self):
        chrome_options = Options()
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')

        driver = webdriver.Chrome(chrome_options=chrome_options)
        driver.get("https://www.cnvd.org.cn/flaw/list.htm")
        cj = driver.get_cookies()
        cookie = ''
        for c in cj:
            cookie += "'"+c['name'] + "':'" + c['value'] + "',"
        cookie = ast.literal_eval('{'+cookie+'}')
        time.sleep(2)
        driver.quit()

        return cookie

    # 解析页面
    def parse(self, url):
        time.sleep(random.randint(1, 2))
        self.count += 1
        print(self.count)
        if self.count == 5:
            self.cookies = self.get_cookies()
            self.count = 0
        html = requests.get(url, headers=self.headers, cookies=self.cookies).content.decode()
        html = etree.HTML(html)
        return html

    # 定义起始任务
    @every(minutes=24 * 60)
    def on_start(self):
        self.cookies = self.get_cookies()

        for i in range(0, 128800, 100):
            url = 'https://www.cnvd.org.cn/flaw/list.htm?%s' % str(i)
            self.crawl(url, method='POST', data={'max': 100, 'offset': str(i)}, callback=self.index_page, headers=self.headers, cookies=self.cookies)

    # 解析列表页
    @config(age=10 * 24 * 60 * 60)
    def index_page(self, response):
        list_url = response.etree.xpath("//div[@id='flawList']/tbody/tr/td[1]/a/@href")
        if list_url is None:
            list_url = response.etree.xpath("//div[@class='blkContainerPblk']//table[@class='tlist']/tbody/tr/td[1]/a/@href")
        for url in list_url:
            url = "http://www.cnvd.org.cn" + url
            self.detail_page(url)

    # 解析详情页
    @config(priority=2)
    def detail_page(self, url):
        html = self.parse(url)
        item = {}

        item["cn_title"] = html.xpath("//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")
        if item["cn_title"]:
            item["cn_title"] = html.xpath("//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")[0].strip()
        else:
            item["cn_title"] = 'Null'

        item["date"] = ''.join(html.xpath(u"//td[text()='公开日期']/following-sibling::td[1]/text()")).strip()

        item["hazard_level"] = html.xpath(u"//td[text()='危害级别']/following-sibling::td[1]/text()")
        if item["hazard_level"]:
            item["hazard_level"] = "".join([i.replace("(", "").replace(")", "").strip() for i in item["hazard_level"])
        else:
            item["hazard_level"] = 'Null'

        item["cn_impact"] = html.xpath(u"//td[text()='影响产品']/following-sibling::td[1]/text()")
        if item["cn_impact"]:
            item["cn_impact"] = "   ;   ".join([i.strip() for i in item["cn_impact"])
        else:
            item["cn_impact"] = 'Null'

        item["cnvd_id"] = html.xpath("//td[text()='CNVD-ID']/following-sibling::td[1]/text()")
        if item["cnvd_id"]:
            item["cnvd_id"] = "".join([i.strip() for i in item["cnvd_id"])
        else:
            item["cnvd_id"] = 'Null'

        item["cve_id"] = html.xpath("//td[text()='CVE ID']/following-sibling::td[1]//text()")
        if item["cve_id"]:
            item["cve_id"] = "".join([i.strip() for i in item["cve_id"])
        else:
            item["cve_id"] = 'Null'

        item["cn_types"] = html.xpath(u"//td[text()='漏洞类型']/following-sibling::td[1]//text()")
        if item["cn_types"]:
            item["cn_types"] = "".join([i.strip() for i in item["cn_types"])
        else:
            item["cn_types"] = 'Null'

        item["cn_describe"] = html.xpath(u"//td[text()='漏洞描述']/following-sibling::td[1]//text()")
        if item["cn_describe"]:
            item["cn_describe"] = "".join([i.strip() for i in item["cn_describe"]).replace("\u200b", "")
        else:
            item["cn_describe"] = 'Null'

        item["cn_reference"] = html.xpath(u"//td[text()='参考链接']/following-sibling::td[1]/a/@href")
        if item["cn_reference"]:
            item["cn_reference"] = item["cn_reference"][0].replace('\r', '')
        else:
            item["cn_reference"] = 'Null'

        item["cn_solution"] = html.xpath(u"//td[text()='漏洞解决方案']/following-sibling::td[1]//text()")
        if item["cn_solution"]:
            item["cn_solution"] = "".join([i.strip() for i in item["cn_solution"])
        else:
            item["cn_solution"] = 'Null'

        item["cn_patch"] = html.xpath(u"//td[text()='厂商补丁']/following-sibling::td[1]/a")
        if item["cn_patch"]:
            for i in item["cn_patch"]:
                list = []
                list.append(i.xpath("./text()")[0])
                list.append("http://www.cnvd.org.cn" + i.xpath("./@href")[0])
                item["cn_patch"] = list[0] + ':' + list[1]
        else:
            item["cn_patch"] = 'Null'

        return {
            "cnvd_id": item["cnvd_id"],
            "cnvd_date": item["date"],
            "cnvd_level": item["hazard_level"],
            "cnvd_product": item["cn_impact"],
            "cnvd_cve_id": item["cve_id"],
            "cnvd_type": item["cn_types"],
            "cnvd_description": item["cn_describe"],
            "cnvd_reference": item["cn_reference"],
            "cnvd_solution": item["cn_solution"],
            "cnvd_patch": item["cn_patch"],
        }
