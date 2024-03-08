#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

import requests
from lxml import etree
import csv
import time
import random
from collections import OrderedDict
import codecs
from datetime import date
from multiprocessing.dummy import Pool as Threadpool
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import ast

class Cnvdspider(object):
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.16 Safari/537.36"}
        self.count = 0
        self.cookies = self.get_cookies()

    def get_cookies(self):
        chrome_options = Options()
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        driver = webdriver.Chrome(chrome_options=chrome_options)
        driver.get("https://www.cnvd.org.cn/flaw/list.htm?max=20&offset=20")
        cj = driver.get_cookies()
        cookie = ''
        for c in cj:
            cookie += "'"+c['name'] + "':'" + c['value'] + "',"
        cookie = ast.literal_eval('{'+cookie+'}')
        driver.quit()
        return cookie

    def parse(self, i):
        time.sleep(random.randint(2, 5))
        self.count += 1
        print(self.count)
        if(self.count == 5):
            self.cookies = self.get_cookies()
            self.count = 0
        url='https://www.cnvd.org.cn/flaw/list.htm?%s' % str(i)
        html = requests.post(url, data={'max': 100, 'offset': str(i)}, headers=self.headers,
                            cookies=self.cookies).content.decode()
        html = etree.HTML(html)
        return html

    def parse2(self, url):
        time.sleep(random.randint(2, 5))
        self.count += 1
        print(self.count)
        if(self.count == 5):
            self.cookies = self.get_cookies()
            self.count = 0
        html = requests.get(url, headers=self.headers,
                            cookies=self.cookies).content.decode()
        html = etree.HTML(html)
        return html

    def get_list_url(self, html):
        list_url = html.xpath("//div[@id='flawList']/tbody/tr/td[1]/a/@href")
        if list_url is None:
            list_url = html.xpath(
                "//div[@class='blkContainerPblk']//table[@class='tlist']/tbody/tr/td[1]/a/@href")
        for url in list_url:
            url = "http://www.cnvd.org.cn" + url
            self.parse_detail(url)

    def parse_detail(self, url):
        time.sleep(random.randint(2, 5))
        html = self.parse2(url)
        item = {}
        item["cn_url"] = url
        item["cn_title"] = html.xpath(
            "//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")
        if item["cn_title"]:
            item["cn_title"] = html.xpath("//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")[
                0].strip()
        else:
            item["cn_title"] = 'Null'

        item["pub_date"] = html.xpath(
            "//div[@class='tableDiv']/table[@class='gg_detail']//tr[2]/td[2]/text()")
        if item["pub_date"]:
            item["pub_date"] = "".join(
                [i.strip() for i in item["pub_date"]])
        else:
            item["pub_date"] = '2000-01-01'

        item["hazard_level"] = html.xpath(
            "//td[text()='危害级别']/following-sibling::td[1]/text()")
        if item["hazard_level"]:
            item["hazard_level"] = "".join(
                [i.replace("(", "").replace(")", "").strip() for i in item["hazard_level"]])
        else:
            item["hazard_level"] = 'Null'

        item["cn_impact"] = html.xpath(
            "//td[text()='影响产品']/following-sibling::td[1]/text()")
        if item["cn_impact"]:
            item["cn_impact"] = "   ;   ".join(
                [i.strip() for i in item["cn_impact"]])
        else:
            item["cn_impact"] = 'Null'

        item["cnvd_id"] = html.xpath(
            "//td[text()='CNVD-ID']/following-sibling::td[1]/text()")
        if item["cnvd_id"]:
            item["cnvd_id"] = "".join(
                [i.strip() for i in item["cnvd_id"]])
        else:
            item["cnvd_id"] = 'Null'

        item["cve_id"] = html.xpath(
            "//td[text()='CVE ID']/following-sibling::td[1]//text()")
        if item["cve_id"]:
            item["cve_id"] = "".join(
                [i.strip() for i in item["cve_id"]])
        else:
            item["cve_id"] = 'Null'

        item["cn_types"] = html.xpath(
            "//td[text()='漏洞类型']/following-sibling::td[1]//text()")
        if item["cn_types"]:
            item["cn_types"] = "".join(
                [i.strip() for i in item["cn_types"]])
        else:
            item["cn_types"] = 'Null'

        item["cn_describe"] = html.xpath(
            "//td[text()='漏洞描述']/following-sibling::td[1]//text()")
        if item["cn_describe"]:
            item["cn_describe"] = "".join(
                [i.strip() for i in item["cn_describe"]]).replace("\u200b", "")
        else:
            item["cn_describe"] = 'Null'

        item["cn_reference"] = html.xpath(
            "//td[text()='参考链接']/following-sibling::td[1]/a/@href")
        if item["cn_reference"]:
            item["cn_reference"] = item["cn_reference"][0].replace('\r', '')
        else:
            item["cn_reference"] = 'Null'

        item["cn_solution"] = html.xpath(
            "//td[text()='漏洞解决方案']/following-sibling::td[1]//text()")
        if item["cn_solution"]:
            item["cn_solution"] = "".join(
                [i.strip() for i in item["cn_solution"]])
        else:
            item["cn_solution"] = 'Null'

        item["cn_patch"] = html.xpath(
            "//td[text()='厂商补丁']/following-sibling::td[1]/a")
        if item["cn_patch"]:
            for i in item["cn_patch"]:
                list = []
                try:
                    list.append(i.xpath("./text()")[0])
                    list.append("http://www.cnvd.org.cn" + i.xpath("./@href")[0])
                    item["cn_patch"] = list[0] + ':' + list[1]
                except IndexError:
                    pass            
        else:
            item["cn_patch"] = 'Null'

        print(item)
        self.save_data(item)

    def convertstringtodate(self, stringtime):
        if stringtime[0:2] == "20":
            year = stringtime[0:4]
            month = stringtime[4:6]
            day = stringtime[6:8]
            if day == "":
                day = "01"
            begintime = date(int(year), int(month), int(day))
            return begintime
        else:
            year = "20" + stringtime[0:2]
            month = stringtime[2:4]
            day = stringtime[4:6]

            begintime = date(int(year), int(month), int(day))
            return begintime

    def save_data(self, item):
        with open("./cnvd-1290ye.csv", "a") as f:
            writer = csv.writer(f, codecs.BOM_UTF8)
            c = []
            for i in item.values():
                c.append(i)
            writer.writerow(c)

    def run(self):
        for i in range(128900,129900,100):
            html = self.parse(i)
            print(i)
            next_url = self.get_list_url(html)
            print(next_url)

if __name__ == "__main__":
    a = Cnvdspider()
    pool = Threadpool(1)
    a.run()
    pool.close()
    pool.join()
