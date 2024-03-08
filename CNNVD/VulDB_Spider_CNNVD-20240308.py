#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from pyspider.libs.base_handler import *


class Handler(BaseHandler):
    crawl_config = {
        'headers': {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'keep-alive',
            'Cookie': 'SESSION=填你自己的; topcookie=a1',
            'Host': 'www.cnnvd.org.cn',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.87 Safari/537.36',
            'Cache-Control': 'max-age=0'
        }
    }

    @every(minutes=3*24*60)  # 定期执行时间设置
    def on_start(self):
        # 输入爬取页数
        for i in range(1, 14377):
            url = 'http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=%s' % str(i)
            self.crawl(url, callback=self.index_page)

    @config(age=3 * 24 * 60 * 60)  # 数据过期时间设置
    def index_page(self, response):
        # 解析列表页
        for each in response.doc('div.fl > a[href^="http"]').items():
            self.crawl(each.attr.href, callback=self.detail_page)

    @config(priority=2)
    def detail_page(self, response):
        # 解析详情页
        cnnvd_title = response.doc('.detail_xq > h2:nth-child(1)').text()
        cnnvd_id = response.doc('.detail_xq > ul:nth-child(2) > li:nth-child(1) > span:nth-child(1)').text()
        cnnvd_level = response.doc('.detail_xq > ul:nth-child(2) > li:nth-child(2) > a:nth-child(2)').text()
        cve_id = response.doc('.detail_xq > ul:nth-child(2) > li:nth-child(3) > a:nth-child(2)').text()
        vulnerable_type = response.doc('.detail_xq > ul:nth-child(2) > li:nth-child(4) > a:nth-child(2)').text()
        upload_time = response.doc('.detail_xq > ul:nth-child(2) > li:nth-child(5) > a:nth-child(2)').text()
        threat_type = response.doc('.detail_xq > ul:nth-child(2) > li:nth-child(6) > a:nth-child(2)').text()
        update = response.doc('.detail_xq > ul:nth-child(2) > li:nth-child(7) > a:nth-child(2)').text()
        vulnerable_detail = response.doc('div.d_ldjj:nth-child(4)').text()
        vulnerable_notice = response.doc('div.d_ldjj:nth-child(5)').text()
        reference_url = response.doc('div.d_ldjj:nth-child(6)').text()
        patch = response.doc('div.d_ldjj:nth-child(10)').text()

        return {
            "cve_id": cve_id,
            "cnnvd_id": cnnvd_id,
            "cnnvd_url": response.url,
            "title": cnnvd_title,
            "level": cnnvd_level,
            "patch": patch,
            "reference_url": reference_url,
            "cnnvd_threat_type": threat_type,
            "cnnvd_upload_time": upload_time,
            "pub_date": update,
            "detail": vulnerable_detail,
            "solution": vulnerable_notice,
            "cnnvd_type": vulnerable_type,
        }
