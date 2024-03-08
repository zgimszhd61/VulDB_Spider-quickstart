#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from pyspider.libs.base_handler import *


class Handler(BaseHandler):
    crawl_config = {
    }

    @every(minutes=24 * 60)
    def on_start(self):
        # 开始爬取入口页面
        self.crawl('https://nvd.nist.gov/vuln/full-listing/', callback=self.index_page)

    @config(age=10 * 24 * 60 * 60)
    def index_page(self, response):
        # 获取按年月分类的链接
        for each in response.doc('#body-section > div:nth-child(2) a[href^="http"]').items():
            self.crawl(each.attr.href, callback=self.index2_page)

    def index2_page(self, response):
        # 获取所属分类的具体CVE链接
        for each in response.doc('#body-section > div:nth-child(2) > div a[href^="http"]').items():
            self.crawl(each.attr.href, callback=self.detail_page)

    @config(priority=2)
    def detail_page(self, response):
        items = response.etree.xpath('//div[@class="col-lg-9 col-md-7 col-sm-12"]')
        for item in items:
            # 解析CVE链接页面的字段
            vuln_description = ''.join(item.xpath('//p[@data-testid="vuln-description"]/text()')).strip()
            cvss3_nvd_base_score = ''.join(item.xpath('//*[@data-testid="vuln-cvss3-panel-score"]/text()')).strip()
            cvss3_nvd_vector = ''.join(item.xpath('//*[@data-testid="vuln-cvss3-nist-vector"]/text()')).strip()
            cvss2_nvd_base_score = ''.join(item.xpath('//*[@id="p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_Cvss2CalculatorAnchor"]/text()')).strip()
            cvss2_nvd_vector = ''.join(item.xpath('//*[@data-testid="vuln-cvss2-panel-vector"]/text()')).strip()
            references = '\n'.join(item.xpath('//*[@data-testid="vuln-hyperlinks-table"]//a/text()')).strip()
            cwe_id = '\n'.join(item.xpath('//*[@data-testid="vuln-CWEs-link-0"]/a/text()')).strip()
            cwe_name = '\n'.join(item.xpath('//*[@data-testid="vuln-CWEs-link-0"]/text()')).strip()
            cpe = '\n'.join(item.xpath('//*[@data-testid="vuln-configurations-container"]//b[@data-testid]/text()')).strip()

        return {
            "vuln_description": vuln_description,
            "cvss3_nvd_base_score": cvss3_nvd_base_score,
            "cvss3_nvd_vector": cvss3_nvd_vector,
            "cvss2_nvd_base_score": cvss2_nvd_base_score,
            "cvss2_nvd_vector": cvss2_nvd_vector,
            "references": references,
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "cpe": cpe,
        }
