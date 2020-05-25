# coding=utf-8

import json
import re
import time
import logging
import requests
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkecs.request.v20140526.DescribeRegionsRequest import DescribeRegionsRequest
from aliyunsdkecs.request.v20140526.DescribeSecurityGroupsRequest import DescribeSecurityGroupsRequest
from aliyunsdkecs.request.v20140526.DescribeSecurityGroupAttributeRequest import DescribeSecurityGroupAttributeRequest
from aliyunsdkecs.request.v20140526.RevokeSecurityGroupRequest import RevokeSecurityGroupRequest
from aliyunsdkecs.request.v20140526.AuthorizeSecurityGroupRequest import AuthorizeSecurityGroupRequest

accessKeyId = r'xxxxxxxxxxxxxxx'
accessSecret = r'xxxxxxxxxxxxxxxxxx'
ignore_ip = ['218.17.140.183']


def get_regions():
    """ 获取区域列表

    :return: 返回区域列表数组,格式
        [{
            "RegionId": "cn-shenzhen",
            "RegionEndpoint": "ecs.aliyuncs.com",
            "LocalName": "华南 1"
        },...]
    """
    client = AcsClient(accessKeyId, accessSecret, 'cn-shenzhen')
    request = DescribeRegionsRequest()
    request.set_accept_format('json')
    response = client.do_action_with_exception(request)
    return json.loads(str(response, encoding='utf-8'))['Regions']['Region']


def get_security_groups(region_id):
    """ 获取指定区域的安全组列表

    :param region_id: 区域id
    :return: 返回安全组列表，格式
        [{
            "Description": "",
            "SecurityGroupName": "放行信任IP",
            "VpcId": "vpc-wz9czt0wu7wma8289fo8f",
            "ResourceGroupId": "",
            "SecurityGroupId": "sg-wz98sywkiky9feqah7ks",
            "CreationTime": "2020-05-18T02:59:26Z",
            "SecurityGroupType": "normal",
            "Tags": {
                "Tag": []
            }
        },...]
    """
    client = AcsClient(accessKeyId, accessSecret, region_id)
    request = DescribeSecurityGroupsRequest()
    request.set_accept_format('json')

    response = client.do_action_with_exception(request)
    return json.loads(str(response, encoding='utf-8'))['SecurityGroups']['SecurityGroup']


def get_security_group_rules(region_id, security_group_id):
    """ 获取安全组规则列表

    :param region_id: 区域id
    :param security_group_id: 安全组id
    :return: 安全组规则列表,格式 :
        [{
            "SourceGroupId": "",
            "Policy": "Accept",
            "Description": "公司宽带拨号IP",
            "SourcePortRange": "-1/-1",
            "Priority": 1,
            "CreateTime": "2020-05-22T09:40:17Z",
            "Ipv6SourceCidrIp": "",
            "NicType": "intranet",
            "DestGroupId": "",
            "Direction": "ingress",
            "SourceGroupName": "",
            "PortRange": "-1/-1",
            "DestGroupOwnerAccount": "",
            "SourceCidrIp": "183.14.28.116",
            "IpProtocol": "ALL",
            "DestCidrIp": "",
            "DestGroupName": "",
            "SourceGroupOwnerAccount": "",
            "Ipv6DestCidrIp": ""
        },..]
    """
    client = AcsClient(accessKeyId, accessSecret, region_id)
    request = DescribeSecurityGroupAttributeRequest()
    request.set_accept_format('json')

    request.set_SecurityGroupId(security_group_id)
    request.set_NicType("intranet")
    request.set_Direction("ingress")

    response = client.do_action_with_exception(request)
    return json.loads(str(response, encoding='utf-8'))['Permissions']['Permission']


def del_security_group_rule(region_id, security_group_id, source_cidr_ip):
    """ 删除安全组规则

    :param region_id: 区域id
    :param security_group_id: 安全组id
    :param source_cidr_ip: 源数据ip
    """
    client = AcsClient(accessKeyId, accessSecret, region_id)
    request = RevokeSecurityGroupRequest()
    request.set_accept_format('json')

    request.set_SecurityGroupId(security_group_id)
    request.set_PortRange("-1/-1")
    request.set_IpProtocol("all")
    request.set_SourceCidrIp(source_cidr_ip)
    request.set_Policy("accept")
    request.set_NicType("intranet")

    response = client.do_action_with_exception(request)
    # python2:  print(response)
    print(str(response, encoding='utf-8'))


def add_security_group_rule(region_id, security_group_id, source_cidr_ip):
    client = AcsClient(accessKeyId, accessSecret, region_id)
    request = AuthorizeSecurityGroupRequest()
    request.set_accept_format('json')

    request.set_SecurityGroupId(security_group_id)
    request.set_IpProtocol("all")
    request.set_PortRange("-1/-1")
    request.set_SourceCidrIp(source_cidr_ip)
    request.set_Policy("accept")
    request.set_NicType("intranet")
    request.set_Description("公司宽带拨号IP")

    response = client.do_action_with_exception(request)
    # python2:  print(response)
    print(str(response, encoding='utf-8'))


def get_current_ip():
    """ 获取当前网络的公网IP

    :return: 当前网络的公网IP
    """
    url = "http://120.25.240.122/get_ip"
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload, timeout=5)
    return json.loads(str(response.text.encode('utf8'), encoding='utf-8'))['ipv4']


def is_ip(ipAddr):
    """ 判断是否为IP地址

    :param ipAddr: IP地址
    :return: 如果为IP地址，返回True。如果不是，返回False
    """
    check_ip = re.compile(
        '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
    if check_ip.match(ipAddr):
        return True
    else:
        return False


def run():
    current_ip = get_current_ip()
    if not is_ip(current_ip):
        raise Exception("current ip error")
    print(current_ip)

    if current_ip in ignore_ip:
        raise Exception("ignore ip")

    # regions = get_regions()
    s1 = r'[{"RegionId": "cn-beijing", "RegionEndpoint": "ecs.aliyuncs.com", "LocalName": "华北 2"},' \
         r' {"RegionId": "cn-shenzhen", "RegionEndpoint": "ecs.aliyuncs.com", "LocalName": "华南 1"}]'
    regions = json.loads(s1)
    for region in regions:
        # print("RegionId: " + region['RegionId'] + "  LocalName: " + region['LocalName'])
        # 获取安全组列表
        security_groups = get_security_groups(region['RegionId'])
        for security_group in security_groups:
            # print("SecurityGroupId: " + security_group['SecurityGroupId'] +
            #      "   SecurityGroupName: " + security_group['SecurityGroupName'])
            # 如果存在安全组 放行信任IP
            if security_group['SecurityGroupName'] == r'放行信任IP':
                # 获取 安全组规则列表
                security_group_rules = get_security_group_rules(region['RegionId'], security_group['SecurityGroupId'])
                flag = True
                for security_group_rule in security_group_rules:
                    # print("Description: " + security_group_rule['Description'] +
                    #     "   SourceCidrIp: " + security_group_rule['SourceCidrIp'])
                    # 如果存在安全组规则 公司宽带拨号IP
                    if security_group_rule['Description'] == r'公司宽带拨号IP':
                        flag = False
                        # 如果当前IP与安装组规则记录IP不同
                        if security_group_rule['SourceCidrIp'] != current_ip:
                            print(security_group_rule['SourceCidrIp'])
                            del_security_group_rule(region['RegionId'], security_group['SecurityGroupId'],
                                                    security_group_rule['SourceCidrIp'])
                            add_security_group_rule(region['RegionId'], security_group['SecurityGroupId'], current_ip)
                # 不存在"公司宽带拨号IP"安全组规则,则创建
                if flag:
                    add_security_group_rule(region['RegionId'], security_group['SecurityGroupId'], current_ip)


if __name__ == "__main__":
    while True:
        try:
            print(time.strftime('%Y-%m-%d %H:%M:%S') + "    start")
            run()
        except Exception as e:
            print(str(e))
        print(time.strftime('%Y-%m-%d %H:%M:%S') + "    end")
        time.sleep(60)
