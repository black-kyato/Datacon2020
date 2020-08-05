import os
import socket
import dpkt


def ave_dict(dict):
    sum = 0
    for value in dict.values():
        sum += value
    return sum / len(dict)


def max_dict(dict):
    max = 0
    for value in dict.values():
        if max < value:
            max = value
    return max


def min_dict(dict):
    min = 1000000
    for value in dict.values():
        if min > value:
            min = value
    return min


def variance_dict(dict):
    ave = ave_dict(dict)
    sum = 0
    for value in dict.values():
        sum += (value - ave) * (value - ave)
    return sum / len(dict)


# 时间差
def time_dict(dict):
    first = True
    start = 0
    dict_re = {}
    for key in dict.keys():
        if first:
            first = False
            start = key
        else:
            dict_re[start] = key - start
            start = key
    return dict_re


def display_dict(dict, output):
    if len(dict) > 0:
        output.write("{:>12.4f}{:>12.4f}{:>12.4f}{:>12.4f}{:>12}".format(ave_dict(dict), max_dict(dict), min_dict(dict),
                                                                         variance_dict(dict), len(dict)))
    else:
        output.write("{:>12}{:>12}{:>12}{:>12}{:>12}".format(0, 0, 0, 0, 0))


class Flow:
    def __init__(self, name):
        self.name = name
        self.client_hello_dict = {}
        self.alert_dict = {}
        self.change_cipher_dict = {}
        self.server_hello_dict = {}
        self.server_hello_done_dict = {}
        self.upload_app_data_dict = {}
        self.download_app_data_dict = {}
        self.dict_set = [{}]
        self.count = 0

    def stat(self, out_file):
    #   global flag
        global ip_file
        ip_file.write(self.name)
        if len(self.client_hello_dict) > 0:
            out_file.write("{:>12}{:>12.4f}".format(len(self.client_hello_dict), ave_dict(self.client_hello_dict)))
        else:
            out_file.write("{:>12}{:>12}".format(0, 0))
        if len(self.server_hello_dict) > 0:
            out_file.write("{:>12}{:>12.4f}".format(len(self.server_hello_dict), ave_dict(self.server_hello_dict)))
        else:
            out_file.write("{:>12}{:>12}".format(0, 0))
        display_dict(self.upload_app_data_dict, out_file)
        if len(self.upload_app_data_dict) > 1:
            out_file.write("{:>12.4f}".format(ave_dict(time_dict(self.upload_app_data_dict))))
        else:
            out_file.write("{:>12}".format(0))
        display_dict(self.download_app_data_dict, out_file)
        if len(self.download_app_data_dict) > 1:
            out_file.write("{:>12.4f}".format(ave_dict(time_dict(self.download_app_data_dict))))
        else:
            out_file.write("{:>12}".format(0))
        out_file.write("\n")
        ip_file.write(",\n")


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def is_client_ip(ip):
    ip_str = inet_to_str(ip)
    if ip_str[:8] == '192.168.':
        return True
    else:
        return False


def parse_pcap(file_name):
    try:
        with open(file_name, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for time_stamp, package in pcap:
                eth = dpkt.ethernet.Ethernet(package)
                # ip package
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                # tcp package
                if isinstance(eth.data.data, dpkt.tcp.TCP) and len(eth.data.data.data) and eth.data.data.sport:
                    parse_tcp_packet(eth.data, time_stamp)
    except IOError:
        print("cannot open file " + file_name)


def parse_tcp_packet(ip_package, time_stamp):
    global flow_data
    stream = ip_package.data.data
    """ refer: The Transport Layer Security (TLS) Protocol URL:https://tools.ietf.org/html/rfc5246
    enum {
          change_cipher_spec(20), alert(21), handshake(22),
          application_data(23), (255)
      } ContentType;
    """
    # ssl flow
    type = stream[0]
    if type == 20:
        # change_cipher_spec
        flow_data.alert_dict[time_stamp] = len(stream)
    if type == 21:
        # alert
        flow_data.change_cipher_dict[time_stamp] = len(stream)
    if type == 22:
        # handshake
        if is_client_ip(ip_package.src):
            flow_data.client_hello_dict[time_stamp] = len(stream)
        else:
            flow_data.server_hello_dict[time_stamp] = len(stream)
    if type in {23, 255}:
        if is_client_ip(ip_package.src):
            flow_data.upload_app_data_dict[time_stamp] = len(stream)
        else:
            flow_data.download_app_data_dict[time_stamp] = len(stream)


# 原始数据路径
ROOT_PATH = "F:\\ssl\\first\\test\\"
# 解析输出路径, 可自动创建文件夹
OUTPUT_PATH = "F:\\ssl\\first\\output\\"

if not os.path.exists(OUTPUT_PATH):
    os.makedirs(OUTPUT_PATH)
data_file = open(OUTPUT_PATH + "result_data.txt", "w")
ip_file = open(OUTPUT_PATH + "result_ip.txt", "w")
for _, sub_dir, _ in os.walk(ROOT_PATH):
    flag = 0
    for each_dir in sub_dir:
        for target_file in os.listdir(ROOT_PATH + each_dir):
            # 子文件
            file_name = ROOT_PATH + each_dir + '\\' + target_file
            flow_data = Flow(target_file.replace(".pcap", ""))
            parse_pcap(file_name)
            flow_data.stat(data_file)
data_file.close()
ip_file.close()
