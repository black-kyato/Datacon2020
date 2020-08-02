import os
import socket
import struct
import sys
from binascii import hexlify
import dpkt
from asn1crypto import x509


class Extension(object):
    """
    Encapsulates TLS extensions.
    """

    def __init__(self, payload, output):
        self._type_id, payload = unpacker('H', payload)
        self._type_name = "{}:{}".format('extension_type', self._type_id)
        self.length, payload = unpacker('H', payload)
        # Data contains an array with the 'raw' contents
        self._data = None
        # pretty_data contains an array with the 'beautified' contents
        self._pretty_data = None
        if self.length > 0:
            self._data, self._pretty_data = parse_extension(payload[:self.length],
                                                            self._type_name, output)

    def __str__(self):
        # Prints out data array in textual format
        return '{0}: {1}'.format(self._type_name, self._pretty_data)


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def parse_pcap(file_name, out_file):
    try:
        with open(file_name, "rb") as f:
            output = open(out_file, "w")
            pcap = dpkt.pcap.Reader(f)
            for time_stamp, package in pcap:
                eth = dpkt.ethernet.Ethernet(package)
                # ip package
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                # tcp package
                if isinstance(eth.data.data, dpkt.tcp.TCP) and len(eth.data.data.data) and eth.data.data.sport:
                    parse_tcp_packet(eth.data, time_stamp, output)
            output.close()
    except IOError:
        print("cannot open file " + file_name)


def parse_tcp_packet(ip_package, time_stamp, output):
    stream = ip_package.data.data
    """ refer: The Transport Layer Security (TLS) Protocol URL:https://tools.ietf.org/html/rfc5246
    enum {
          change_cipher_spec(20), alert(21), handshake(22),
          application_data(23), (255)
      } ContentType;
    """
    # ssl flow
    if (stream[0]) in {20, 21, 22, 23}:
        if (stream[0]) in {20, 21, 22}:
            parse_tls_connect(ip_package, stream, time_stamp, output)
        else:
            connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip_package.src),
                                                  ip_package.data.sport,
                                                  socket.inet_ntoa(ip_package.dst),
                                                  ip_package.data.dport)
            output.write("{}: App Data\n{}\n{}\n{}\n".format(stream[0], time_stamp, connection, stream))


def parse_tls_connect(ip_package, stream, time_stamp, output):
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
    except dpkt.ssl.SSL3Exception as exception:
        print('exception while parsing TLS records: {0}'.format(exception))
        return
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip_package.src),
                                          ip_package.data.sport,
                                          socket.inet_ntoa(ip_package.dst),
                                          ip_package.data.dport)
    for record in records:
        type = record.type
        output.write("{}: ".format(type))
        if type == 20:
            # change_cipher_spec
            output.write('Change cipher - encrypted messages from now on\n{}\n{}\n{}\n'.format(time_stamp, connection,
                                                                                               record.data))
        if type == 21:
            # alert
            output.write('Encrypted TLS Alert message\n{}\n{}\n{}\n'.format(time_stamp, connection, record.data))
        if type == 22:
            # handshake
            parse_tls_handshake(ip_package, record.data, record.length, time_stamp, output)


def parse_tls_handshake(ip_package, data, length, time_stamp, output):
    connection = '{0}:{1}-{2}:{3}'.format(socket.inet_ntoa(ip_package.src),
                                          ip_package.data.sport,
                                          socket.inet_ntoa(ip_package.dst),
                                          ip_package.data.dport)
    handshake_type = ord(data[:1])
    if handshake_type == 4:
        print('New Session Ticket is not implemented yet')
        output.write('New Session Ticket is not implemented yet\n{}\n{}\n{}\n'.format(time_stamp, connection, data))
        return

    total_len_consumed = 0
    while total_len_consumed < length:
        buffers = data[total_len_consumed:]
        try:
            handshake = dpkt.ssl.TLSHandshake(buffers)
        except dpkt.ssl.SSL3Exception as exception:
            print('exception while parsing TLS handshake record: {0}'.format(exception))
            output.write('exception while parsing TLS handshake record: {0}\n'.format(exception))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
            break
        except dpkt.dpkt.NeedData as exception:
            print('exception while parsing TLS handshake record: {0}'.format(exception))
            output.write('exception while parsing TLS handshake record: {0}\n'.format(exception))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
            break
        try:
            ch = handshake.data
        except UnboundLocalError as exception:
            print('exception while parsing TLS handshake record: {0}'.format(exception))
            output.write('exception while parsing TLS handshake record: {0}\n'.format(exception))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
            break
        total_len_consumed += handshake.length + 4

        client = '{0}:{1}'.format(socket.inet_ntoa(ip_package.src), ip_package.data.sport)
        server = '{0}:{1}'.format(socket.inet_ntoa(ip_package.dst), ip_package.data.dport)

        if handshake.type == 0:
            output.write('<-  Hello Request {0} <- {1}\n'.format(client, server))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
        if handshake.type == 1:
            output.write('-> ClientHello {0} -> {1}\n'.format(client, server))
            output.write('{}\n{}\n'.format(time_stamp, connection))
            parse_client_hello(handshake, output)
            output.write('{}\n'.format(data))
        if handshake.type == 2:
            output.write('-> ServerHello {0} -> {1}\n'.format(client, server))
            output.write('{}\n{}\n'.format(time_stamp, connection))
            parse_server_hello(handshake, output)
            output.write('{}\n'.format(data))
        if handshake.type == 11:
            # TLSCertificate
            output.write('<-  Certificate {1} <- {0}'.format(client, server))
            output.write('{}\n{}\n'.format(time_stamp, connection))
            hd_data = handshake.data
            assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
            certs = []
            for i in range(len(hd_data.certificates)):
                output.write("certificates[i]:")
                output.buffer.write(hd_data.certificates[i])
                output.write("\n")
                cert = x509.Certificate.load(hd_data.certificates[i])
                sha = cert.sha256_fingerprint.replace(" ", "")
                output.write(sha)
        if handshake.type == 12:
            output.write('<-  ServerKeyExchange {1} <- {0}'.format(server, client))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
        if handshake.type == 13:
            output.write('<-  CertificateRequest {1} <- {0}'.format(client, server))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
        if handshake.type == 14:
            output.write('<-  ServerHelloDone {1} <- {0}'.format(client, server))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
        if handshake.type == 15:
            output.write(' -> CertificateVerify {0} -> {1}'.format(client, server))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
        if handshake.type == 16:
            output.write(' -> ClientKeyExchange {0} -> {1}'.format(client, server))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))
        if handshake.type == 20:
            output.write(' -> Finished {0} -> {1}'.format(client, server))
            output.write('{}\n{}\n{}\n'.format(time_stamp, connection, data))


def parse_server_hello(handshake, output):
    """
    Parses server hello handshake.
    """
    payload = handshake.data.data
    session_id, payload = unpacker('p', payload)
    cipher_suite, payload = unpacker('H', payload)
    output.write('Cipher: {0}'.format("{}: {}\n".format('cipher_suites',
                                                        cipher_suite)))
    compression, payload = unpacker('B', payload)
    output.write('Compression: {0}'.format("{}: {}\n".format('compression_methods',
                                                             compression)))
    extensions = parse_extensions(payload, output)
    for extension in extensions:
        output.write('{0}\n'.format(extension))


def parse_client_hello(handshake, output):
    hello = handshake.data
    payload = handshake.data.data
    session_id, payload = unpacker('p', payload)
    cipher_suites, pretty_cipher_suites = parse_extension(payload, 'cipher_suites', output)
    output.write('TLS Record Layer Length: {0}\n'.format(len(handshake)))
    output.write('Client Hello Version: {0}\n'.format(dpkt.ssl.ssl3_versions_str[hello.version]))
    output.write('Client Hello Length: {0}\n'.format(len(hello)))
    output.write('Session ID: {0}\n'.format(hexlify(session_id)))
    output.write('[*]   Ciphers: {0}\n'.format(pretty_cipher_suites))
    # consume 2 bytes for each cipher suite plus 2 length bytes
    payload = payload[(len(cipher_suites) * 2) + 2:]
    compressions, pretty_compressions = parse_extension(payload, 'compression_methods', output)
    output.write('[*]   Compression methods: {0}\n'.format(pretty_compressions))
    # consume 1 byte for each compression method plus 1 length byte
    payload = payload[len(compressions) + 1:]
    extensions = parse_extensions(payload, output)
    for extension in extensions:
        output.write('{0}\n'.format(extension))


def parse_extensions(payload, output):
    """
    Parse data as one or more TLS extensions.
    """
    extensions = []
    if len(payload) <= 0:
        return []
    output.write('[*]   Extensions:\n')
    extensions_len, payload = unpacker('H', payload)
    output.write('Extensions Length: {0}\n'.format(extensions_len))
    while len(payload) > 0:
        extension = Extension(payload, output)
        extensions.append(extension)
        # consume 2 bytes for type and 2 bytes for length
        payload = payload[extension.length + 4:]
    return extensions


def parse_extension(payload, type_name, output):
    """
    Parses an extension based on the type_name.
    Returns an array of raw values as well as an array of prettified values.
    """
    entries = []
    pretty_entries = []
    format_list_length = 'H'
    format_entry = 'B'
    list_length = 0
    if type_name == 'elliptic_curves':
        format_list_length = 'H'
        format_entry = 'H'
    if type_name == 'ec_point_formats':
        format_list_length = 'B'
    if type_name == 'compression_methods':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'heartbeat':
        format_list_length = 'B'
        format_entry = 'B'
    if type_name == 'next_protocol_negotiation':
        format_entry = 'p'
    else:
        if len(payload) > 1:  # contents are a list
            list_length, payload = unpacker(format_list_length, payload)
    output.write('type {0}, list type is {1}, number of entries is {2}\n'.
                 format(type_name, format_list_length, list_length))
    if type_name == 'status_request' or type_name == 'status_request_v2':
        _type, payload = unpacker('B', payload)
        format_entry = 'H'
    if type_name == 'padding':
        return payload, hexlify(payload)
    if type_name == 'SessionTicket_TLS':
        return payload, hexlify(payload)
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if type_name == 'supported_groups':
        format_entry = 'H'
    if type_name == 'signature_algorithms':
        format_entry = 'H'
    if type_name == 'cipher_suites':
        format_entry = 'H'
    if list_length:
        payload = payload[:list_length]
    while len(payload) > 0:
        if type_name == 'server_name':
            _type, payload = unpacker('B', payload)
            format_entry = 'P'
        if type_name == 'application_layer_protocol_negotiation':
            format_entry = 'p'
        entry, payload = unpacker(format_entry, payload)
        entries.append(entry)
        if type_name == 'signature_algorithms':
            pretty_entries.append('{0}-{1}'.format("{}: {}".format('signature_algorithms_hash', entry >> 8),
                                                   "{}: {}".format('signature_algorithms_signature', entry % 256)))
        else:
            if format_entry.lower() == 'p':
                pretty_entries.append(entry)
            else:
                pretty_entries.append("{}: {}".format(type_name, entry))
    return entries, pretty_entries


def unpacker(type_string, packet):
    """
    Returns network-order parsed data and the packet minus the parsed data.
    """
    if type_string.endswith('H'):
        length = 2
    if type_string.endswith('B'):
        length = 1
    if type_string.endswith('P'):  # 2 bytes for the length of the string
        length, packet = unpacker('H', packet)
        type_string = '{0}s'.format(length)
    if type_string.endswith('p'):  # 1 byte for the length of the string
        length, packet = unpacker('B', packet)
        type_string = '{0}s'.format(length)
    data = struct.unpack('!' + type_string, packet[:length])[0]
    if type_string.endswith('s'):
        data = data
    return data, packet[length:]


# 原始数据路径
ROOT_PATH = "F:\\ssl\\first\\train\\"
# 解析输出路径, 可自动创建文件夹
OUTPUT_PATH = "F:\\ssl\\first\\output\\"

for _, sub_dir, _ in os.walk(ROOT_PATH):
    for each_dir in sub_dir:
        # 子文件夹，white black
        if not os.path.exists(OUTPUT_PATH + each_dir):
            os.makedirs(OUTPUT_PATH + each_dir)
        for target_file in os.listdir(ROOT_PATH + each_dir):
            # 子文件
            file_name = ROOT_PATH + each_dir + '\\' + target_file
            out_file = OUTPUT_PATH + each_dir + '\\' + target_file.replace("pcap", "txt")
            parse_pcap(file_name, out_file)
