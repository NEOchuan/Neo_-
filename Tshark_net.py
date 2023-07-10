import pyshark

# 打开Wireshark捕获的pcap文件
cap = pyshark.FileCapture('capture.pcap')

# 遍历数据包并打印相关信息
for pkt in cap:
    print(pkt)

# 关闭捕获会话
cap.close()
