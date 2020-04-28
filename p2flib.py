from __future__ import print_function, division
from subprocess import check_call
from subprocess import CalledProcessError
import subprocess
# from CythonUtil import c_parse_records_tshark
 

#<start time stamp> <src ip> <src port> <dst ip> <dst port> <protocol> <flow size> <num packets> <flow duration>
def parse_records_tshark(f_name):
    records = []
    NAME = ['start_time', 'date_time','src_ip', 'src_port', 'dst_ip', 'dst_port','protocol', 'length']
    skipped = []
    with open(f_name, 'r') as infile:
        for line in infile:
            line = line.strip()
            # print(line)
            items = line.split()
            if(len(items) != 8): # not a standard entry
                # print('non-standard record:' + line)
                skipped.append(line)
                continue

            try:
                rec = (float(items[0]), items[1], items[2], items[3], items[4],
                    items[5], items[6], int(items[7]))
            except ValueError as e:
                    skipped.append(line)
                    pass
            records.append(rec)
            # print(str(skipped) + ' records')
    return records, NAME, skipped

def export_to_txt(f_name, txt_f_name):
    cmd = """tshark -o column.format:'"Time", "%%t","DateTime", "%%Aut", "Source", "%%s", "srcport", "%%uS", "Destination", "%%d", "dstport", "%%uD", "Protocol", "%%p", "len", "%%L"' -r %s > %s""" % (f_name, txt_f_name)

    print('--> ', cmd)
    try:
        ret = check_call(cmd, shell=True)
        print('pcap to text converted with full tcp conv: ' + txt_f_name)
    except CalledProcessError as e: # non-zero return; ignore
        print("non-zero exit on cmd with code = " + str(e.returncode) + ", and message:\n" + str(e.output))
        pass

def change_to_flows(records, name, time_out, skip_count):
    return records

def write_flow(flows, f_name):
    fid = open(f_name, 'w')
    for f in flows:
        fid.write(' '.join([str(v) for v in f]) + '\n')
    fid.close()

def pcap2flow(pcap_file_name, flow_file_name, time_out):
    # txt_f_name = generate_full_con(pcap_file_name)
    print('generate .pcap file with full TCP flows')
    cmd = './filter-full-conv.sh ' + pcap_file_name

    prefix = 'full_conv_'
    print('--> ', cmd)
    try:
        ret = check_call(cmd, shell=True, stderr=subprocess.PIPE)
        print(pcap_file_name + ' converted to full tcp pcap: ' + prefix + pcap_file_name)
    except CalledProcessError as e: # non-zero return; ignore
        print("non-zero exit on cmd with code = " + str(e.returncode) + ", and message:\n" + str(e.output))
        pass

    txt_f_name = pcap_file_name.rsplit('.pcap')[0] + '_tshark.txt'
    txt_f_name = prefix + txt_f_name

    export_to_txt(pcap_file_name, txt_f_name)
    records, name, skipped = parse_records_tshark(txt_f_name)
    relevant_packets = len(records)
    skip_count = len(skipped)

    res_flows = change_to_flows(records, name, time_out,len(skipped))

    write_flow(res_flows, prefix + flow_file_name)
    
    with open(pcap_file_name + '.skipped', "w") as outfile:
        outfile.write("\n".join(skipped))

    print('========== Summary ========== ')
    print('total packets = ' + str(relevant_packets + skip_count) 
        + ', relevant packets = ' + str(relevant_packets)
        + ', skipped = ' + str(skip_count))
    print('text to flow converted with full tcp conv: ' + prefix + flow_file_name)
    print('skipped packet metadata in: ' + pcap_file_name + '.skipped')
