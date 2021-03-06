from __future__ import print_function, division
from subprocess import check_call
from subprocess import CalledProcessError
import subprocess
# from CythonUtil import c_parse_records_tshark
 

#<start time stamp> <date> <time> <src ip> <src port> <dst ip> <dst port> <protocol> <flow size> <num packets> <flow duration>
def parse_records_tshark(f_name):
    records = []
    NAME = ['start_time', 'date', 'time','src_ip', 'src_port', 'dst_ip', 'dst_port','protocol', 'length']
    skipped = []
    with open(f_name, 'r') as infile:
        for line in infile:
            line = line.strip()
            # print(line)
            items = line.split()
            if(len(items) != 9): # not a standard entry
                # print('non-standard record:' + line)
                skipped.append(line)
                continue

            try:
                rec = (float(items[0]), items[1], items[2], items[3], items[4],
                    items[5], items[6], items[7], int(items[8]))
            except ValueError as e:
                    skipped.append(line)
                    pass
            records.append(rec)
            # print(str(skipped) + ' records')
    return records, NAME, skipped

def export_to_txt(f_name, txt_f_name):
    cmd = """tshark -o column.format:'"Time", "%%t","DateTime", "%%Yt", "Source", "%%s", "srcport", "%%uS", "Destination", "%%d", "dstport", "%%uD", "Protocol", "%%p", "len", "%%L"' -r %s > %s""" % (f_name, txt_f_name)

    print('--> ', cmd)
    try:
        ret = check_call(cmd, shell=True)
        print('pcap to text converted with full tcp conv: ' + txt_f_name)
    except CalledProcessError as e: # non-zero return; ignore
        print("non-zero exit on cmd with code = " + str(e.returncode) + ", and message:\n" + str(e.output))
        pass

def change_to_flows(records, name, time_out, skip_count):
    # print('change_to_flows: len(records) = ' + str(len(records)))
    # print(records) 
    t_seq = name.index('start_time')
    # dt_seq = name.index('date_time')
    dt_seq = name.index('date')
    time_seq = name.index('time')
    length_seq = name.index('length')
    protocol_seq = name.index('protocol')
    five_tuple_seq = [name.index(k) for k in ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol']]
    # print(five_tuple_seq)
    # five_tuple_seq = [name.index(k) for k in ['src_ip', 'dst_ip', 'protocol']]
    open_flows = dict()
    res_flow = []
    for rec in records:
        # five_tuple = get_five_tuple(rec)
        # print(rec)
        five_tuple = tuple(rec[seq] for seq in five_tuple_seq) # becomes key to the open_flows dict
        t = rec[t_seq]
        date = rec[dt_seq]
        time = rec[time_seq]
        length = rec[length_seq]
        protocol = rec[protocol_seq].strip().upper()
        # check time out
        remove_flows = []
        count = 0
        # for key, value
        for f_tuple, (st_time, date, time, last_time, last_count, fs) in open_flows.items():
            # print('t = ' + str(t) + ', last_time = ' + str(last_time) + ', time_out = ' + str(time_out))
            if t - last_time > time_out: # time out
                fd = t - st_time
                res_flow.append( (st_time, date, time, ) + f_tuple + (fs, last_count, fd))
                remove_flows.append(f_tuple)
        for f_tuple in remove_flows:
            del open_flows[f_tuple]

        stored_rec = open_flows.get(five_tuple, None)
        if stored_rec is not None: # if already exists
            (st_time_old, date, time, last_time_old, last_count_old, fs_old) = stored_rec
            open_flows[five_tuple] = (st_time_old, date, time, t, last_count_old+1, fs_old + length)
        else: # not existant
            open_flows[five_tuple] = (t, date, time, t, 1, length)

    # print('open_flow = ' + str(len(open_flows)))
    return res_flow, len(open_flows)

def write_flow(flows, f_name):
    fid = open(f_name, 'w')
    # header
    header = 'relative time, start date, start time, src ip, src port, dst ip, dst port, protocol, flow size, num packets, flow duration'
    fid.write(header + '\n')  


    for f in flows:
        fid.write(', '.join([str(v) for v in f]) + '\n')
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

    pcap_file_name = prefix + pcap_file_name
    txt_f_name = pcap_file_name.rsplit('.pcap')[0] + '_tshark.txt'
    # txt_f_name = prefix + txt_f_name

    export_to_txt(pcap_file_name, txt_f_name)
    records, name, skipped = parse_records_tshark(txt_f_name)
    res_flows, open_flow_count = change_to_flows(records, name, time_out,len(skipped))
    
    # exported flow
    write_flow(res_flows, prefix + flow_file_name + '.csv')
    
    with open(pcap_file_name + '.skipped', "w") as outfile:
        outfile.write("\n".join(skipped))

    relevant_packets = len(res_flows)
    skip_count = len(skipped)

    print('========== Summary ========== ')
    print('total packets = ' + str(len(records)) 
        + ', exported flows = ' + str(len(res_flows))
        + '. open flows = ' + str(open_flow_count)
        + ', skipped = ' + str(skip_count))
    print('text to flow converted with full tcp conv: ' + prefix + flow_file_name + '.csv')
    print('skipped packet metadata in: ' + pcap_file_name + '.skipped')
