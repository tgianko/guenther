'''
Created on Jan 26, 2015

@author: gianko

TODO: import these functionality into guenther.

'''
import sys, csv


if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as csvfile:
        r = csv.reader(csvfile, delimiter=';')
        w = csv.writer(sys.stdout, csvfile, delimiter=';')
        in_data = []
        for row in r:
            if row[0].startswith("htt") and "classes_of_states" in row[1]:
                in_data.append(row)
        
        
        """
        
        FULL is:
        - b_i=P_CLOSED
        - b_j=P_FILTERED
        - b_p=P_OPEN
        
        OPEN_ONLY is (Open ports are distinguishable):
        - b_i=P_OPEN
        - b_j=P_FILTERED | P_CLOSED
        
        Partial OPEN_ONLY is (Open ports are partly distinguishable. The rest may be open, closed, or filtered):
        - b_i=P_OPEN
        - b_j=P_FILTERED | P_CLOSED | P_OPEN
        or:
        - b_i=P_OPEN
        - b_j=P_CLOSED (P_FILTERED)  | P_OPEN
        - b_p=P_FILTERED (or P_CLOSE)
        or
        - b_i=P_OPEN
        - b_j=P_CLOSED (P_FILTERED)   | P_OPEN
        - b_p=P_FILTERED (or P_CLOSE) | P_OPEN
        
        FULL_INDIST:
        -b_i=P_OPEN | P_CLOSED | P_FILTERED
        
        INDIST*:
        -b_i=P_OPEN | P_FILTERED
        -b_j=P_OPEN | P_CLOSED
        
        """
        
        def at_least_one_p_open_dist(data):
            for d in data:
                if "P_OPEN" in d[3] and "P_FILTERED" not in d[3] and "P_CLOSED" not in d[3]:
                    return True
            return False

        def all_p_open_dist(data):
            for d in data:
                if "P_OPEN" in d[3] and ("P_FILTERED" in d[3] or "P_CLOSED" in d[3]):
                    return False
            return True
        
        def all_p_close_dist(data):
            for d in data:
                if "P_CLOSE" in d[3] and ("P_FILTERED" in d[3] or "P_OPEN" in d[3]):
                    return False
            return True
        
        def all_p_filtered_dist(data):
            for d in data:
                if "P_FILTERED" in d[3] and ("P_OPEN" in d[3] or "P_CLOSED" in d[3]):
                    return False
            return True
        
        def all_p_indist(data):
            for d in data:
                if "P_OPEN" in d[3] and "P_FILTERED" in d[3] and "P_CLOSED" in d[3]:
                    return True
            return False

        out_data = []
        url = row[0]

        if all_p_open_dist(in_data) and all_p_close_dist(in_data) and all_p_filtered_dist(in_data):
            out_data.append([url, "port_scanning", "P_FULL"])
        elif all_p_open_dist(in_data):
            out_data.append([url, "port_scanning", "P_OPEN_ONLY"])
        elif at_least_one_p_open_dist(in_data):
            if all_p_close_dist(in_data):
                out_data.append([url, "port_scanning", "P_PART_OPEN_W_FULL_CLOSED"])
            elif all_p_filtered_dist(in_data):
                out_data.append([url, "port_scanning", "P_PART_OPEN_W_FULL_FILTERED"])
            else:
                out_data.append([url, "port_scanning", "P_PART_OPEN"])
        else:
            if all_p_indist(in_data):
                out_data.append([url, "port_scanning", "P_INDIST"])
            else:
                out_data.append([url, "port_scanning", "P_INDIST*"])
        
        """
        Host discovery
        
        FULL:
        - b_i = ONLINE
        - b_j = OFFLINE
        
        PART_ONLINE:
        - b_i = ONLINE
        - b_j = ONLINE | OFFLINE
        
        INDIST
        - b_i = ONLINE | OFFLINE
        """
        def all_h_onoffline_dist(data):
            for d in data:
                if "H_ONLINE" in d[3] and "H_OFFLINE" in d[3]:
                    return False
            return True
        
        def at_least_h_online_dist(data):
            for d in data:
                if "H_ONLINE" in d[3] and "H_OFFLINE" not in d[3]:
                    return True
            return False
        
        if all_h_onoffline_dist(in_data):
            out_data.append([url, "host_discovery", "H_FULL"])
        elif at_least_h_online_dist(in_data):
            out_data.append([url, "host_discovery", "H_PART_ONLINE"])
        else:
            out_data.append([url, "host_discovery", "H_INDIST"])
        
        """
        Application fingerprinting:
        
        FULL:
        - b_i = EXIST
        - b_j = NEXIST404
        - b_p = NEXIST
        
        FULL*:
        - b_i = EXIST
        - b_j = NEXIST | NEXIST404
        
        PART_EXIST:
        - b_i = EXIST
        - b_j = EXIST | NEXIST | NEXIST404
        
        INDIST:
        - b_i = EXIST | NEXIST404 | NEXIST        
        """
        
        def all_r_exists_dist(data):
            for d in data:
                if "R_EXIST" in d[3] and ("R_NEXISTS_404" in d[3] or "R_NEXISTS" in d[3]):
                    return False
            return True

        def all_r_nexists_dist(data):
            for d in data:
                if "R_NEXISTS" in d[3] and ("R_NEXISTS_404" in d[3] or "R_EXIST" in d[3]):
                    return False
            return True

        def all_r_nexists404_dist(data):
            for d in data:
                if "R_NEXISTS_404" in d[3] and ("R_EXIST" in d[3] or "R_NEXISTS" in d[3]):
                    return False
            return True

        def at_least_exist_dist(data):
            for d in data:
                if "R_EXIST" in d[3] and "R_NEXISTS_404" not in d[3] and "R_NEXISTS" not in d[3]:
                    return True
            return False

        def at_least_nexist404_dist(data):
            for d in data:
                if "R_NEXISTS_404" in d[3] and "R_EXIST" not in d[3] and "R_NEXISTS" not in d[3]:
                    return True
            return False

        def at_least_nexist_dist(data):
            for d in data:
                if "R_NEXISTS" in d[3] and "R_EXIST" not in d[3] and "R_NEXISTS_404" not in d[3]:
                    return True
            return False

        if all_r_exists_dist(in_data) and all_r_nexists_dist(in_data) and all_r_nexists404_dist(in_data):
            out_data.append([url, "app_fingerprinting", "R_FULL"])
        elif all_r_exists_dist(in_data):
            out_data.append([url, "app_fingerprinting", "R_FULL*"])
        elif at_least_exist_dist(in_data):
            if at_least_nexist404_dist(in_data):
                out_data.append([url, "app_fingerprinting", "R_PART_EXISTS_FULL_NEXISTS404"])
            elif at_least_nexist_dist(in_data):
                out_data.append([url, "app_fingerprinting", "R_PART_EXISTS_FULL_NEXISTS"])
            else:
                out_data.append([url, "app_fingerprinting", "R_PART_EXISTS"])
        else:
            out_data.append([url, "app_fingerprinting", "R_INDIST"])
            
            
            
        for row in out_data:
            w.writerow(row)