from dateutil.parser import parse
import datetime
from typing import Tuple
import sys

import pandas as pd

from graph_helpers import pickle_read, pickle_write, relabels, vertex_times


def dump_graph():
    vertex_times(g)
    vertices = []
    for i in range(0,len(g.vs)):
        v = g.vs[i]
        try:
            time = int(v["min_time"])
            default_label = "benign"
            pretty_name = v["name"].lstrip("\x00")
            vertices.append("%d,%s,\"%s\",%s,%s" % (time, v["type"], pretty_name, v["uuid"], default_label))
        except Exception as e:
            print("Error: %s" % (e))
            pdb.set_trace()
            
    for vertex in vertices:
        print(vertex)



def convert_to_unix_time(utc_timestamp, for_carbanak=True):
    """
    Converts a UTC timestamp string to Unix time.
    
    Args:
        utc_timestamp (str): The UTC timestamp string.
        for_carbanak (bool): If True, returns Unix time in microseconds (for Carbanak).
                             If False, returns Unix time in nanoseconds (for others).
                             
    Returns:
        int: Unix time in microseconds or nanoseconds.
    """
    dt_object = parse(utc_timestamp)
    
    # Convert to Unix timestamp in seconds
    unix_timestamp = datetime.datetime.timestamp(dt_object)
    
    if for_carbanak:
        # Return timestamp in microseconds
        return int(unix_timestamp * 1000000)
    else:
        # Return timestamp in nanoseconds
        return int(unix_timestamp * 1000000000)

def filter_graph_by_time(graph, start_time, end_time):
    """Filters the graph to include only nodes and edges within the specified time range."""
    start_unix = convert_to_unix_time(start_time)
    end_unix = convert_to_unix_time(end_time)

    # Filter vertices and edges by time
    subgraph = graph.subgraph_edges(
        [e.index for e in graph.es if start_unix <= e['time'] <= end_unix]
    )
    return subgraph
    

def find_nodes_by_keyword(attack_graph, keyword, matching_nodes=None):

    print('\nkeyword:', keyword)
    print()

    matching_nodes = matching_nodes if matching_nodes is not None else []
    for vertex in attack_graph.vs:
        if keyword.lower() in vertex['name'].lower():
            record = {
                'uuid': vertex['uuid'],
                'name': vertex['name'],
                'type': vertex['type']
            }
            print(record)
            matching_nodes.append(record)
    
    return matching_nodes


def pollinate(g, target_uuids, new_label, seed_file):
    pass
  
#   for v in g.vs:
#       attr = v.attributes()
#       if attr['uuid']
#   z_uuids = set([zv['uuid'] for zv in z_vertices])
#   df = pd.read_csv(seed_file)
#   df.loc[df.iloc[:, 2].isin(z_uuids), df.columns[-1]] = new_label
#   df.to_csv(seed_file, index=False)


if __name__ == '__main__':

    raise Exception("Don't run this!")

    igraph_file: str = sys.argv[1]
    base_fname: str = igraph_file

    if igraph_file.endswith("pkl.xz"):
        base_fname = igraph_file.replace(".pkl.xz", "")
    elif igraph_file.endswith("pickle.xz"):
        base_fname = igraph_file.replace(".pickle.xz", "")
    else:
        base_fname= igraph_file.replace(".pickle", "")

    # 1. Load graph
    graph = pickle_read(igraph_file)
    print(f"Graph loaded: {len(graph.vs)} vertices, {len(graph.es)} edges")

    # 2. Filter by time
    #
    # # UTC times (easier to normalize)
    start_time = "2024-05-7 19:09:00 +0000"
    end_time = "2024-05-8 21:42:00 +0000"
    graph = filter_graph_by_time(graph, start_time, end_time)
    print(f"Graph filtered by time from {start_time} to {end_time}, updated graph: {len(graph.vs)} vertices, {len(graph.es)} edges")

    # 3. Relabel
    relabels(graph)
    print("Node and edge relabeling complete.")

    pickle_write(graph, f'{base_fname}_prime.pickle.xz')
    
    exit(0)

    #
    # 4. Pollinate
    #

    # Root Causes
    z_root_causes = []
    find_nodes_by_keyword(graph, '10.195.78.253', z_root_causes)
    # find_nodes_by_keyword(graph, 'WindowsDefender', z_root_causes)
    # find_nodes_by_keyword(graph, 'carbon', z_root_causes)
    print()
    print('Pollinating Root Causes...')
    pollinate(z_root_causes, new_label='root_cause', seed_file=seed_file)
    print('Done')
    print()

    # Impacts
    z_impacts = []
    find_nodes_by_keyword(graph, 'Java-Update.exe', z_impacts)
    find_nodes_by_keyword(graph, 'Java-Update.vbs', z_impacts)
    find_nodes_by_keyword(graph, 'defenderupgrade', z_impacts)
    find_nodes_by_keyword(graph, 'infosmin48', z_impacts)
    # find_nodes_by_keyword(graph, 'tightvnc', z_impacts)
    # find_nodes_by_keyword(graph, 'vnc', z_impacts)
    find_nodes_by_keyword(graph, 'klog2.txt', z_impacts)
    # find_nodes_by_keyword(graph, 'rdp', z_impacts)

    print()
    print('Pollinating Impacts...')
    pollinate(z_impacts, new_label='impact', seed_file=seed_file)
    print('Done')
    print()