from dateutil.parser import parse
import datetime
from typing import Tuple
import sys

import pandas as pd

from graph_helpers import pickle_read, pickle_write, relabels, vertex_times


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


if __name__ == '__main__':

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

    pickle_write(graph, f'{base_fname}_filtered.pickle.xz')
