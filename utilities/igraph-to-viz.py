import csv
import igraph
import matplotlib.pyplot as plt
import os
import sys
import pickle
import pdb
import lzma

from graph_helpers import *

if __name__ == "__main__":

    igraph_file = sys.argv[1]
    seed_file = igraph_file.replace(".pkl.xz", ".csv")
    pdf_file = igraph_file.replace(".pkl.xz", ".pdf")
    
    g = pickle_read(igraph_file)

    print("Relabeling nodes and edges...")
    relabels(g)
    print("Coloring graph...")
    color_graph(g, seed_file)
    print("Decloning processes...")
    declone_processes(g)
    print("Pruning Edges...")
    prune_edges(g)
    print("Merging Vertices...")
    merge_vertices(g)
    lamport_timestamps(g)
    #mark_uuids(g)

    print("Plotting %s..." %(pdf_file))
    layout = g.layout_davidson_harel()
    g.vs["label"] = [g.vs[i]["name"] for i in range(0,len(g.vs))]
    g.vs["shape"] = ["rectangle" for t in g.vs["name"]]
    g.vs["height"] = [25 for n in g.vs["name"]]
    g.vs["width"] = [20 + 10*(len(n)-1) for n in g.vs["name"]]
    g.es["label"] = [t for t in g.es["type"]]
    g.es["arrow_size"] = [1.25 for t in g.es["type"]]
    igraph.plot(g, pdf_file, layout=layout, bbox=(2560, 1080), margin=200)

