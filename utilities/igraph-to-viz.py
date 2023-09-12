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

    base_fname = igraph_file
    if igraph_file.endswith("pkl.xz"):
        base_fname = igraph_file.replace(".pkl.xz", "")
    else:
        base_fname= igraph_file.replace(".pickle", "")

    
    seed_file = base_fname + ".csv"
    pdf_file = base_fname + ".pdf"

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
    print("Re-pruning Edges...")
    prune_edges(g)
    #lamport_timestamps(g)
    #mark_uuids(g)

    print("Plotting %s of size V=%d, E=%d..." %(pdf_file, len(g.vs), len(g.es)))
    layout = g.layout_davidson_harel()
    g.vs["label"] = [g.vs[i]["name"] for i in range(0,len(g.vs))]
    g.vs["shape"] = ["rectangle" for t in g.vs["name"]]
    g.vs["height"] = [25 for n in g.vs["name"]]
    g.vs["width"] = [20 + 10*(len(n)-1) for n in g.vs["name"]]
    g.es["label"] = [t for t in g.es["type"]]
    g.es["arrow_size"] = [1.25 for t in g.es["type"]]
    igraph.plot(g, pdf_file, layout=layout, bbox=(2560, 1080), margin=200)

