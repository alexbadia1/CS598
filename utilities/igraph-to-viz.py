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

    igraph_file: str = sys.argv[1]

    base_fname: str = igraph_file

    if igraph_file.endswith("pkl.xz"):
        base_fname = igraph_file.replace(".pkl.xz", "")
    elif igraph_file.endswith("pickle.xz"):
        base_fname = igraph_file.replace(".pickle.xz", "")
    else:
        base_fname= igraph_file.replace(".pickle", "")

    
    seed_file: str = base_fname + ".csv"
    pdf_file: str = base_fname + ".pdf"
    
    print('\nSeed File:', seed_file, '\n')

    g: igraph.Graph = pickle_read(igraph_file)
    graph_summary(g)

    print("\nRelabeling nodes and edges...\n")
    relabels(g)
    graph_summary(g)

    print("\nRecovering vertex times...\n")
    vertex_times(g)
    graph_summary(g)

    print("\nColoring graph...\n")
    color_graph(g, seed_file)
    graph_summary(g)
    
    print("\nAttack only...\n")
    attack_only(g)

    print("\nDecloning processes...\n")
    declone_processes(g)
    print("\nPruning Edges...\n")
    prune_edges(g)
    print("\nMerging Vertices...\n")
    merge_vertices(g, seed_file)
    print("\nRe-pruning Edges...\n")
    prune_edges(g)
    print("\nPruning Vertices...\n")
    prune_vertices(g, seed_file)        
    #mark_uuids(g)
    

    
    print("Plotting %s of size V=%d, E=%d..." %(pdf_file, len(g.vs), len(g.es)))
    if len(g.vs) == 0:
        print("\t...nevermind.")
        sys.exit(-1)
    layout = g.layout_davidson_harel()
    g.vs["label"] = [g.vs[i]["name"] for i in range(0,len(g.vs))]
    g.vs["shape"] = ["rectangle" for t in g.vs["name"]]
    g.vs["height"] = [25 for n in g.vs["name"]]
    g.vs["width"] = [20 + 10*(len(n)-1) for n in g.vs["name"]]
    g.es["label"] = [t for t in g.es["type"]]
    #lamport_timestamps(g)
    g.es["arrow_size"] = [1.25 for t in g.es["type"]]
    igraph.plot(g, pdf_file, layout=layout, bbox=(2560, 1080), margin=200)
