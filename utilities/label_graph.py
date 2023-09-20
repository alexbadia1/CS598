from graph_helpers import *

igraph_file = sys.argv[1]

base_fname = igraph_file
if igraph_file.endswith("pkl.xz"):
    base_fname = igraph_file.replace(".pkl.xz", "")
else:
    base_fname= igraph_file.replace(".pickle", "")
    
    
seed_file = base_fname + ".csv"
pdf_file = base_fname + ".pdf"

g = pickle_read(igraph_file)

vertex_times(g)
contaminate_graph(g, seed_file)
color_graph(g, seed_file)

for v in range(0,len(g.vs)):
    vertex = g.vs[v]
    if vertex["attack_label"]:
        vertex["label"] = "attack"
    elif vertex["contaminate_label"]:
        vertex["label"] = "contaminated"
    else:
        vertex["label"] = "benign"

for v in range(0,len(g.vs)):
    vertex = g.vs[v]
    if vertex["type"] == "process":
        if "atlasv2" in base_fname:
            print("%s, %d, %s, %s" % (base_fname, int(vertex["pid"]), vertex["name"], vertex["label"]))
        else:
            print("%s, %s, %s, %s" % (base_fname, vertex["uuid"], vertex["name"], vertex["label"]))
