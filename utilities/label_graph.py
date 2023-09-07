from graph_helpers import *
    
igraph_file = sys.argv[1]
base_name = igraph_file.replace(".pkl.xz", "")
seed_file = igraph_file.replace(".pkl.xz", ".csv")

g = pickle_read(igraph_file)

# Color the graph
seed_labels={}
if os.path.isfile(seed_file):
    with open(seed_file,'r') as csvfile:
        rdr = csv.reader(csvfile)
        for row in rdr:
            seed_labels[row[3]] = row[4]

    root_vertex_ids = []
    impact_vertex_ids = []
    g.vs["label"] = g.vs["uuid"]
    for i in range(0,len(g.vs["uuid"])):        
        if seed_labels[g.vs[i]["uuid"]] == "root_cause":
            g.vs[i]["label"] = "attack"
            root_vertex_ids.append(i)
        elif seed_labels[g.vs[i]["uuid"]] == "impact":
            g.vs[i]["label"] = "attack"
            impact_vertex_ids.append(i)
        elif seed_labels[g.vs[i]["uuid"]] == "attack":
            g.vs[i]["label"] = "attack"
        elif seed_labels[g.vs[i]["uuid"]] == "descendent":
            g.vs[i]["label"] = "attack"
        else:
            g.vs[i]["label"] = "contaminated"


    
    # Propagate root cause taint in graph colors
    descendents = []
    for r in root_vertex_ids:
        descendents = descendents + forward_trace(g, r, g.vs[r]["time"], [])

    # (Maybe) trace back from impact vertices
    ancestors = []
    for i in impact_vertex_ids:
        ancestors = ancestors + backward_trace(g, i, g.vs[i]["time"], [])

    attack_chain = [vertex for vertex in descendents if vertex in ancestors]
    attack_chain = descendents
    for d in attack_chain:
            g.vs[d]["label"] = "attack"


for v in range(0,len(g.vs)):
    vertex = g.vs[v]
    if vertex["type"] == "process":
        print("%s, %s, %s, %s" % (base_name, vertex["uuid"], vertex["name"], vertex["label"]))
