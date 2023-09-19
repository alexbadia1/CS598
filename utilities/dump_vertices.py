from graph_helpers import *

igraph_file = sys.argv[1]

base_fname = igraph_file
if igraph_file.endswith("pkl.xz"):
    base_fname = igraph_file.replace(".pkl.xz", "")
else:
    base_fname= igraph_file.replace(".pickle", "")

seed_file = base_fname + ".csv"


g = pickle_read(igraph_file)


if False:
    print("Relabeling nodes and edges...")
    relabels(g)
    print("Coloring graph...")
    color_graph(g, seed_file)
    #print("Decloning processes...")
    #declone_processes(g)
    print("Pruning Edges...")
    prune_edges(g)
    print("Merging Vertices...")
    merge_vertices(g)
    print("Re-pruning Edges...")
    prune_edges(g)
    #lamport_timestamps(g)
    #mark_uuids(g)

    attack_only(g)
    
vertices = []
for i in range(0,len(g.vs)):
    v = g.vs[i]

    try:

        time = 0
        if "time" in v.attributes():
            time = v["time"]
        
        default_label = "benign"

        if "is_attack" in v.attributes() and v["is_attack"]:
            default_label = "attack"            

        vertices.append("%d,%s,\"%s\",%s,%s" % (time, v["type"],v["name"],v["uuid"],default_label))

    except Exception as e:
        print("Error: %s" % (e))
        pdb.set_trace()
        
for vertex in vertices:
    print(vertex)

    
