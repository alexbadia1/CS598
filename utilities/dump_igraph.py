from graph_helpers import *

igraph_file = sys.argv[1]
g = pickle_read(igraph_file)


relabels(g)
declone_processes(g)
prune(g, debug=True)
#prune(g, debug=True)


vertices = []
for i in range(0,len(g.vs)):
    v = g.vs[i]
    
    vertices.append("%d: %s,%s,%s" % (v.index, v["type"],v["name"],v["uuid"]))

#vertices.sort()    

edges = []
for i in range(0, len(g.es)):
    s = g.vs[g.es[i].source]
    t = g.vs[g.es[i].target]

    if s["type"] == "unknown":
        s["name"] = "unknown"
        
    if t["type"] == "unknown":
        t["name"] = "unknown"
            
    edges.append("%d:%s --[%s]--> %d:%s" % (s.index,s["name"],
                                            g.es[i]["type"],t.index,t["name"]))

edges.sort()

for vertex in vertices:
    print(vertex)
    
for edge in edges:
    print(edge)
    
