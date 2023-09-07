from graph_helpers import *

igraph_file = sys.argv[1]
g = pickle_read(igraph_file)

vertices = []
for i in range(0,len(g.vs)):
    v = g.vs[i]
    vertices.append("%s, %s,%s,%s" % (str(v["time"]), v["type"],v["name"],v["uuid"]))

for vertex in vertices:
    print(vertex)

    
