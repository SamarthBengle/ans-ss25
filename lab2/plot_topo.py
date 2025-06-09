# plot_topo.py
import networkx as nx
import matplotlib.pyplot as plt
from topo import Fattree

def plot_fattree(k):
    ft = Fattree(k)
    G = nx.Graph()

    # 1) Add nodes with a "layer" attribute (0=host,1=edge,2=agg,3=core)
    for sw in ft.switches:
        if sw.type == 'edge':
            layer = 1
        elif sw.type == 'agg':
            layer = 2
        else:  # core
            layer = 3
        G.add_node(sw.id, layer=layer, ftype=sw.type)

    for h in ft.servers:
        G.add_node(h.id, layer=0, ftype='host')

    # 2) Add each fat-tree link exactly once
    seen = set()
    for node in ft.switches + ft.servers:
        for edge in node.edges:
            if edge in seen:
                continue
            seen.add(edge)
            u = edge.lnode.id
            v = edge.rnode.id
            G.add_edge(u, v)

    # 3) Compute a multipartite layout by "layer"
    pos = nx.multipartite_layout(G, subset_key="layer")

    # 4) Draw nodes colored/sized by type
    plt.figure(figsize=(10, 6))
    node_colors = []
    node_sizes = []
    for n, data in G.nodes(data=True):
        t = data['ftype']
        if t == 'host':
            node_colors.append('green')
            node_sizes.append(200)
        elif t == 'edge':
            node_colors.append('blue')
            node_sizes.append(400)
        elif t == 'agg':
            node_colors.append('orange')
            node_sizes.append(400)
        else:  # core
            node_colors.append('red')
            node_sizes.append(400)

    nx.draw(
        G,
        pos,
        with_labels=True,
        labels={n: n for n in G.nodes()},
        node_color=node_colors,
        node_size=node_sizes,
        font_size=7,
        font_color='black',
        linewidths=0.5,
        edge_color='gray'
    )

    plt.title(f"Fat-tree (k={k})", fontsize=14)
    plt.axis('off')

    # 5) Save using bbox_inches='tight' instead of tight_layout()
    plt.savefig('fattree_k4.jpg', format='jpg', dpi=300, bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    plot_fattree(4)
