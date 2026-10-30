import unittest
from mirage.topology import build_topology
from mirage.models import Asset

class TopologyTests(unittest.TestCase):
    def test_relationship_graph_uses_observed_assets(self):
        assets=[
            Asset('domain','example.test','target-input'),
            Asset('subdomain','api.example.test','certificate-transparency'),
            Asset('ip','192.0.2.5','dns',details={'hostname':'api.example.test'}),
            Asset('http_service','https://api.example.test','http-crawl'),
            Asset('url','https://api.example.test/v1/users','http-crawl'),
            Asset('parameter','page','url-query',details={'url':'https://api.example.test/v1/users?page=1'}),
        ]
        nodes,edges=build_topology(assets,'example.test')
        self.assertEqual(len(nodes),len(assets))
        self.assertGreaterEqual(len(edges),len(assets)-1)
        self.assertEqual({n['asset'].value for n in nodes},{a.value for a in assets})

    def test_multi_target_graph_keeps_domain_relationships_separate(self):
        assets=[
            Asset('domain','alpha.test','target-input'),
            Asset('domain','beta.test','target-input'),
            Asset('subdomain','api.alpha.test','certificate-transparency'),
            Asset('subdomain','admin.beta.test','certificate-transparency'),
        ]
        nodes,edges=build_topology(assets,'alpha.test, beta.test')
        idx={node['asset'].value:i for i,node in enumerate(nodes)}
        self.assertIn((idx['alpha.test'],idx['api.alpha.test']),edges)
        self.assertIn((idx['beta.test'],idx['admin.beta.test']),edges)
        self.assertNotIn((idx['alpha.test'],idx['admin.beta.test']),edges)

if __name__=='__main__': unittest.main()
