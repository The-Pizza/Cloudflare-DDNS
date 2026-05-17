from kubernetes import client, config, watch
from core.database import get_session
from core.models import AnnotationTarget
from datetime import datetime

ANNOTATION_KEY = "cloudflare-ddns.witschger.home/dns-name"

class AnnotationWatcher:
    def __init__(self):
        try:
            config.load_incluster_config()
        except:
            config.load_kube_config()
        self.apps_v1 = client.AppsV1Api()

    def watch_resources(self):
        session = get_session()
        w = watch.Watch()
        for event in w.stream(self.apps_v1.list_deployment_for_all_namespaces, timeout_seconds=0):
            obj = event['object']
            annotations = obj.metadata.annotations or {}
            if ANNOTATION_KEY in annotations:
                dns_name = annotations[ANNOTATION_KEY]
                target = AnnotationTarget(
                    namespace=obj.metadata.namespace,
                    name=obj.metadata.name,
                    kind="Deployment",
                    dns_name=dns_name,
                    last_seen=datetime.utcnow()
                )
                session.add(target)
                session.commit()
                print(f"Discovered annotated Deployment: {obj.metadata.name} -> {dns_name}")