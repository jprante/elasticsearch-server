getent group elasticsearch >/dev/null 2>&1 || groupadd elasticsearch
getent passwd elasticsearch >/dev/null 2>&1 || useradd -g elasticsearch -r elasticsearch -d /var/lib/elasticsearch
install --mode=770 --owner=elasticsearch --group=elasticsearch --directory /var/lib/elasticsearch
