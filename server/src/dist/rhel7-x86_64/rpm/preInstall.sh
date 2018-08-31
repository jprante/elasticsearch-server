getent group es >/dev/null 2>&1 || groupadd es
getent passwd es >/dev/null 2>&1 || useradd -g es -r es -d /var/lib/elasticsearch
install --mode=770 --owner=es --group=es --directory /var/lib/elasticsearch
