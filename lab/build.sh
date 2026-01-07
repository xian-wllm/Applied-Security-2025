mkdir -p Pre-Built

docker build -t imovies/nginx Images/nginx
docker build -t imovies/portal Images/portal
docker build -t imovies/mysql Images/mysql
docker build -t imovies/vault Images/vault
docker build -t imovies/client Images/client
docker build -t imovies/guacd Images/guacd
docker build -t imovies/guacamole Images/guacamole
docker build -t imovies/backup Images/backup
docker build -t imovies/wazuh:indexer -f Images/wazuh/Dockerfile.indexer .
docker build -t imovies/wazuh:dashboard -f Images/wazuh/Dockerfile.dashboard .
docker build -t imovies/wazuh:manager -f Images/wazuh/Dockerfile.manager .

docker save imovies/nginx -o Pre-Built/nginx_prebuilt.tar
docker save imovies/portal -o Pre-Built/portal_prebuilt.tar
docker save imovies/mysql -o Pre-Built/mysql_prebuilt.tar
docker save imovies/vault -o Pre-Built/vault_prebuilt.tar
docker save imovies/client -o Pre-Built/client_prebuilt.tar
docker save imovies/guacd -o Pre-Built/guacd_prebuilt.tar
docker save imovies/guacamole -o Pre-Built/guacamole_prebuilt.tar
docker save imovies/backup -o Pre-Built/backup_prebuilt.tar
docker save imovies/wazuh:indexer -o Pre-Built/wazuh_indexer_prebuilt.tar
docker save imovies/wazuh:dashboard -o Pre-Built/wazuh_dashboard_prebuilt.tar
docker save imovies/wazuh:manager -o Pre-Built/wazuh_manager_prebuilt.tar