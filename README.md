# monitoring_project

This project was made for gaining some experience with Prometheus monitoring system and it's ecosystem.
Ansible was used in project for gaining experience as well and like a guideline through the project.

Technologies is used in the project: Linux ,Prometheus, Ansible, Grafana, Alertmanager, Nginx(Webserver), Docker, Certbot(Let'sencrypt), Pushgateway_exporter, cadvisor_exporter(Docker_exporter), Mysqld_exporter, Wordpress(in Docker-Compose witf Mysqld), Node_exporter, Nginx_exporter.

## Roles brief description 


* [docker_compose](https://github.com/DevEnv-94/monitoring_project/blob/master/docker_compose/tasks/main.yml) role: installs all requirement packages and then installs docker and docker-compose from docker repository.

* [Wordpress](https://github.com/DevEnv-94/monitoring_project/tree/master/wordpress/tasks) role: creates directory /opt/wordpress puts here [docker-compose.yml](https://github.com/DevEnv-94/monitoring_project/blob/master/wordpress/templates/docker-compose.yml.j2) and starts wordpress in docker-compose.

* [alertmanager](https://github.com/DevEnv-94/monitoring_project/blob/master/alertmanager/tasks/main.yml) role: creates /opt/alertmanager directory puts here alertmanager.yml config and starts alertmanager in docker on eth1 ip4 address on 9093 port.

* [cadvisor](https://github.com/DevEnv-94/monitoring_project/blob/master/cadvisor/tasks/main.yml) role: starts cadsisor in Docker on eth1 ip4 address on 8080 port.

* [mysql_exporter](https://github.com/DevEnv-94/monitoring_project/blob/master/mysql_exporter/tasks/main.yml) role: starts mysqld-exporter on eth1 ip4 address on 9104 port.

* [node_exporter](https://github.com/DevEnv-94/monitoring_project/blob/master/node_exporter/tasks/main.yml) role: creates /opt/node_exporter directory uploads here node_exporter, puts here node_exporter.service file and starts node_exporter with systemd on eth1 ip4 address on 9100 port.

* [certbot_tls](https://github.com/DevEnv-94/monitoring_project/blob/master/certbot_tls/tasks/main.yml) role: downloads and updates snapd and then downloads certbot with snapd, creates required directories and makes TLS certificates for {{domain}} and www.{{domain}} mode:standalone with http(80port) challenge without email. and puts its to /etc/letsencrypt/live/{{domain}} directory.

* [nginx](https://github.com/DevEnv-94/monitoring_project/blob/master/nginx/tasks/main.yml) role: downloads nginx:latest from official nginx repository and puts config files for site to ./nginx/conf.d/ and starts sites on HTTPS(443port)(all HTTP traffic redirects to HTTPS) proxy to wordpress on [node] and grafana on [prometheus] puts here different config site files.

* [nginx_exporter](https://github.com/DevEnv-94/monitoring_project/blob/master/nginx_exporter/tasks/main.yml) role: creates /opt/nginx_exporter direcory puts here [prometheus-nginxlog-exporter.hcl](https://github.com/DevEnv-94/monitoring_project/blob/master/nginx_exporter/tasks/main.yml) and starts nginx_exporter in Docker on eth1 ip4 address on 4040 port.

* [prometheus](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/tasks/main.yml) role: creates /opt/prometheus, /opt/prometheus/prom-targets and /opt/prometheus/alerts directories puts here [prometheus.yml](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/templates/prometheus.yml.j2) config file, [nodes.json](https://github.com/DevEnv-94/monitoring_project/blob/master/prometheus/templates/nodes.json.j2) with discovery targets and [rules](https://github.com/DevEnv-94/monitoring_project/tree/master/prometheus/files) files for alerts, after that starts prometheus in Docker on eth1 ip4 address on 9090 port.
* [grafana](https://github.com/DevEnv-94/monitoring_project/blob/master/grafana/tasks/main.yml) role: creates /opt/grafana directory then puts here grafana.ini config and starts grafana in Docker on eth1 ip4 address on 3000 port.

* [push-gateway](https://github.com/DevEnv-94/monitoring_project/blob/master/push-gateway/tasks/main.yml) role: starts pushgateway in Docker on eth1 ip4 address on 9091 port.

* [backup_scipt_prometheus](https://github.com/DevEnv-94/monitoring_project/blob/master/backup_scirpt_prometheus/tasks/main.yml) role: installs required packages, creates /opt/prom_backup directory puts here script and creates cron job which starts that script every day at 17:00.

* [ssh_key_transfer](https://github.com/DevEnv-94/monitoring_project/blob/master/backup_scirpt_prometheus/templates/prometheus_backup_script.sh.j2) role: creates ssh_key for root user on [prometheus] instance and sends ssh_pub.key to {{ansible_user}} on [node] instance [for backup script correct work]

## Requrimenets

* Installed [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) on your machine

* Install community.general and community.docker collections
```bash
   $ ansible-galaxy collection install community.general
   $ ansible-galaxy collection install community.docker
```
* Two instances and Ubuntu 20.04 on it.

* LAN network between instances on eth1 interface.

* Sudo priveleges on your user on instances

* Define variables on [hosts](https://github.com/DevEnv-94/monitoring_project/blob/master/hosts) file:

```ini
[node]
# IP address of your machine


[node:vars]
ansible_user= # User on your instance
ansible_become=true # Like a sudo behind a command, must be true
ansible_become_pass= # Password of your user
domain= # Your domain name, for example you can get it here https://www.namecheap.com or use something free like https://sslip.io or https://nip.io . (without www subdomain)

[prometheus]
# IP address of your machine


[prometheus:vars]
ansible_user= # User on your instance
ansible_become=true # Like a sudo behind a command, must be true
ansible_become_pass= # Password of your user
domain=  # Your domain name, for example you can get it here https://www.namecheap.com or use something free like https://sslip.io or https://nip.io . (without www subdomain)

#NB1: Domain names on node and prometheus sections have to be different but you can use on [prometheus] section your [node] domain with additional subdomain for example [grafana.yourdomain.com]
#NB2: If you have choosed sslip.io or nip.io as a domain name #NB1 is should not concerned you, but may appear let'sencrypt limit error, because for this domain aquire many certificates.
```

* Define options in [alertmanager.yml]

```yaml
  routes:
  - receiver: 'critical-prometheus' # must be same as service name on PagerDuty https://www.pagerduty.com/docs/guides/prometheus-integration-guide/
    matchers:
    - severity="critical"
  - receiver: 'slack-warning'
    matchers:
    - severity=~"warning|info"
  - receiver: 'DeadMansSwitch' # this reciever created for All prometheus monitoring system, always firing and sends signal every minute, when prometheus is dead, stops sending signal and you recieve alert.
    repeat_interval: 1m
    group_wait: 0s
    matchers:
    - severity="none"


receivers:
- name: 'DeadMansSwitch'
  webhook_configs:
  - url: #how to [https://deadmanssnitch.com/docs]
    send_resolved: false
- name: 'critical-prometheus' # must be same as service name on PagerDuty https://www.pagerduty.com/docs/guides/prometheus-integration-guide/
  pagerduty_configs:
  - service_key: #How to https://www.pagerduty.com/docs/guides/prometheus-integration-guide/
- name: 'slack-warning'
  slack_configs:
    - api_url: #How to [https://grafana.com/blog/2020/02/25/step-by-step-guide-to-setting-up-prometheus-alertmanager-with-slack-pagerduty-and-gmail/]
      channel: '#' # must be same name as slack channel
```