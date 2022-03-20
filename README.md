# monitoring_project


This project was made for gaining some experience with Prometheus monitoring system and it's ecosystem.
Ansible was used in project for gaining experience as well and like a guideline through the project.

Technologies is used in the project: Prometheus, Ansible, Grafana, Alertmanager, Nginx(Webserver), Docker, Certbot(Let'sencrypt), Pushgateway_exporter, cadvisor_exporter(Docker_exporter), Mysqld_exporter, Wordpress(in Docker-Compose witf Mysqld), Node_exporter, Nginx_exporter.

## Requrimenets

* Installed [Ansible](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html) on your machine

* Install community.general and community.docker collections
```bash
   $ ansible-galaxy collection install community.general
   $ ansible-galaxy collection install community.docker
```
* Two instances and Ubuntu 20.04 on it.

* LAN network between instances on eth1 interface on instances.

* Define variables on [hosts](https://github.com/DevEnv-94/monitoring_project/blob/master/hosts) file:

```ini
[node]
# IP address of your machine
164.92.137.192

[node:vars]
ansible_user=user # User on your instance
ansible_become=true # Like a sudo behind a command
ansible_become_pass=qwerty # Password of your user
domain=devenv.quest # Your domain name, for example you can get it here https://www.namecheap.com or use something free like https://sslip.io or https://nip.io .

[prometheus]
# IP address of your machine
164.92.184.183

[prometheus:vars]
ansible_user=user # User on your instance
ansible_become=true # Like a sudo behind a command
ansible_become_pass=qwerty # Password of your user
domain=grafana.devenv.quest  # Your domain name, for example you can get it here https://www.namecheap.com or use something free like https://sslip.io or https://nip.io .
backup_user=user # In this case without any adjustment of project you should use same user which you used on [node] section.
```
