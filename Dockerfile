FROM python:3.10-slim

# install debian packages
RUN apt-get update
RUN apt-get install -y build-essential libpq-dev postgresql-client cron nano gettext librsync-dev libsecp256k1-0

# install python packages
RUN pip3 install --upgrade pip
ADD requirements.txt .
RUN pip3 install -r requirements.txt

# copy app data
COPY ./ /app
WORKDIR /app

# install cron entry
RUN chmod +x backup_cron.sh
RUN chmod +x payout_cron.sh
RUN (crontab -l; echo '0 15 * * * /app/backup_cron.sh >> /var/log/backup_cron.log 2>&1') | crontab -
RUN (crontab -l; echo '0 16 * * * /app/payout_cron.sh >> /var/log/payout_cron.log 2>&1') | crontab -

# start cron and app
CMD service cron start && python3 app.py
EXPOSE 5000