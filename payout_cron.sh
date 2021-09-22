#!/bin/bash

### source the environment
. <(xargs -0 bash -c 'printf "export %q\n" "$@"' -- < /proc/1/environ)

date_format=$(date "+%Y%m%dT%H%M%s")

echo $date_format - payouts_notification_create
python3 /app/app.py payouts_notification_create