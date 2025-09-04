#!/data/data/com.termux/files/usr/bin/bash
while true; do
    pg_ctl -D $PREFIX/var/lib/postgresql -l logfile start
    # Wait until postgres exits
    wait $!
    echo "Postgres crashed/restarted. Restarting in 5s..."
    sleep 5
done
