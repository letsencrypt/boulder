This directory contains a handful of utility scripts for manually interacting
with boulder-mtca.

 - clear.sh: clear the demo log SQL DB (only works for MariaDB).
 - start.sh: run boulder-mtca as a single component.

To list all tiles (while bminio is running):

    alias mc="docker compose exec bminio mc"
    mc ls -r local/boulder-mtc-tiles/

To see a specific tile:

    mc cat local/boulder-mtc-tiles/tile/entries/011.p/9 > 9.gz

To clear tile storage:

    mc rm -r --force local/boulder-mtc-tiles/
