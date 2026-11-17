#!/bin/bash
# Register the parameterized C2 name in the .lab zone (run once, by fixlocal.sh).
# The C2 is "name only": it resolves, but no server answers there.

conf=/etc/nxlab/lab.conf
zone=/etc/bind/zones/db.lab

. "$conf"

# Parameterization must have replaced the tokens with numbers. Without this
# check a failed parameterization would go unnoticed: the literal token would
# be used as the seed and every student would get the same C2 name.
case "$DGA_SEED$C2_INDEX" in
    *[!0-9]*|"")
        echo "lab.conf is not parameterized (DGA_SEED=$DGA_SEED C2_INDEX=$C2_INDEX)."
        exit 1 ;;
esac

if ! name=$(python3 /usr/local/bin/nxdga.py --seed "$DGA_SEED" --index "$C2_INDEX"); then
    echo "nxdga.py failed."
    exit 1
fi
label=${name%.lab}

if ! grep -q "^$label " "$zone"; then
    printf '%-15s IN A    %s   ; C2 (dga index %s)\n' "$label" "$C2_IP" "$C2_INDEX" >> "$zone"
fi

# Keep the answer for the instructor (not readable by the student user).
echo "$name $C2_IP $C2_INDEX" > /var/lib/nxlab_c2.txt
chmod 600 /var/lib/nxlab_c2.txt
echo "C2 name registered: index $C2_INDEX"
