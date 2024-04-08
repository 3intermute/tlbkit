cmd_/home/debian/tlbkit/modules.order := {   echo /home/debian/tlbkit/tlbkit.ko; :; } | awk '!x[$$0]++' - > /home/debian/tlbkit/modules.order
