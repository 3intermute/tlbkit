cmd_/home/debian/tlbkit/Module.symvers := sed 's/ko$$/o/' /home/debian/tlbkit/modules.order | scripts/mod/modpost -m    -o /home/debian/tlbkit/Module.symvers -e -i Module.symvers   -T -
