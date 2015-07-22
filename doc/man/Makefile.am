dist_man_MANS = pwmake.1 pwscore.1 pwquality.conf.5

if HAVE_PAM
dist_man_MANS += pam_pwquality.8
endif

EXTRA_DIST=pam_pwquality.8.pod pwmake.1.pod pwscore.1.pod pwquality.conf.5.pod

%.8: %.8.pod
	bash -c 'declare -u ucname=$*; pod2man --utf8 --name="$$ucname" --section=8 --center="Linux-PAM Manual" --release="Red Hat, Inc." $< $@'

%.1: %.1.pod
	bash -c 'declare -u ucname=$*; pod2man --utf8 --name="$$ucname" --section=1 --center="General Commands Manual" --release="Red Hat, Inc." $< $@'

%.5: %.5.pod
	bash -c 'declare -u ucname=$*; pod2man --utf8 --name="$$ucname" --section=5 --center="File Formats Manual" --release="Red Hat, Inc." $< $@'

manclean:
	rm *.8 *.1 *.5
